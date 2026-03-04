package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/jhaals/yopass/pkg/yopass"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/crypto/openpgp/armor"
)

type Server struct {
	DB                  Database
	MaxLength           int
	ForceOneTimeSecrets bool
	AssetPath           string
	Logger              *zap.Logger
	TrustedProxies      []string
}

func (y *Server) createSecret(w http.ResponseWriter, request *http.Request) {
	decoder := json.NewDecoder(request.Body)
	var s yopass.Secret
	if err := decoder.Decode(&s); err != nil {
		y.Logger.Debug("Unable to decode request", zap.Error(err))
		http.Error(w, `{"message": "Unable to parse json"}`, http.StatusBadRequest)
		return
	}

	if !isPGPEncrypted(s.Message) {
		http.Error(w, `{"message": "Message must be PGP encrypted"}`, http.StatusBadRequest)
		return
	}

	if !validExpiration(s.Expiration) {
		http.Error(w, `{"message": "Invalid expiration specified"}`, http.StatusBadRequest)
		return
	}

	if !s.OneTime && y.ForceOneTimeSecrets {
		http.Error(w, `{"message": "Secret must be one time download"}`, http.StatusBadRequest)
		return
	}

	if len(s.Message) > y.MaxLength {
		http.Error(w, `{"message": "The encrypted message is too long"}`, http.StatusBadRequest)
		return
	}

	uuidVal, err := uuid.NewV4()
	if err != nil {
		y.Logger.Error("Unable to generate UUID", zap.Error(err))
		http.Error(w, `{"message": "Unable to generate UUID"}`, http.StatusInternalServerError)
		return
	}
	key := uuidVal.String()

	if err := y.DB.Put(key, s); err != nil {
		y.Logger.Error("Unable to store secret", zap.Error(err))
		http.Error(w, `{"message": "Failed to store secret in database"}`, http.StatusInternalServerError)
		return
	}

	resp := map[string]string{"message": key}
	jsonData, err := json.Marshal(resp)
	if err != nil {
		y.Logger.Error("Failed to marshal create secret response", zap.Error(err))
	}

	if _, err = w.Write(jsonData); err != nil {
		y.Logger.Error("Failed to write response", zap.Error(err))
	}
}

func (y *Server) getSecret(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Cache-Control", "private, no-cache")

	secretKey := mux.Vars(request)["key"]
	secret, err := y.DB.Get(secretKey)
	if err != nil {
		y.Logger.Debug("Secret not found", zap.Error(err))
		http.Error(w, `{"message": "Secret not found"}`, http.StatusNotFound)
		return
	}

	data, err := secret.ToJSON()
	if err != nil {
		y.Logger.Error("Failed to encode request", zap.Error(err))
		http.Error(w, `{"message": "Failed to encode secret"}`, http.StatusInternalServerError)
		return
	}

	if _, err := w.Write(data); err != nil {
		y.Logger.Error("Failed to write response", zap.Error(err))
	}
}

func (y *Server) getSecretStatus(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Cache-Control", "private, no-cache")
	w.Header().Set("Content-Type", "application/json")

	secretKey := mux.Vars(request)["key"]
	oneTime, err := y.DB.Status(secretKey)
	if err != nil {
		y.Logger.Debug("Secret not found", zap.Error(err))
		http.Error(w, `{"message": "Secret not found"}`, http.StatusNotFound)
		return
	}

	resp := map[string]bool{"oneTime": oneTime}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		y.Logger.Error("Failed to write status response", zap.Error(err))
	}
}

func (y *Server) deleteSecret(w http.ResponseWriter, request *http.Request) {
	deleted, err := y.DB.Delete(mux.Vars(request)["key"])
	if err != nil {
		http.Error(w, `{"message": "Failed to delete secret"}`, http.StatusInternalServerError)
		return
	}

	if !deleted {
		http.Error(w, `{"message": "Secret not found"}`, http.StatusNotFound)
		return
	}

	w.WriteHeader(204)
}

func (y *Server) optionsSecret(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Headers", "content-type")
}

func (y *Server) configHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Headers", "content-type")
	w.Header().Set("Content-Type", "application/json")

	config := map[string]interface{}{
		"DISABLE_UPLOAD":        viper.GetBool("disable-upload"),
		"PREFETCH_SECRET":       viper.GetBool("prefetch-secret"),
		"DISABLE_FEATURES":      viper.GetBool("disable-features"),
		"NO_LANGUAGE_SWITCHER":  viper.GetBool("no-language-switcher"),
		"FORCE_ONETIME_SECRETS": viper.GetBool("force-onetime-secrets"),
	}

	if privacyURL := viper.GetString("privacy-notice-url"); privacyURL != "" {
		config["PRIVACY_NOTICE_URL"] = privacyURL
	}
	if imprintURL := viper.GetString("imprint-url"); imprintURL != "" {
		config["IMPRINT_URL"] = imprintURL
	}

	if err := json.NewEncoder(w).Encode(config); err != nil {
		y.Logger.Error("Failed to encode config response", zap.Error(err))
	}
}

func (y *Server) HTTPHandler() http.Handler {
	mx := mux.NewRouter()
	mx.Use(corsMiddleware)

	mx.HandleFunc("/create/secret", y.createSecret).Methods(http.MethodPost)
	mx.HandleFunc("/create/secret", y.optionsSecret).Methods(http.MethodOptions)
	if viper.GetBool("prefetch-secret") {
		mx.HandleFunc("/secret/"+keyParameter+"/status", y.getSecretStatus).Methods(http.MethodGet)
	}
	mx.HandleFunc("/secret/"+keyParameter, y.getSecret).Methods(http.MethodGet)
	mx.HandleFunc("/secret/"+keyParameter, y.deleteSecret).Methods(http.MethodDelete)

	mx.HandleFunc("/config", y.configHandler).Methods(http.MethodGet)
	mx.HandleFunc("/config", y.optionsSecret).Methods(http.MethodOptions)

	if !viper.GetBool("disable-upload") {
		mx.HandleFunc("/create/file", y.createSecret).Methods(http.MethodPost)
		mx.HandleFunc("/create/file", y.optionsSecret).Methods(http.MethodOptions)
		if viper.GetBool("prefetch-secret") {
			mx.HandleFunc("/file/"+keyParameter+"/status", y.getSecretStatus).Methods(http.MethodGet)
		}
		mx.HandleFunc("/file/"+keyParameter, y.getSecret).Methods(http.MethodGet)
		mx.HandleFunc("/file/"+keyParameter, y.deleteSecret).Methods(http.MethodDelete)
	}

	mx.PathPrefix("/").Handler(http.FileServer(http.Dir(y.AssetPath)))
	return handlers.CustomLoggingHandler(nil, SecurityHeadersHandler(mx), y.httpLogFormatter())
}

const keyParameter = "{key:(?:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})}"

func validExpiration(expiration int32) bool {
	for _, ttl := range []int32{3600, 86400, 604800} {
		if ttl == expiration {
			return true
		}
	}
	return false
}

func isPGPEncrypted(content string) bool {
	if content == "" {
		return false
	}

	_, err := armor.Decode(strings.NewReader(content))
	return err == nil
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", viper.GetString("cors-allow-origin"))
		next.ServeHTTP(w, r)
	})
}

func SecurityHeadersHandler(next http.Handler) http.Handler {
	csp := []string{
		"default-src 'self'",
		"font-src 'self' data:",
		"form-action 'self'",
		"frame-ancestors 'none'",
		"img-src 'self' data:",
		"script-src 'self'",
		"style-src 'self' 'unsafe-inline'",
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-security-policy", strings.Join(csp, "; "))
		w.Header().Set("referrer-policy", "no-referrer")
		w.Header().Set("x-content-type-options", "nosniff")
		w.Header().Set("x-frame-options", "DENY")
		w.Header().Set("x-xss-protection", "1; mode=block")
		if r.URL.Scheme == "https" || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("strict-transport-security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}
