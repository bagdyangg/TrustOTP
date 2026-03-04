package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jhaals/yopass/pkg/yopass"
	"github.com/spf13/viper"
	"go.uber.org/zap/zaptest"
)

func newTestServer(t *testing.T, db Database, maxLength int, forceOneTime bool) Server {
	return Server{
		DB:                  db,
		MaxLength:           maxLength,
		ForceOneTimeSecrets: forceOneTime,
		Logger:              zaptest.NewLogger(t),
	}
}

type mockDB struct{}

func (db *mockDB) Get(key string) (yopass.Secret, error) {
	return yopass.Secret{Message: `***ENCRYPTED***`}, nil
}
func (db *mockDB) Put(key string, secret yopass.Secret) error {
	return nil
}
func (db *mockDB) Delete(key string) (bool, error) {
	return true, nil
}
func (db *mockDB) Exists(key string) (bool, error) {
	return true, nil
}
func (db *mockDB) Status(key string) (bool, error) {
	return false, nil
}

type brokenDB struct{}

func (db *brokenDB) Get(key string) (yopass.Secret, error) {
	return yopass.Secret{}, fmt.Errorf("Some error")
}
func (db *brokenDB) Put(key string, secret yopass.Secret) error {
	return fmt.Errorf("Some error")
}
func (db *brokenDB) Delete(key string) (bool, error) {
	return false, fmt.Errorf("Some error")
}
func (db *brokenDB) Exists(key string) (bool, error) {
	return false, fmt.Errorf("Some error")
}
func (db *brokenDB) Status(key string) (bool, error) {
	return false, fmt.Errorf("Some error")
}

type mockBrokenDB2 struct{}

func (db *mockBrokenDB2) Get(key string) (yopass.Secret, error) {
	return yopass.Secret{OneTime: true, Message: "encrypted"}, nil
}
func (db *mockBrokenDB2) Put(key string, secret yopass.Secret) error {
	return fmt.Errorf("Some error")
}
func (db *mockBrokenDB2) Delete(key string) (bool, error) {
	return false, nil
}
func (db *mockBrokenDB2) Exists(key string) (bool, error) {
	return false, fmt.Errorf("Some error")
}
func (db *mockBrokenDB2) Status(key string) (bool, error) {
	return true, nil
}

type mockStatusDB struct {
	oneTime bool
	exists  bool
}

func (db *mockStatusDB) Get(key string) (yopass.Secret, error) {
	if !db.exists {
		return yopass.Secret{}, fmt.Errorf("Secret not found")
	}
	return yopass.Secret{Message: "test", OneTime: db.oneTime}, nil
}

func (db *mockStatusDB) Put(key string, secret yopass.Secret) error {
	return nil
}

func (db *mockStatusDB) Delete(key string) (bool, error) {
	return true, nil
}

func (db *mockStatusDB) Exists(key string) (bool, error) {
	return db.exists, nil
}

func (db *mockStatusDB) Status(key string) (bool, error) {
	if !db.exists {
		return false, fmt.Errorf("Secret not found")
	}
	return db.oneTime, nil
}

type mockErrorDB struct {
	errorOnGet    bool
	errorOnPut    bool
	errorOnDelete bool
	errorOnStatus bool
}

func (db *mockErrorDB) Get(key string) (yopass.Secret, error) {
	if db.errorOnGet {
		return yopass.Secret{}, fmt.Errorf("Database error")
	}
	return yopass.Secret{Message: "test"}, nil
}

func (db *mockErrorDB) Put(key string, secret yopass.Secret) error {
	if db.errorOnPut {
		return fmt.Errorf("Database error")
	}
	return nil
}

func (db *mockErrorDB) Delete(key string) (bool, error) {
	if db.errorOnDelete {
		return false, fmt.Errorf("Database error")
	}
	return true, nil
}

func (db *mockErrorDB) Exists(key string) (bool, error) {
	return true, nil
}

func (db *mockErrorDB) Status(key string) (bool, error) {
	if db.errorOnStatus {
		return false, fmt.Errorf("Database error")
	}
	return false, nil
}

func TestCreateSecret(t *testing.T) {
	validPGPMessage := `-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.10.8
Comment: https://openpgpjs.org

wy4ECQMIRthQ3aO85NvgAfASIX3dTwsFVt0gshPu7n1tN05e8rpqxOk6PYNm
xtt90k4BqHuTCLNlFRJjuiuE8zdIc+j5zTN5zihxUReVqokeqULLOx2FBMHZ
sbfqaG/iDbp+qDOc98IagMyPrEqKDxnhVVOraXy5dD9RDsntLso=
=0vwU
-----END PGP MESSAGE-----`

	tt := []struct {
		name       string
		statusCode int
		body       io.Reader
		output     string
		db         Database
		maxLength  int
	}{
		{
			name:       "validRequest",
			statusCode: 200,
			body:       strings.NewReader(fmt.Sprintf(`{"message": "%s", "expiration": 3600}`, strings.ReplaceAll(validPGPMessage, "\n", "\\n"))),
			output:     "",
			db:         &mockDB{},
			maxLength:  10000,
		},
		{
			name:       "invalid json",
			statusCode: 400,
			body:       strings.NewReader(`{fooo`),
			output:     "Unable to parse json",
			db:         &mockDB{},
		},
		{
			name:       "non-PGP message",
			statusCode: 400,
			body:       strings.NewReader(`{"expiration": 3600, "message": "hello world"}`),
			output:     "Message must be PGP encrypted",
			db:         &mockDB{},
		},
		{
			name:       "message too long",
			statusCode: 400,
			body:       strings.NewReader(fmt.Sprintf(`{"expiration": 3600, "message": "%s"}`, strings.ReplaceAll(validPGPMessage, "\n", "\\n"))),
			output:     "The encrypted message is too long",
			db:         &mockDB{},
			maxLength:  1,
		},
		{
			name:       "invalid expiration",
			statusCode: 400,
			body:       strings.NewReader(fmt.Sprintf(`{"expiration": 10, "message": "%s"}`, strings.ReplaceAll(validPGPMessage, "\n", "\\n"))),
			output:     "Invalid expiration specified",
			db:         &mockDB{},
		},
		{
			name:       "broken database",
			statusCode: 500,
			body:       strings.NewReader(fmt.Sprintf(`{"expiration": 3600, "message": "%s"}`, strings.ReplaceAll(validPGPMessage, "\n", "\\n"))),
			output:     "Failed to store secret in database",
			db:         &brokenDB{},
			maxLength:  10000,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/secret", tc.body)
			rr := httptest.NewRecorder()
			y := newTestServer(t, tc.db, tc.maxLength, false)
			y.createSecret(rr, req)
			var s yopass.Secret
			json.Unmarshal(rr.Body.Bytes(), &s)
			if tc.output != "" {
				if s.Message != tc.output {
					t.Fatalf(`Expected body "%s"; got "%s"`, tc.output, s.Message)
				}
			}
			if rr.Code != tc.statusCode {
				t.Fatalf(`Expected status code %d; got "%d"`, tc.statusCode, rr.Code)
			}
		})
	}
}

func TestOneTimeEnforcement(t *testing.T) {
	validPGPMessage := `-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.10.8
Comment: https://openpgpjs.org

wy4ECQMIRthQ3aO85NvgAfASIX3dTwsFVt0gshPu7n1tN05e8rpqxOk6PYNm
xtt90k4BqHuTCLNlFRJjuiuE8zdIc+j5zTN5zihxUReVqokeqULLOx2FBMHZ
sbfqaG/iDbp+qDOc98IagMyPrEqKDxnhVVOraXy5dD9RDsntLso=
=0vwU
-----END PGP MESSAGE-----`

	tt := []struct {
		name           string
		statusCode     int
		body           io.Reader
		output         string
		requireOneTime bool
	}{
		{
			name:           "one time request",
			statusCode:     200,
			body:           strings.NewReader(fmt.Sprintf(`{"message": "%s", "expiration": 3600, "one_time": true}`, strings.ReplaceAll(validPGPMessage, "\n", "\\n"))),
			output:         "",
			requireOneTime: true,
		},
		{
			name:           "non oneTime request",
			statusCode:     400,
			body:           strings.NewReader(fmt.Sprintf(`{"message": "%s", "expiration": 3600, "one_time": false}`, strings.ReplaceAll(validPGPMessage, "\n", "\\n"))),
			output:         "Secret must be one time download",
			requireOneTime: true,
		},
		{
			name:           "one_time payload flag missing",
			statusCode:     400,
			body:           strings.NewReader(fmt.Sprintf(`{"message": "%s", "expiration": 3600}`, strings.ReplaceAll(validPGPMessage, "\n", "\\n"))),
			output:         "Secret must be one time download",
			requireOneTime: true,
		},
		{
			name:           "one time disabled",
			statusCode:     200,
			body:           strings.NewReader(fmt.Sprintf(`{"message": "%s", "expiration": 3600, "one_time": false}`, strings.ReplaceAll(validPGPMessage, "\n", "\\n"))),
			output:         "",
			requireOneTime: false,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/secret", tc.body)
			rr := httptest.NewRecorder()
			y := newTestServer(t, &mockDB{}, 10000, tc.requireOneTime)
			y.createSecret(rr, req)
			var s yopass.Secret
			json.Unmarshal(rr.Body.Bytes(), &s)
			if tc.output != "" {
				if s.Message != tc.output {
					t.Fatalf(`Expected body "%s"; got "%s"`, tc.output, s.Message)
				}
			}
			if rr.Code != tc.statusCode {
				t.Fatalf(`Expected status code %d; got "%d"`, tc.statusCode, rr.Code)
			}
		})
	}
}

func TestGetSecret(t *testing.T) {
	tt := []struct {
		name       string
		statusCode int
		output     string
		db         Database
	}{
		{
			name:       "Get Secret",
			statusCode: 200,
			output:     "***ENCRYPTED***",
			db:         &mockDB{},
		},
		{
			name:       "Secret not found",
			statusCode: 404,
			output:     "Secret not found",
			db:         &brokenDB{},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/secret/foo", nil)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			y := newTestServer(t, tc.db, 1, false)
			y.getSecret(rr, req)
			cacheControl := rr.Header().Get("Cache-Control")
			if cacheControl != "private, no-cache" {
				t.Fatalf(`Expected Cache-Control header to be "private, no-cache"; got %s`, cacheControl)
			}
			var s yopass.Secret
			json.Unmarshal(rr.Body.Bytes(), &s)
			if s.Message != tc.output {
				t.Fatalf(`Expected body "%s"; got "%s"`, tc.output, s.Message)
			}
			if rr.Code != tc.statusCode {
				t.Fatalf(`Expected status code %d; got "%d"`, tc.statusCode, rr.Code)
			}
		})
	}
}

func TestDeleteSecret(t *testing.T) {
	tt := []struct {
		name       string
		statusCode int
		output     string
		db         Database
	}{
		{
			name:       "Delete Secret",
			statusCode: 204,
			db:         &mockDB{},
		},
		{
			name:       "Secret deletion failed",
			statusCode: 500,
			output:     "Failed to delete secret",
			db:         &brokenDB{},
		},
		{
			name:       "Secret not found",
			statusCode: 404,
			output:     "Secret not found",
			db:         &mockBrokenDB2{},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("DELETE", "/secret/foo", nil)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			y := newTestServer(t, tc.db, 1, false)
			y.deleteSecret(rr, req)
			var s struct {
				Message string `json:"message"`
			}
			json.Unmarshal(rr.Body.Bytes(), &s)
			if s.Message != tc.output {
				t.Fatalf(`Expected body "%s"; got "%s"`, tc.output, s.Message)
			}
			if rr.Code != tc.statusCode {
				t.Fatalf(`Expected status code %d; got "%d"`, tc.statusCode, rr.Code)
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	tt := []struct {
		scheme       string
		headers      map[string]string
		unsetHeaders []string
	}{
		{
			scheme: "http",
			headers: map[string]string{
				"content-security-policy": "default-src 'self'; font-src 'self' data:; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'",
				"referrer-policy":         "no-referrer",
				"x-content-type-options":  "nosniff",
				"x-frame-options":         "DENY",
				"x-xss-protection":        "1; mode=block",
			},
			unsetHeaders: []string{"strict-transport-security"},
		},
		{
			scheme: "https",
			headers: map[string]string{
				"content-security-policy":   "default-src 'self'; font-src 'self' data:; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'",
				"referrer-policy":           "no-referrer",
				"strict-transport-security": "max-age=31536000",
				"x-content-type-options":    "nosniff",
				"x-frame-options":           "DENY",
				"x-xss-protection":          "1; mode=block",
			},
		},
	}

	y := newTestServer(t, &mockDB{}, 1, false)
	h := y.HTTPHandler()

	t.Parallel()
	for _, test := range tt {
		t.Run("scheme="+test.scheme, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Forwarded-Proto", test.scheme)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			for header, value := range test.headers {
				if got := rr.Header().Get(header); got != value {
					t.Errorf("Expected HTTP header %s to be %q, got %q", header, value, got)
				}
			}

			for _, header := range test.unsetHeaders {
				if got := rr.Header().Get(header); got != "" {
					t.Errorf("Expected HTTP header %s to not be set, got %q", header, got)
				}
			}
		})
	}
}

func TestConfigHandler(t *testing.T) {
	viper.Set("disable-upload", "true")

	server := newTestServer(t, &mockDB{}, 1, false)

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	w := httptest.NewRecorder()
	server.configHandler(w, req)

	res := w.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", res.StatusCode)
	}

	var config map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&config); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if got, want := config["DISABLE_UPLOAD"].(bool), true; got != want {
		t.Errorf("Expected DISABLE_UPLOAD to be %v, got %v", want, got)
	}
}

func TestConfigHandlerLanguageSwitcher(t *testing.T) {
	tt := []struct {
		name     string
		setValue bool
		expected bool
	}{
		{
			name:     "no-language-switcher disabled (default)",
			setValue: false,
			expected: false,
		},
		{
			name:     "no-language-switcher enabled",
			setValue: true,
			expected: true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			viper.Set("no-language-switcher", tc.setValue)

			server := newTestServer(t, &mockDB{}, 1, false)

			req := httptest.NewRequest(http.MethodGet, "/config", nil)
			w := httptest.NewRecorder()
			server.configHandler(w, req)

			res := w.Result()
			defer res.Body.Close()

			if res.StatusCode != http.StatusOK {
				t.Fatalf("Expected status OK, got %d", res.StatusCode)
			}

			var config map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&config); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if got, want := config["NO_LANGUAGE_SWITCHER"].(bool), tc.expected; got != want {
				t.Errorf("Expected NO_LANGUAGE_SWITCHER to be %v, got %v", want, got)
			}

			if _, exists := config["NO_LANGUAGE_SWITCHER"]; !exists {
				t.Error("Expected NO_LANGUAGE_SWITCHER key to exist in config response")
			}
		})
	}
}

func TestGetSecretStatus(t *testing.T) {
	tt := []struct {
		name       string
		statusCode int
		db         Database
		oneTime    bool
	}{
		{
			name:       "existing secret - not one time",
			statusCode: 200,
			db:         &mockStatusDB{oneTime: false, exists: true},
			oneTime:    false,
		},
		{
			name:       "existing secret - one time",
			statusCode: 200,
			db:         &mockStatusDB{oneTime: true, exists: true},
			oneTime:    true,
		},
		{
			name:       "secret not found",
			statusCode: 404,
			db:         &mockStatusDB{exists: false},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			viper.Set("prefetch-secret", true)

			req := httptest.NewRequest(http.MethodGet, "/secret/test-key/status", nil)
			w := httptest.NewRecorder()

			y := newTestServer(t, tc.db, 1, false)
			y.getSecretStatus(w, req)

			res := w.Result()
			defer res.Body.Close()

			if res.StatusCode != tc.statusCode {
				t.Fatalf("Expected status %d, got %d", tc.statusCode, res.StatusCode)
			}

			if tc.statusCode == 200 {
				var resp map[string]bool
				if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if resp["oneTime"] != tc.oneTime {
					t.Errorf("Expected oneTime to be %v, got %v", tc.oneTime, resp["oneTime"])
				}
			}
		})
	}
}
