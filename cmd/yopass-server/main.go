package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jhaals/yopass/pkg/server"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logLevel zapcore.Level

func init() {
	pflag.String("address", "", "listen address (default 0.0.0.0)")
	pflag.Int("port", 1337, "listen port")
	pflag.String("asset-path", "public", "path to the assets folder")
	pflag.Int("max-length", 10000, "max length of encrypted secret")
	pflag.String("redis", "redis://localhost:6379/0", "Redis URL")
	pflag.Bool("force-onetime-secrets", false, "reject non onetime secrets from being created")
	pflag.String("cors-allow-origin", "*", "Access-Control-Allow-Origin")
	pflag.Bool("disable-upload", false, "disable the /file upload endpoints")
	pflag.Bool("prefetch-secret", true, "Display information that the secret might be one time use")
	pflag.Bool("disable-features", false, "disable features")
	pflag.Bool("no-language-switcher", false, "disable the language switcher in the UI")
	pflag.StringSlice("trusted-proxies", []string{}, "trusted proxy IP addresses or CIDR blocks for X-Forwarded-For header validation")
	pflag.String("privacy-notice-url", "", "URL to privacy notice page")
	pflag.String("imprint-url", "", "URL to imprint/legal notice page")
	pflag.CommandLine.AddGoFlag(&flag.Flag{Name: "log-level", Usage: "Log level", Value: &logLevel})

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	if err := viper.BindPFlags(pflag.CommandLine); err != nil {
		log.Fatalf("Unable to bind flags: %v", err)
	}

	pflag.Parse()
}

func main() {
	logger := configureZapLogger()
	db, err := setupDatabase(logger)
	if err != nil {
		logger.Fatal("failed to setup database", zap.Error(err))
	}

	quit := make(chan os.Signal, 1)

	y := server.Server{
		DB:                  db,
		MaxLength:           viper.GetInt("max-length"),
		ForceOneTimeSecrets: viper.GetBool("force-onetime-secrets"),
		AssetPath:           viper.GetString("asset-path"),
		Logger:              logger,
		TrustedProxies:      viper.GetStringSlice("trusted-proxies"),
	}
	yopassSrv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", viper.GetString("address"), viper.GetInt("port")),
		Handler: y.HTTPHandler(),
	}
	go func() {
		logger.Info("Starting yopass server", zap.String("address", yopassSrv.Addr))
		logger.Info("Loading assets from: ", zap.String("asset-path", y.AssetPath))
		if err := yopassSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("yopass stopped unexpectedly", zap.Error(err))
		}
	}()

	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	logger.Info("Shutting down HTTP server", zap.String("signal", sig.String()))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := yopassSrv.Shutdown(ctx); err != nil {
		logger.Fatal("shutdown error: %s", zap.Error(err))
	}
	logger.Info("Server shut down")
}

func configureZapLogger() *zap.Logger {
	loggerCfg := zap.NewProductionConfig()
	loggerCfg.Level.SetLevel(logLevel)

	logger, err := loggerCfg.Build()
	if err != nil {
		log.Fatalf("Unable to build logger %v", err)
	}
	zap.ReplaceGlobals(logger)
	return logger
}

func setupDatabase(logger *zap.Logger) (server.Database, error) {
	redisURL := viper.GetString("redis")
	db, err := server.NewRedis(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Redis URL: %w", err)
	}
	logger.Debug("configured Redis", zap.String("url", redisURL))
	return db, nil
}
