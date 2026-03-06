package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/f46b83ee9/heimdall/config"
	"github.com/f46b83ee9/heimdall/db"
	"github.com/f46b83ee9/heimdall/handler"
	heimdallOtel "github.com/f46b83ee9/heimdall/pkg/otel"
	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Heimdall reverse proxy server",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runServe()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func runServe() error {
	// 1. Load and validate config (fail-fast)
	if cfgFile == "" {
		return fmt.Errorf("--config flag is required")
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if err := cfg.ValidateServe(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Set default logger with OTel support (AGENTS.md Rule 222)
	var level slog.Level
	switch strings.ToLower(cfg.Server.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	slog.SetDefault(slog.New(heimdallOtel.NewOTelHandler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))))

	slog.Info("configuration loaded", "config_file", cfgFile)

	// 2. Initialize OpenTelemetry
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	otelProvider, err := heimdallOtel.Init(ctx, cfg.Telemetry)
	if err != nil {
		return fmt.Errorf("OpenTelemetry initialization failed: %w", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if shutdownErr := otelProvider.Shutdown(shutdownCtx); shutdownErr != nil {
			slog.Error("OTel shutdown error", "error", shutdownErr)
		}
	}()

	slog.Info("OpenTelemetry initialized", "enabled", cfg.Telemetry.Enabled)

	// 3. Connect to database (fail-fast)
	gormDB, err := db.Open(cfg.Database.Driver, cfg.Database.DSN)
	if err != nil {
		return fmt.Errorf("database connection failed: %w", err)
	}

	store := db.NewStore(gormDB)

	// 4. Run migrations (fail-fast)
	if err := store.Migrate(); err != nil {
		return fmt.Errorf("database migration failed: %w", err)
	}

	slog.Info("database connected and migrated", "driver", cfg.Database.Driver)

	// 5. Initialize metrics (early init for other components)
	metrics, err := handler.NewMetrics()
	if err != nil {
		return fmt.Errorf("initializing metrics: %w", err)
	}

	bundleServer := db.NewBundleServer(store, metrics)

	// Initial bundle build
	if err := bundleServer.Rebuild(ctx); err != nil {
		return fmt.Errorf("initial bundle rebuild failed: %w", err)
	}

	// Start change detection
	if cfg.Database.Driver == "postgres" {
		if err := bundleServer.StartListenNotify(ctx, cfg.Database.RefreshInterval); err != nil {
			slog.Warn("LISTEN/NOTIFY setup failed, falling back to polling", "error", err)
			bundleServer.StartPolling(ctx, cfg.Database.RefreshInterval)
		}
	} else {
		bundleServer.StartPolling(ctx, cfg.Database.RefreshInterval)
	}

	// Start bundle HTTP server + metrics endpoint
	bundleMux := http.NewServeMux()
	bundleMux.Handle("/bundles/bundle.tar.gz", bundleServer)
	bundleMux.Handle("/metrics", otelProvider.MetricsHandler)
	bundleHTTPServer := &http.Server{
		Addr:         cfg.Server.Bundle.Addr,
		Handler:      bundleMux,
		ReadTimeout:  cfg.Server.Bundle.ReadTimeout,
		WriteTimeout: cfg.Server.Bundle.WriteTimeout,
		IdleTimeout:  cfg.Server.Bundle.IdleTimeout,
	}

	bundleTLSEnabled := cfg.Server.Bundle.TLS.Enabled()
	if bundleTLSEnabled {
		bundleTLSCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		if cfg.Server.Bundle.TLS.ClientCAFile != "" {
			caCert, err := os.ReadFile(cfg.Server.Bundle.TLS.ClientCAFile)
			if err != nil {
				return fmt.Errorf("reading bundle client CA file: %w", err)
			}
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("failed to parse bundle client CA certificate from %s", cfg.Server.Bundle.TLS.ClientCAFile)
			}
			bundleTLSCfg.ClientCAs = caPool
			bundleTLSCfg.ClientAuth = tls.RequireAndVerifyClientCert
			slog.Info("bundle mTLS enabled", "client_ca", cfg.Server.Bundle.TLS.ClientCAFile)
		}

		bundleHTTPServer.TLSConfig = bundleTLSCfg
	}

	go func() {
		if bundleTLSEnabled {
			slog.Info("bundle server starting (TLS)", "addr", cfg.Server.Bundle.Addr)
			if listenErr := bundleHTTPServer.ListenAndServeTLS(cfg.Server.Bundle.TLS.CertFile, cfg.Server.Bundle.TLS.KeyFile); listenErr != nil && listenErr != http.ErrServerClosed {
				slog.Error("bundle server error", "error", listenErr)
			}
		} else {
			slog.Info("bundle server starting", "addr", cfg.Server.Bundle.Addr)
			if listenErr := bundleHTTPServer.ListenAndServe(); listenErr != nil && listenErr != http.ErrServerClosed {
				slog.Error("bundle server error", "error", listenErr)
			}
		}
	}()

	// 6. Initialize OPA client with optional auth transport
	opaTransport, err := config.NewAuthTransport(cfg.OPA.Auth, cfg.OPA.InsecureSkipVerify)
	if err != nil {
		return fmt.Errorf("initializing OPA auth: %w", err)
	}
	opaClient := handler.NewOPAClient(cfg.OPA.URL, cfg.OPA.PolicyPath, cfg.OPA.Timeout, opaTransport, metrics)

	slog.Info("metrics initialized")

	// 8. Initialize fan-out engine with optional upstream auth transport
	mimirTransport, err := config.NewAuthTransport(cfg.Mimir.Auth, cfg.Mimir.InsecureSkipVerify)
	if err != nil {
		return fmt.Errorf("initializing Mimir auth: %w", err)
	}
	fanOut := handler.NewFanOutEngine(opaClient, cfg.Mimir, cfg.FanOut, mimirTransport, metrics)

	// 9. Set up Gin router
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	h := handler.NewHandler(cfg, fanOut, gormDB)

	baseLister := &tenantListerAdapter{store: store}
	if cfg.Database.Driver != "sqlite" {
		cachedLister := handler.NewCachedTenantLister(baseLister, cfg.Database.RefreshInterval, metrics)
		h.WithTenantLister(cachedLister)
	} else {
		h.WithTenantLister(baseLister)
	}

	h.RegisterRoutes(r, metrics)

	// 10. Start HTTP(S) server
	srv := &http.Server{
		Addr:         cfg.Server.Main.Addr,
		Handler:      r,
		ReadTimeout:  cfg.Server.Main.ReadTimeout,
		WriteTimeout: cfg.Server.Main.WriteTimeout,
		IdleTimeout:  cfg.Server.Main.IdleTimeout,
	}

	tlsEnabled := cfg.Server.Main.TLS.Enabled()
	if tlsEnabled {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		if cfg.Server.Main.TLS.ClientCAFile != "" {
			caCert, err := os.ReadFile(cfg.Server.Main.TLS.ClientCAFile)
			if err != nil {
				return fmt.Errorf("reading client CA file: %w", err)
			}
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("failed to parse client CA certificate from %s", cfg.Server.Main.TLS.ClientCAFile)
			}
			tlsCfg.ClientCAs = caPool
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
			slog.Info("mTLS enabled", "client_ca", cfg.Server.Main.TLS.ClientCAFile)
		}

		srv.TLSConfig = tlsCfg
	}

	go func() {
		if tlsEnabled {
			slog.Info("Heimdall starting (TLS)", "addr", cfg.Server.Main.Addr)
			if listenErr := srv.ListenAndServeTLS(cfg.Server.Main.TLS.CertFile, cfg.Server.Main.TLS.KeyFile); listenErr != nil && listenErr != http.ErrServerClosed {
				slog.Error("server error", "error", listenErr)
				os.Exit(1)
			}
		} else {
			slog.Info("Heimdall starting", "addr", cfg.Server.Main.Addr)
			if listenErr := srv.ListenAndServe(); listenErr != nil && listenErr != http.ErrServerClosed {
				slog.Error("server error", "error", listenErr)
				os.Exit(1)
			}
		}
	}()

	// 11. Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down Heimdall...")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	g, gCtx := errgroup.WithContext(shutdownCtx)

	g.Go(func() error {
		if err := srv.Shutdown(gCtx); err != nil {
			return fmt.Errorf("server shutdown error: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		if err := bundleHTTPServer.Shutdown(gCtx); err != nil {
			return fmt.Errorf("bundle server shutdown error: %w", err)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return err
	}

	// Close database connection pool
	sqlDB, err := gormDB.DB()
	if err == nil {
		if closeErr := sqlDB.Close(); closeErr != nil {
			slog.Error("database close error", "error", closeErr)
		}
	}

	slog.Info("Heimdall stopped gracefully")
	return nil
}

// tenantListerAdapter adapts db.Store to satisfy handler.TenantLister.
type tenantListerAdapter struct {
	store *db.Store
}

func (a *tenantListerAdapter) ListTenantIDs(ctx context.Context) ([]string, error) {
	tenants, err := a.store.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(tenants))
	for i, t := range tenants {
		ids[i] = t.ID
	}
	return ids, nil
}
