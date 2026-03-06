package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/f46b83ee9/heimdall/config"
	"github.com/f46b83ee9/heimdall/db"
	"github.com/f46b83ee9/heimdall/handler"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/metric"
)

var (
	cfgFile string
	Version = "dev"

	// Tenant Cache Performance
	tenantCacheHits   metric.Int64Counter
	tenantCacheMisses metric.Int64Counter
)

// rootCmd is the base command for Heimdall.
var rootCmd = &cobra.Command{
	Use:   "heimdall",
	Short: "Heimdall — Identity-aware reverse proxy for Grafana Mimir",
	Long: `Heimdall is an identity-aware, multi-tenant reverse proxy for Grafana Mimir.
It enforces access control and ensures data isolation by injecting PromQL label
filters into queries based on user identity, using OPA for policy evaluation.`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path (required)")
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the Heimdall version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Heimdall version %s\n", Version)
	},
}

// initStoreAndBundle is a helper to initialize the DB store and bundle server for CLI commands.
func initStoreAndBundle() (*db.Store, *db.BundleServer, error) {
	if cfgFile == "" {
		return nil, nil, fmt.Errorf("--config flag is required")
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load config: %w", err)
	}

	gormDB, err := db.Open(cfg.Database.Driver, cfg.Database.DSN)
	if err != nil {
		return nil, nil, fmt.Errorf("database connection failed: %w", err)
	}

	store := db.NewStore(gormDB)
	if err := store.Migrate(); err != nil {
		return nil, nil, fmt.Errorf("database migration failed: %w", err)
	}

	metrics, err := handler.NewMetrics()
	if err != nil {
		return nil, nil, fmt.Errorf("initializing metrics: %w", err)
	}

	bundleServer := db.NewBundleServer(store, metrics)

	return store, bundleServer, nil
}

// withStoreAndBundle wraps command execution with standard DB and BundleServer initialization.
func withStoreAndBundle(fn func(ctx context.Context, store *db.Store, bundleServer *db.BundleServer) error) error {
	store, bundleServer, err := initStoreAndBundle()
	if err != nil {
		return err
	}
	return fn(context.Background(), store, bundleServer)
}
