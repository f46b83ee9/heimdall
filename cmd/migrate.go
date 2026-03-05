package cmd

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, _, err := initStoreAndBundle()
		if err != nil {
			return err
		}

		if err := store.Migrate(); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}

		slog.Info("migrations completed successfully")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(migrateCmd)
}
