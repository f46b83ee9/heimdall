package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/f46b83ee9/heimdall/db"
	"github.com/spf13/cobra"
)

var tenantCmd = &cobra.Command{
	Use:   "tenant",
	Short: "Manage tenants",
}

var tenantCreateCmd = &cobra.Command{
	Use:   "create [id] [name]",
	Short: "Create a new tenant",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withStoreAndBundle(func(ctx context.Context, store *db.Store, bundleServer *db.BundleServer) error {
			tenant := &db.Tenant{
				ID:   args[0],
				Name: args[1],
			}

			if err := store.CreateTenant(ctx, tenant); err != nil {
				return fmt.Errorf("failed to create tenant: %w", err)
			}

			// Rebuild bundle after tenant change (invariant #11)
			if err := bundleServer.Rebuild(ctx); err != nil {
				return fmt.Errorf("bundle rebuild failed after tenant create: %w", err)
			}

			slog.Info("tenant created", "id", tenant.ID, "name", tenant.Name)
			return nil
		})
	},
}

var tenantListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tenants",
	RunE: func(cmd *cobra.Command, args []string) error {
		return withStoreAndBundle(func(ctx context.Context, store *db.Store, bundleServer *db.BundleServer) error {
			tenants, err := store.ListTenants(ctx)
			if err != nil {
				return fmt.Errorf("failed to list tenants: %w", err)
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(tenants)
		})
	},
}

var tenantDeleteCmd = &cobra.Command{
	Use:   "delete [id]",
	Short: "Delete a tenant",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withStoreAndBundle(func(ctx context.Context, store *db.Store, bundleServer *db.BundleServer) error {
			if err := store.DeleteTenant(ctx, args[0]); err != nil {
				return fmt.Errorf("failed to delete tenant: %w", err)
			}

			// Rebuild bundle after tenant change (invariant #11)
			if err := bundleServer.Rebuild(ctx); err != nil {
				return fmt.Errorf("bundle rebuild failed after tenant delete: %w", err)
			}

			slog.Info("tenant deleted", "id", args[0])
			return nil
		})
	},
}

func init() {
	rootCmd.AddCommand(tenantCmd)
	tenantCmd.AddCommand(tenantCreateCmd)
	tenantCmd.AddCommand(tenantListCmd)
	tenantCmd.AddCommand(tenantDeleteCmd)
}
