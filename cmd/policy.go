package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/f46b83ee9/heimdall/db"
	"github.com/spf13/cobra"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage policies",
}

var policyCreateCmd = &cobra.Command{
	Use:   "create [json-file]",
	Short: "Create a policy from a JSON file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withStoreAndBundle(func(ctx context.Context, store *db.Store, bundleServer *db.BundleServer) error {
			// Read policy from JSON file
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("reading policy file: %w", err)
			}

			var policy db.Policy
			if err := json.Unmarshal(data, &policy); err != nil {
				return fmt.Errorf("parsing policy JSON: %w", err)
			}

			if err := store.CreatePolicy(ctx, &policy); err != nil {
				return fmt.Errorf("failed to create policy: %w", err)
			}

			// Rebuild bundle after policy change (invariant #11)
			if err := bundleServer.Rebuild(ctx); err != nil {
				return fmt.Errorf("bundle rebuild failed after policy create: %w", err)
			}

			slog.Info("policy created", "id", policy.ID, "name", policy.Name)
			return nil
		})
	},
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all policies",
	RunE: func(cmd *cobra.Command, args []string) error {
		return withStoreAndBundle(func(ctx context.Context, store *db.Store, bundleServer *db.BundleServer) error {
			policies, err := store.ListPolicies(ctx)
			if err != nil {
				return fmt.Errorf("failed to list policies: %w", err)
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(policies)
		})
	},
}

var policyGetCmd = &cobra.Command{
	Use:   "get [id]",
	Short: "Get a policy by ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withStoreAndBundle(func(ctx context.Context, store *db.Store, bundleServer *db.BundleServer) error {
			id, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid policy ID: %w", err)
			}

			policy, err := store.GetPolicy(ctx, uint(id))
			if err != nil {
				return fmt.Errorf("failed to get policy: %w", err)
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(policy)
		})
	},
}

var policyDeleteCmd = &cobra.Command{
	Use:   "delete [id]",
	Short: "Delete a policy by ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withStoreAndBundle(func(ctx context.Context, store *db.Store, bundleServer *db.BundleServer) error {
			id, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid policy ID: %w", err)
			}

			if err := store.DeletePolicy(ctx, uint(id)); err != nil {
				return fmt.Errorf("failed to delete policy: %w", err)
			}

			// Rebuild bundle after policy change (invariant #11)
			if err := bundleServer.Rebuild(ctx); err != nil {
				return fmt.Errorf("bundle rebuild failed after policy delete: %w", err)
			}

			slog.Info("policy deleted", "id", id)
			return nil
		})
	},
}

func init() {
	rootCmd.AddCommand(policyCmd)
	policyCmd.AddCommand(policyCreateCmd)
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyGetCmd)
	policyCmd.AddCommand(policyDeleteCmd)
}
