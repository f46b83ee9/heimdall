package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	Use:   "create [json-file|-]",
	Short: "Create one or more policies from a JSON file or stdin",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withStoreAndBundle(func(ctx context.Context, store *db.Store, bundleServer *db.BundleServer) error {
			var data []byte
			var err error

			// 1. Read input from file or stdin
			if len(args) == 0 || args[0] == "-" {
				data, err = io.ReadAll(os.Stdin)
			} else {
				data, err = os.ReadFile(args[0])
			}
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}

			// 2. Parse input (handle single object or array)
			var raw json.RawMessage
			if err := json.Unmarshal(data, &raw); err != nil {
				return fmt.Errorf("invalid JSON: %w", err)
			}

			var policies []db.Policy
			if raw[0] == '[' {
				// It's an array
				if err := json.Unmarshal(raw, &policies); err != nil {
					return fmt.Errorf("parsing policy array: %w", err)
				}
			} else {
				// It's a single object
				var p db.Policy
				if err := json.Unmarshal(raw, &p); err != nil {
					return fmt.Errorf("parsing policy object: %w", err)
				}
				policies = append(policies, p)
			}

			// 3. Create policies
			for _, p := range policies {
				// Clear ID for creation to ensure auto-increment or new record
				p.ID = 0
				if err := store.CreatePolicy(ctx, &p); err != nil {
					return fmt.Errorf("failed to create policy %q: %w", p.Name, err)
				}
				slog.Info("policy created", "id", p.ID, "name", p.Name)
			}

			// 4. Rebuild bundle once for the whole batch (Rule 277)
			if err := bundleServer.Rebuild(ctx); err != nil {
				return fmt.Errorf("bundle rebuild failed after batch create: %w", err)
			}

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
