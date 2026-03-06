package db

import (
	"testing"
)

func TestOpen(t *testing.T) {
	t.Run("Open SQLite", func(t *testing.T) {
		db, err := Open("sqlite", ":memory:")
		if err != nil {
			t.Fatalf("failed to open sqlite: %v", err)
		}
		if db == nil {
			t.Fatal("db is nil")
		}
	})

	t.Run("Unsupported driver", func(t *testing.T) {
		_, err := Open("mysql", "localhost")
		if err == nil {
			t.Error("expected error for unsupported driver")
		}
	})

	t.Run("Invalid DSN", func(t *testing.T) {
		// For sqlite, invalid DSN often just creates a file unless permissions fail.
		// For postgres, it will fail to parse if it's missing the protocol or malformed.
		_, err := Open("postgres", "invalid-dsn")
		if err == nil {
			t.Error("expected error for invalid dsn")
		}
	})
}
