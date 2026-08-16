package ingest

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTemp drops a fixture into dir and returns its path.
func writeTemp(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("writing fixture %s: %v", name, err)
	}
	return p
}
