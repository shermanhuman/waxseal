// Package testutil holds helpers shared by tests across packages.
package testutil

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files with the actual output")

// AssertGolden compares got with the golden file at path, ignoring trailing
// whitespace and line-ending differences. Run the test with -update to
// rewrite the file instead; review the diff before committing it.
func AssertGolden(t *testing.T, path string, got []byte) {
	t.Helper()

	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create golden dir: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("update golden %s: %v", path, err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if w, g := normalize(string(want)), normalize(string(got)); w != g {
		t.Errorf("%s mismatch (run with -update to accept):\n\nwant:\n%s\n\ngot:\n%s", path, w, g)
	}
}

func normalize(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t\r")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}
