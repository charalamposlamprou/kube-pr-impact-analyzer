package main

import (
	"context"
	"path/filepath"
	"testing"
)

func TestCLIExitCodes(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.json")
	for _, tc := range []struct {
		args []string
		want int
	}{{[]string{"diff", "--base", "../../examples/base", "--head", "../../examples/head", "--format", "json", "--output", out}, 0}, {[]string{"analyze", "--base", "../../examples/base", "--head", "../../examples/scenarios/c-security", "--output", out}, 3}, {[]string{"validate", "--manifests", "../../examples/scenarios/c-security", "--demo-safe", "--output", out}, 2}, {[]string{"diff", "--base", "missing", "--head", "also-missing"}, 1}, {[]string{"report", "--format", "xml"}, 1}} {
		if got := run(context.Background(), tc.args); got != tc.want {
			t.Fatalf("%v: got %d want %d", tc.args, got, tc.want)
		}
	}
}
