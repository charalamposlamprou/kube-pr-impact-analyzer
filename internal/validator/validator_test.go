package validator_test

import (
	"context"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/renderer"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/validator"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStaticInvalidTypesAndQuantity(t *testing.T) {
	for _, body := range []string{`apiVersion: apps/v1
kind: Deployment
metadata: {name: bad}
spec: {replicas: "many"}`, `apiVersion: v1
kind: Pod
metadata: {name: bad}
spec:
  containers:
    - name: api
      image: demo:1
      resources: {requests: {cpu: invalid-secret-input}}`, `apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: {name: bad}
spec: {minReplicas: 5, maxReplicas: 1}`} {
		rs, e := renderer.Parse([]byte(body), "")
		if e != nil {
			t.Fatal(e)
		}
		cs := validator.Static(rs)
		if !validator.Failed(cs) {
			t.Fatal("invalid input passed")
		}
		for _, c := range cs {
			if strings.Contains(c.Detail, "invalid-secret-input") {
				t.Fatal("leaked invalid value")
			}
		}
	}
}
func TestDemoSafetyGate(t *testing.T) {
	for _, tc := range []struct {
		path string
		safe bool
	}{{"../../examples/base", true}, {"../../examples/scenarios/a-resources", true}, {"../../examples/scenarios/b-scaling", true}, {"../../examples/scenarios/c-security", false}, {"../../examples/scenarios/d-networking", false}, {"../../examples/scenarios/e-safe-image", true}} {
		r, e := renderer.New().Render(context.Background(), tc.path, nil)
		if e != nil {
			t.Fatal(e)
		}
		if e = validator.DemoSafe(r); (e == nil) != tc.safe {
			t.Fatalf("%s: %v", tc.path, e)
		}
	}
}
func TestExplicitServerContext(t *testing.T) {
	c := validator.Server(context.Background(), nil, "")
	if c.Status != "failed" {
		t.Fatal("must require explicit context")
	}
}

func TestRenderedFilesArePrivateAndExact(t *testing.T) {
	rs, e := renderer.Parse([]byte("apiVersion: example.io/v1\nkind: Widget\nmetadata: {name: a}\nspec: {counter: 9007199254740993}"), "default")
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "render.json")
	if e = os.WriteFile(path, []byte("old"), 0644); e != nil {
		t.Fatal(e)
	}
	if e = validator.Write(rs, path); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("render file is not private")
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "9007199254740993") {
		t.Fatal("render lost integer precision")
	}
}
