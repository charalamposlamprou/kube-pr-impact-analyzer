package renderer_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/diff"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/renderer"
)

func TestParseValidation(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		bad        bool
		count      int
	}{{"multi", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: b}\n", false, 2}, {"empty", "---\n# empty\n", false, 0}, {"syntax", "spec: [", true, 0}, {"missing", "kind: Deployment", true, 0}, {"duplicate keys", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, name: b}", true, 0}, {"list", "apiVersion: v1\nkind: List\nitems: [{apiVersion: v1, kind: ConfigMap, metadata: {name: a}}]", false, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := renderer.Parse([]byte(tc.body), "")
			if (e != nil) != tc.bad {
				t.Fatalf("error: %v", e)
			}
			if !tc.bad && len(r) != tc.count {
				t.Fatal(len(r))
			}
		})
	}
}
func TestDuplicateIdentityAndScope(t *testing.T) {
	body := "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata: {name: admin}\n"
	rs, e := renderer.Parse([]byte(body+"---\n"+body), "one")
	if e != nil {
		t.Fatal(e)
	}
	if e = renderer.ResolveScope(rs); e == nil {
		t.Fatal("expected duplicate")
	}
	rs = rs[:1]
	if e = renderer.ResolveScope(rs); e != nil || rs[0].ID.Namespace != "" {
		t.Fatal("cluster scope", e)
	}
	rs, e = renderer.Parse([]byte("apiVersion: v1\nkind: Service\nmetadata: {name: a}\n"), "custom")
	if e != nil || rs[0].ID.Namespace != "custom" {
		t.Fatal(e)
	}
}
func copyTree(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	e := filepath.WalkDir(src, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		return os.WriteFile(target, b, 0600)
	})
	if e != nil {
		t.Fatal(e)
	}
	return dst
}
func tool(t *testing.T, name string) {
	t.Helper()
	if _, e := exec.LookPath(name); e != nil {
		if os.Getenv("REQUIRE_RENDER_TOOLS") == "1" {
			t.Fatalf("required tool %s is missing", name)
		}
		t.Skip(name + " unavailable")
	}
}

// This test invokes the real Helm binary twice; source YAML is never compared.
func TestHelmValuesProduceRenderedDeploymentDiff(t *testing.T) {
	tool(t, "helm")
	b := copyTree(t, "../../examples/helm")
	h := copyTree(t, "../../examples/helm")
	p := filepath.Join(h, "values.yaml")
	v, _ := os.ReadFile(p)
	v = []byte(strings.ReplaceAll(string(v), "250m", "500m"))
	if e := os.WriteFile(p, v, 0600); e != nil {
		t.Fatal(e)
	}
	r := renderer.New()
	before, e := r.Render(context.Background(), b, nil)
	if e != nil {
		t.Fatal(e)
	}
	after, e := r.Render(context.Background(), h, nil)
	if e != nil {
		t.Fatal(e)
	}
	cs := diff.Compare(before, after)
	if len(cs) != 1 || cs[0].Resource.Kind != "Deployment" || len(cs[0].Fields) != 1 || cs[0].Fields[0].Before != "250m" || cs[0].Fields[0].After != "500m" || cs[0].Fields[0].Change != "+100.0%" {
		t.Fatalf("wrong rendered diff: %+v", cs)
	}
	same, e := r.Render(context.Background(), b, nil)
	if e != nil || len(diff.Compare(before, same)) != 0 {
		t.Fatal("non-deterministic Helm render", e)
	}
}
func TestRealKustomizePatch(t *testing.T) {
	tool(t, "kustomize")
	b := copyTree(t, "../../examples/kustomize")
	h := copyTree(t, "../../examples/kustomize")
	p := filepath.Join(h, "kustomization.yaml")
	f, e := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.WriteString("replicas:\n  - name: payment-api\n    count: 1\n")
	_ = f.Close()
	if e != nil {
		t.Fatal(e)
	}
	r := renderer.New()
	before, e := r.Render(context.Background(), b, nil)
	if e != nil {
		t.Fatal(e)
	}
	after, e := r.Render(context.Background(), h, nil)
	if e != nil {
		t.Fatal(e)
	}
	cs := diff.Compare(before, after)
	if len(cs) != 1 || len(cs[0].Fields) != 1 || cs[0].Fields[0].Path != "spec.replicas" || cs[0].Fields[0].After != "1" {
		t.Fatalf("%+v", cs)
	}
}
func TestSymlinkAndTraversalRejected(t *testing.T) {
	root := t.TempDir()
	if e := os.Symlink("/etc/passwd", filepath.Join(root, "bad.yaml")); e != nil {
		t.Fatal(e)
	}
	if _, e := renderer.New().Render(context.Background(), root, nil); e == nil {
		t.Fatal("symlink accepted")
	}
	if _, e := renderer.New().Render(context.Background(), root, []renderer.Target{{Path: "../outside"}}); e == nil {
		t.Fatal("traversal accepted")
	}
}
func TestCRDScope(t *testing.T) {
	rs, e := renderer.Parse([]byte(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata: {name: widgets.example.io}
spec: {group: example.io, scope: Cluster, names: {kind: Widget}}
---
apiVersion: example.io/v1
kind: Widget
metadata: {name: a}
`), "default")
	if e != nil {
		t.Fatal(e)
	}
	if e = renderer.ResolveScope(rs); e != nil {
		t.Fatal(e)
	}
	for _, r := range rs {
		if r.ID.Namespace != "" {
			t.Fatal(r.ID)
		}
	}
}
