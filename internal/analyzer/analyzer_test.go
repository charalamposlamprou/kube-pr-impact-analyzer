package analyzer_test

import (
	"context"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/analyzer"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/diff"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/policy"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/renderer"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/report"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/validator"
	"strings"
	"testing"
)

func TestScenarios(t *testing.T) {
	for _, tc := range []struct {
		name           string
		changes        int
		rule, severity string
	}{{"a-resources", 1, "requests-increased", "medium"}, {"b-scaling", 2, "replicas-decreased", "medium"}, {"c-security", 1, "privileged", "high"}, {"d-networking", 1, "load-balancer", "high"}, {"e-safe-image", 1, "configuration-changed", "low"}, {"f-multiple", 3, "load-balancer", "high"}} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := (analyzer.Analyzer{Renderer: renderer.New()}).Analyze(context.Background(), "../../examples/base", "../../examples/scenarios/"+tc.name, nil, policy.Default())
			if e != nil {
				t.Fatal(e)
			}
			if len(r.Changes) != tc.changes {
				t.Fatalf("changes %d want %d", len(r.Changes), tc.changes)
			}
			found := false
			for _, f := range r.Findings {
				if f.Rule == tc.rule && f.Severity == tc.severity {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing expected finding %+v", r.Findings)
			}
			if validator.Failed(r.Checks) {
				t.Fatalf("invalid fixture %+v", r.Checks)
			}
			md := report.Markdown(r, "")
			if !strings.Contains(md, "Kubernetes Change Impact Report") || strings.Contains(md, "hello-kubernetes") {
				t.Fatal("report title/redaction")
			}
			if tc.name == "e-safe-image" {
				for _, f := range r.Findings {
					if f.Severity != "low" {
						t.Fatal("safe update overclassified")
					}
				}
			}
		})
	}
}
func TestUnchanged(t *testing.T) {
	r, e := (analyzer.Analyzer{Renderer: renderer.New()}).Analyze(context.Background(), "../../examples/base", "../../examples/base", nil, policy.Default())
	if e != nil || len(r.Changes) != 0 || len(r.Findings) != 0 {
		t.Fatalf("false differences %+v %v", r, e)
	}
}

func TestProbeFieldRemovalIsNotWholeProbeRemoval(t *testing.T) {
	r := renderer.New()
	base, e := r.Render(context.Background(), "../../examples/base", nil)
	if e != nil {
		t.Fatal(e)
	}
	head, e := r.Render(context.Background(), "../../examples/base", nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, res := range head {
		if res.ID.Kind == "Deployment" {
			pod := validator.Map(validator.Map(validator.Map(res.Object["spec"])["template"])["spec"])
			cs := pod["containers"].([]any)
			probe := validator.Map(validator.Map(cs[0])["readinessProbe"])
			delete(probe, "periodSeconds")
		}
	}
	cs := diff.Compare(base, head)
	fs := policy.Default().Evaluate(cs, head)
	for _, f := range fs {
		if f.Rule == "readiness-removed" {
			t.Fatal("partial probe change misclassified")
		}
	}
}

func TestRemovedContainerDoesNotLoseLimitsOrBecomeLatest(t *testing.T) {
	ren := renderer.New()
	base, e := ren.Render(context.Background(), "../../examples/base", nil)
	if e != nil {
		t.Fatal(e)
	}
	head, e := ren.Render(context.Background(), "../../examples/base", nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range head {
		if r.ID.Kind == "Deployment" {
			pod := validator.Map(validator.Map(validator.Map(r.Object["spec"])["template"])["spec"])
			pod["containers"] = []any{}
		}
	}
	findings := policy.Default().Evaluate(diff.Compare(base, head), head)
	for _, f := range findings {
		if f.Rule == "limits-removed" || f.Rule == "image-latest" || f.Rule == "readiness-removed" {
			t.Fatalf("deleted container produced false positive %+v", f)
		}
	}
}
