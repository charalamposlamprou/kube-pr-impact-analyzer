package policy_test

import (
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/diff"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/model"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/policy"
	"os"
	"path/filepath"
	"testing"
)

func TestRules(t *testing.T) {
	for _, tc := range []struct{ name, kind, path, a, b, rule, severity string }{{"privileged", "Deployment", "spec.template.spec.containers[\"api\"].securityContext.privileged", "false", "true", "privileged", "high"}, {"wildcard", "ClusterRole", "rules[0].verbs[0]", "get", "*", "rbac-wildcard", "high"}, {"root", "Deployment", "spec.template.spec.securityContext.runAsUser", "10001", "0", "run-as-root", "high"}, {"limits", "Deployment", "spec.template.spec.containers[\"api\"].resources.limits.cpu", "1000m", diff.Absent, "limits-removed", "high"}, {"requests", "Deployment", "spec.template.spec.containers[\"api\"].resources.requests.cpu", "250m", "500m", "requests-increased", "medium"}, {"small request", "Deployment", "spec.template.spec.containers[\"api\"].resources.requests.cpu", "250m", "260m", "configuration-changed", "low"}, {"replicas", "Deployment", "spec.replicas", "3", "1", "replicas-decreased", "medium"}, {"probe", "Deployment", "spec.template.spec.containers[\"api\"].readinessProbe.httpGet.path", "/ready", diff.Absent, "readiness-removed", "medium"}, {"latest", "Deployment", "spec.template.spec.containers[\"api\"].image", "image:1", "image:latest", "image-latest", "medium"}, {"hpa", "HorizontalPodAutoscaler", "spec.maxReplicas", "5", "2", "hpa-max-decreased", "medium"}, {"pdb", "PodDisruptionBudget", "spec.minAvailable", "2", "1", "pdb-weakened", "medium"}, {"pdb percentage", "PodDisruptionBudget", "spec.maxUnavailable", "20%", "50%", "pdb-weakened", "medium"}, {"host", "Deployment", "spec.template.spec.hostNetwork", "false", "true", "host-network", "high"}, {"hostpath", "Deployment", "spec.template.spec.volumes[\"data\"].hostPath.path", diff.Absent, "/var/run", "host-path", "high"}} {
		t.Run(tc.name, func(t *testing.T) {
			cs := []model.Change{{Resource: model.ID{Kind: tc.kind, Name: "api"}, Action: "modified", Fields: []model.Field{{Path: tc.path, Before: tc.a, After: tc.b}}}}
			fs := policy.Default().Evaluate(cs)
			for _, f := range fs {
				if f.Rule == tc.rule && f.Severity == tc.severity {
					if f.Explanation == "" || f.Recommendation == "" {
						t.Fatal("missing explanation")
					}
					return
				}
			}
			t.Fatalf("missing %s: %+v", tc.rule, fs)
		})
	}
}
func TestDeletesAndPolicyOverrides(t *testing.T) {
	cs := []model.Change{{Resource: model.ID{Kind: "NetworkPolicy", Name: "deny"}, Action: "deleted"}}
	p := policy.Default()
	if !p.Violated(p.Evaluate(cs)) {
		t.Fatal("deletion should fail")
	}
	disabled := false
	p.Rules["network-policy-deleted"] = policy.Rule{Enabled: &disabled}
	if len(p.Evaluate(cs)) != 0 {
		t.Fatal("disabled rule emitted")
	}
	p.Rules["network-policy-deleted"] = policy.Rule{Severity: "low"}
	if p.Violated(p.Evaluate(cs)) {
		t.Fatal("override ignored")
	}
	p.FailOn = "none"
	if p.Violated([]model.Finding{{Severity: "high"}}) {
		t.Fatal("none must not fail")
	}
}
func TestPolicyValidation(t *testing.T) {
	for _, text := range []string{"failOn: critical", "unknown: true", "rules: {typo: {severity: high}}", "significantRequestIncreasePercent: -1", "rules: {privileged: {severity: danger}}"} {
		p := filepath.Join(t.TempDir(), "policy.yaml")
		_ = os.WriteFile(p, []byte(text), 0600)
		if _, e := policy.Load(p); e == nil {
			t.Fatalf("accepted invalid policy %s", text)
		}
	}
}
