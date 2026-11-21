// Package policy applies deterministic, configurable change-based risk rules.
package policy

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/diff"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/model"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/yaml"
)

type Rule struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Severity string `json:"severity,omitempty"`
}
type Policy struct {
	FailOn                            string          `json:"failOn"`
	SignificantRequestIncreasePercent float64         `json:"significantRequestIncreasePercent"`
	RequireLimits                     bool            `json:"requireLimits"`
	Rules                             map[string]Rule `json:"rules"`
}

var ruleNames = map[string]bool{"privileged": true, "rbac-wildcard": true, "network-policy-deleted": true, "run-as-root": true, "limits-removed": true, "load-balancer": true, "requests-increased": true, "replicas-decreased": true, "readiness-removed": true, "image-latest": true, "hpa-max-decreased": true, "pdb-weakened": true, "host-network": true, "host-path": true, "security-weakened": true, "configuration-changed": true}

func Default() Policy {
	return Policy{FailOn: "high", SignificantRequestIncreasePercent: 50, RequireLimits: true, Rules: map[string]Rule{}}
}
func Load(path string) (Policy, error) {
	p := Default()
	if path == "" {
		return p, nil
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return p, e
	}
	if e = yaml.UnmarshalStrict(b, &p); e != nil {
		return p, errors.New("invalid policy YAML")
	}
	if p.FailOn != "none" && model.Rank(p.FailOn) == 0 {
		return p, errors.New("failOn must be none, low, medium or high")
	}
	if p.SignificantRequestIncreasePercent < 0 {
		return p, errors.New("request threshold cannot be negative")
	}
	for name, r := range p.Rules {
		if !ruleNames[name] {
			return p, fmt.Errorf("unknown policy rule %q", name)
		}
		if r.Severity != "" && model.Rank(r.Severity) == 0 {
			return p, fmt.Errorf("invalid severity for rule %s", name)
		}
	}
	return p, nil
}
func (p Policy) Violated(fs []model.Finding) bool {
	if p.FailOn == "none" {
		return false
	}
	for _, f := range fs {
		if model.Rank(f.Severity) >= model.Rank(p.FailOn) {
			return true
		}
	}
	return false
}
func (p Policy) Evaluate(changes []model.Change, proposed ...[]model.Resource) []model.Finding {
	out := []model.Finding{}
	fullHead := map[model.ID]map[string]string{}
	if len(proposed) > 0 {
		for _, r := range proposed[0] {
			fullHead[r.ID] = diff.Fields(r)
		}
	}
	for _, c := range changes {
		headFields := fullHead[c.Resource]
		containerExists := func(path string) bool {
			if len(proposed) == 0 {
				return true
			}
			for _, kind := range []string{"containers[", "initContainers[", "ephemeralContainers["} {
				if i := strings.Index(path, kind); i >= 0 {
					suffix := path[i:]
					end := strings.Index(suffix, "].")
					if end >= 0 {
						prefix := path[:i] + suffix[:end+2]
						for key := range headFields {
							if strings.HasPrefix(key, prefix) {
								return true
							}
						}
						return false
					}
				}
			}
			return true
		}
		add := func(rule, sev string, f model.Field, why, action string) {
			if r, ok := p.Rules[rule]; ok {
				if r.Enabled != nil && !*r.Enabled {
					return
				}
				if r.Severity != "" {
					sev = r.Severity
				}
			}
			out = append(out, model.Finding{Rule: rule, Severity: sev, Resource: c.Resource, Field: f.Path, Before: f.Before, After: f.After, Explanation: why, Recommendation: action})
		}
		if c.Action == "deleted" && c.Resource.Kind == "NetworkPolicy" {
			add("network-policy-deleted", "high", model.Field{Path: "resource", Before: "present", After: diff.Absent}, "NetworkPolicy was removed. Selected pods could have broader access, depending on remaining policies and the network plugin.", "Review remaining ingress and egress isolation.")
		}
		for _, f := range c.Fields {
			path, a, b := f.Path, f.Before, f.After
			live := c.Action != "deleted" && containerExists(path)
			switch {
			case live && strings.HasSuffix(path, ".privileged") && b == "true":
				add("privileged", "high", f, "Privileged execution was enabled, expanding container access to the host.", "Remove privileged mode or document a narrowly scoped exception.")
			case live && (c.Resource.Kind == "Role" || c.Resource.Kind == "ClusterRole") && strings.HasPrefix(path, "rules[") && b == "*":
				add("rbac-wildcard", "high", f, "A wildcard permission was introduced; access can include current and future API resources or actions.", "Enumerate only required verbs and resources.")
			case live && (strings.HasSuffix(path, ".runAsUser") && b == "0" || strings.HasSuffix(path, ".runAsNonRoot") && a == "true" && b != "true"):
				add("run-as-root", "high", f, "Root execution is explicitly requested or a non-root safeguard was removed. Effective identity also depends on inherited context and image metadata.", "Set runAsNonRoot and an explicit non-zero UID; review inherited pod settings.")
			case live && p.RequireLimits && strings.Contains(path, ".resources.limits.") && b == diff.Absent:
				add("limits-removed", "high", f, "A configured resource limit was removed under the requireLimits policy. Admission defaults may still apply.", "Restore the limit or update the reviewed policy exception.")
			case live && c.Resource.Kind == "Service" && path == "spec.type" && b == "LoadBalancer":
				add("load-balancer", "high", f, "Service type now requests a load balancer; provider settings may increase network exposure and cost.", "Confirm intended exposure, firewall rules and provider annotations.")
			case live && strings.HasSuffix(path, ".hostNetwork") && b == "true":
				add("host-network", "high", f, "Host networking was enabled, sharing the node network namespace.", "Prefer pod networking; review port conflicts and isolation.")
			case live && strings.Contains(path, ".hostPath.path") && b != diff.Absent:
				add("host-path", "high", f, "A host filesystem mount was added or changed.", "Prefer a PVC or ephemeral volume and avoid host filesystem access.")
			case live && strings.HasSuffix(path, ".allowPrivilegeEscalation") && a == "false" && b != "false":
				add("security-weakened", "high", f, "The explicit restriction on privilege escalation was removed or disabled.", "Set allowPrivilegeEscalation to false.")
			case live && strings.Contains(path, ".resources.requests.") && diff.IsQuantity(path):
				aq, e1 := resource.ParseQuantity(a)
				bq, e2 := resource.ParseQuantity(b)
				if e1 == nil && e2 == nil && aq.Sign() > 0 && bq.Cmp(aq) > 0 {
					pct := (bq.AsApproximateFloat64()/aq.AsApproximateFloat64() - 1) * 100
					if pct >= p.SignificantRequestIncreasePercent {
						add("requests-increased", "medium", f, fmt.Sprintf("Resource reservation increased by %.1f%%. Scheduling could be affected by available node capacity; this is not evidence of a scheduling failure.", pct), "Check allocatable capacity, quotas and rollout surge requirements.")
					}
				}
			case live && path == "spec.replicas" && decreased(a, b):
				add("replicas-decreased", "medium", f, "Desired replicas decreased, potentially reducing redundancy or throughput.", "Check traffic, HPA ownership and disruption requirements.")
			case live && strings.Contains(path, ".readinessProbe.") && b == diff.Absent && !hasProbe(c, path, headFields, len(proposed) > 0):
				add("readiness-removed", "medium", f, "Readiness probing was removed; traffic eligibility may no longer reflect application health.", "Restore an appropriate readiness probe.")
			case live && b != diff.Absent && strings.HasSuffix(path, ".image") && (strings.HasSuffix(b, ":latest") || !strings.Contains(b, "@") && !strings.Contains(b[strings.LastIndex(b, "/")+1:], ":")):
				add("image-latest", "medium", f, "The image uses latest or an implicit latest tag, which can resolve to changing content.", "Pin an approved version, preferably by digest.")
			case live && c.Resource.Kind == "HorizontalPodAutoscaler" && path == "spec.maxReplicas" && decreased(a, b):
				add("hpa-max-decreased", "medium", f, "The autoscaling ceiling decreased, reducing potential scale-out capacity.", "Check peak load and current autoscaler metrics.")
			case live && c.Resource.Kind == "PodDisruptionBudget" && (path == "spec.minAvailable" || path == "spec.maxUnavailable") && weakerPDB(path, a, b):
				add("pdb-weakened", "medium", f, "The disruption budget became less protective or its interpretation changed.", "Verify allowable concurrent voluntary disruptions against replicas.")
			}
		}
		// Every changed resource gets a conservative contextual note, including generic CRDs.
		if c.Action == "deleted" && c.Resource.Kind == "PodDisruptionBudget" {
			add("pdb-weakened", "medium", model.Field{Path: "resource", Before: "present", After: diff.Absent}, "The disruption budget was deleted; this removes its voluntary-disruption protection.", "Verify another budget covers the workload.")
		}
		if len(c.Fields) > 0 {
			add("configuration-changed", "low", model.Field{Path: "resource", Before: state(c.Action, true), After: state(c.Action, false)}, impact(c), "Review the rendered changes and validate against the target cluster's policies.")
		}
	}
	return dedupe(out)
}
func state(action string, before bool) string {
	if before && action == "added" || !before && action == "deleted" {
		return diff.Absent
	}
	return "present"
}
func decreased(a, b string) bool {
	x, e1 := strconv.ParseFloat(a, 64)
	y, e2 := strconv.ParseFloat(b, 64)
	return e1 == nil && e2 == nil && y < x
}
func weakerPDB(path, a, b string) bool {
	if b == diff.Absent {
		return true
	}
	if a == diff.Absent {
		return false
	}
	if strings.HasSuffix(a, "%") != strings.HasSuffix(b, "%") {
		return true
	}
	a = strings.TrimSuffix(a, "%")
	b = strings.TrimSuffix(b, "%")
	if path == "spec.maxUnavailable" {
		return decreased(b, a)
	}
	return decreased(a, b)
}
func hasProbe(c model.Change, path string, head map[string]string, complete bool) bool {
	prefix := strings.Split(path, ".readinessProbe.")[0] + ".readinessProbe."
	if complete {
		for key := range head {
			if strings.HasPrefix(key, prefix) {
				return true
			}
		}
		return false
	}
	for _, f := range c.Fields {
		if strings.HasPrefix(f.Path, prefix) && f.After != diff.Absent {
			return true
		}
	}
	return false
}
func dedupe(fs []model.Finding) []model.Finding {
	seen := map[string]bool{}
	out := []model.Finding{}
	for _, f := range fs {
		k := f.Resource.String() + f.Rule + f.Field
		if f.Rule == "readiness-removed" {
			k = f.Resource.String() + f.Rule + strings.Split(f.Field, ".readinessProbe.")[0]
		}
		if !seen[k] {
			out = append(out, f)
			seen[k] = true
		}
	}
	return out
}
func impact(c model.Change) string {
	if c.Action == "deleted" {
		return "Resource deletion is confirmed. Consumers or dependents may be affected; impact depends on runtime use."
	}
	switch c.Resource.Kind {
	case "Deployment", "StatefulSet", "DaemonSet":
		return "Workload configuration changed. Pod-template changes can trigger replacement or rollout according to the workload strategy."
	case "Service", "Ingress", "NetworkPolicy":
		return "Network configuration changed. Reachability depends on selectors, controllers and other active policies."
	case "ConfigMap", "Secret":
		return "Configuration changed; values are redacted. Running applications may require a restart or reload to consume changes."
	case "PersistentVolumeClaim":
		return "Storage configuration changed. Expansion, binding and immutable-field constraints require cluster validation."
	case "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "ServiceAccount":
		return "Access configuration changed. Effective permissions depend on all applicable bindings and admission controls."
	case "HorizontalPodAutoscaler":
		return "Autoscaling configuration changed; observed scaling depends on metrics availability and workload demand."
	}
	return "Rendered resource configuration changed. Runtime consequences require controller and cluster-specific validation."
}
