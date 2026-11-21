// Package validator distinguishes local structure checks from API admission and readiness.
package validator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/diff"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/model"
	apps "k8s.io/api/apps/v1"
	autoscaling "k8s.io/api/autoscaling/v2"
	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

func Static(rs []model.Resource) []model.Check {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{apps.AddToScheme, autoscaling.AddToScheme, core.AddToScheme, networking.AddToScheme, policyv1.AddToScheme, rbac.AddToScheme} {
		_ = add(scheme)
	}
	decoder := serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDeserializer()
	checks := []model.Check{}
	for _, r := range rs {
		valid := true
		details := []string{}
		b, _ := json.Marshal(r.Object)
		_, _, err := decoder.Decode(b, nil, nil)
		if err != nil && !runtime.IsNotRegisteredError(err) {
			valid = false
			details = append(details, "built-in field type or strict schema check failed (values withheld)")
		}
		if runtime.IsNotRegisteredError(err) {
			details = append(details, "generic object checks only; custom/unsupported API schema requires server validation")
		}
		fields := diff.Fields(r)
		for p, s := range fields {
			if diff.IsQuantity(p) {
				q, e := resource.ParseQuantity(s)
				if e != nil || q.Sign() < 0 {
					valid = false
					details = append(details, "invalid resource quantity (value withheld)")
				}
			}
		}
		if r.ID.Kind == "Deployment" || r.ID.Kind == "StatefulSet" || r.ID.Kind == "DaemonSet" {
			spec := Map(r.Object["spec"])
			template := Map(spec["template"])
			pod := Map(template["spec"])
			containers, _ := pod["containers"].([]any)
			if len(containers) == 0 {
				valid = false
				details = append(details, "workload requires containers")
			}
			selector := Map(Map(spec["selector"])["matchLabels"])
			labels := Map(Map(template["metadata"])["labels"])
			expressions, _ := Map(spec["selector"])["matchExpressions"].([]any)
			if len(selector) == 0 && len(expressions) == 0 {
				valid = false
				details = append(details, "workload requires a non-empty selector")
			}
			for k, v := range selector {
				if labels[k] != v {
					valid = false
					details = append(details, "selector does not match template labels")
					break
				}
			}
			for _, c := range containers {
				m := Map(c)
				if m["name"] == nil || m["image"] == nil || m["image"] == "" {
					valid = false
					details = append(details, "container requires name and image")
				}
			}
		}
		if r.ID.Kind == "HorizontalPodAutoscaler" {
			spec := Map(r.Object["spec"])
			max := Number(spec["maxReplicas"])
			min := Number(spec["minReplicas"])
			if spec["minReplicas"] == nil {
				min = 1
			}
			if max < 1 || min < 0 || min > max {
				valid = false
				details = append(details, "HPA requires maxReplicas >= max(1, minReplicas)")
			}
		}
		status := "passed"
		if !valid {
			status = "failed"
		}
		if len(details) == 0 {
			details = append(details, "built-in types and local invariants checked; not full Kubernetes admission validation")
		}
		checks = append(checks, model.Check{Name: "static: " + r.ID.String(), Status: status, Detail: strings.Join(details, "; ")})
	}
	if len(rs) == 0 {
		checks = append(checks, model.Check{Name: "static", Status: "passed", Detail: "No proposed resources in the selected targets."})
	}
	return checks
}
func Map(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}
func Failed(cs []model.Check) bool {
	for _, c := range cs {
		if c.Status == "failed" {
			return true
		}
	}
	return false
}
func Write(rs []model.Resource, path string) error {
	items := make([]any, 0, len(rs))
	for _, r := range rs {
		b, _ := json.Marshal(r.Object)
		var o map[string]any
		_ = json.Unmarshal(b, &o)
		m := Map(o["metadata"])
		if r.ID.Namespace != "" {
			m["namespace"] = r.ID.Namespace
		}
		items = append(items, o)
	}
	b, e := json.MarshalIndent(map[string]any{"apiVersion": "v1", "kind": "List", "items": items}, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}
func Server(ctx context.Context, rs []model.Resource, kubeContext string) model.Check {
	c := model.Check{Name: "Kubernetes API validation", Status: "failed"}
	if kubeContext == "" {
		c.Detail = "An explicit --context is required for API access."
		return c
	}
	if len(rs) == 0 {
		c.Status = "skipped"
		c.Detail = "No resources to validate."
		return c
	}
	f, e := os.CreateTemp("", "kube-impact-*.json")
	if e != nil {
		c.Detail = "Cannot create private manifest file."
		return c
	}
	name := f.Name()
	_ = f.Close()
	defer os.Remove(name)
	if e = Write(rs, name); e != nil {
		c.Detail = "Cannot encode manifests."
		return c
	}
	cmd := exec.CommandContext(ctx, "kubectl", "--context", kubeContext, "apply", "--dry-run=server", "--validate=strict", "--field-manager=kube-impact", "-f", name)
	if e = cmd.Run(); e != nil {
		c.Detail = "Server dry-run failed. Check API versions, namespaces, CRDs and admission constraints. Diagnostics withheld to protect manifest values."
		return c
	}
	c.Status = "passed"
	c.Detail = "Server dry-run accepted the manifests; resources were not persisted and workload readiness was not tested."
	return c
}

// DemoSafe is a strict application gate for the disposable demonstration cluster.
// This is intentionally not a general purpose production deployment permission.
func DemoSafe(rs []model.Resource) error {
	for _, r := range rs {
		if r.ID.Namespace != "impact-demo" {
			return errors.New("demo gate: only impact-demo namespace is allowed")
		}
		switch r.ID.Kind {
		case "ConfigMap":
		case "HorizontalPodAutoscaler":
			s := Map(r.Object["spec"])
			n := Number(s["maxReplicas"])
			if n > 5 {
				return errors.New("demo gate: autoscaling ceiling exceeds 5")
			}
		case "Service":
			s := Map(r.Object["spec"])
			if t := s["type"]; t != nil && t != "ClusterIP" {
				return errors.New("demo gate: only ClusterIP Services are allowed")
			}
			if s["externalIPs"] != nil || s["externalName"] != nil {
				return errors.New("demo gate: external service routing is not allowed")
			}
		case "Deployment":
			s := Map(r.Object["spec"])
			n := Number(s["replicas"])
			if n < 1 || n > 5 {
				return errors.New("demo gate: replicas must be between 1 and 5")
			}
			pod := Map(Map(s["template"])["spec"])
			for _, k := range []string{"hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"} {
				if pod[k] == true {
					return errors.New("demo gate: host/shared namespaces are not allowed")
				}
			}
			if pod["automountServiceAccountToken"] != false {
				return errors.New("demo gate: service account token mounting must be disabled")
			}
			for _, k := range []string{"initContainers", "ephemeralContainers", "volumes", "imagePullSecrets", "runtimeClassName", "nodeName"} {
				if pod[k] != nil {
					return fmt.Errorf("demo gate: %s is not allowed", k)
				}
			}
			ps := Map(pod["securityContext"])
			if ps["runAsNonRoot"] != true || Number(ps["runAsUser"]) != 10001 {
				return errors.New("demo gate: pod must explicitly use non-root UID 10001")
			}
			cs, _ := pod["containers"].([]any)
			if len(cs) != 1 {
				return errors.New("demo gate: exactly one demo container required")
			}
			for _, v := range cs {
				c := Map(v)
				if c["image"] != "kube-impact-demo:1.0.0" && c["image"] != "kube-impact-demo:1.1.0" {
					return errors.New("demo gate: only locally built approved demo images allowed")
				}
				sec := Map(c["securityContext"])
				if sec["privileged"] == true || sec["allowPrivilegeEscalation"] != false || sec["readOnlyRootFilesystem"] != true {
					return errors.New("demo gate: unsafe container security context")
				}
				if u := sec["runAsUser"]; u != nil && Number(u) != 10001 {
					return errors.New("demo gate: unexpected container UID")
				}
				if sec["runAsNonRoot"] == false {
					return errors.New("demo gate: non-root safeguard disabled")
				}
				caps := Map(sec["capabilities"])
				drops, _ := caps["drop"].([]any)
				if caps["add"] != nil || len(drops) != 1 || drops[0] != "ALL" {
					return errors.New("demo gate: all Linux capabilities must be dropped")
				}
				for _, k := range []string{"command", "args", "volumeMounts", "volumeDevices", "lifecycle"} {
					if c[k] != nil {
						return fmt.Errorf("demo gate: container %s is not allowed", k)
					}
				}
				ports, _ := c["ports"].([]any)
				for _, port := range ports {
					if Map(port)["hostPort"] != nil {
						return errors.New("demo gate: host ports are not allowed")
					}
				}
				limits := Map(Map(c["resources"])["limits"])
				for _, k := range []string{"cpu", "memory"} {
					q, e := resource.ParseQuantity(fmt.Sprint(limits[k]))
					ceiling := resource.MustParse("2")
					if k == "memory" {
						ceiling = resource.MustParse("1Gi")
					}
					if e != nil || q.Sign() <= 0 || q.Cmp(ceiling) > 0 {
						return errors.New("demo gate: resource limits missing or above demo ceiling")
					}
				}
			}
		default:
			return errors.New("demo gate: unsupported resource kind; arbitrary PR resources are never applied")
		}
	}
	return nil
}

func Number(v any) float64 {
	n, e := strconv.ParseFloat(fmt.Sprint(v), 64)
	if e != nil {
		return -1
	}
	return n
}
