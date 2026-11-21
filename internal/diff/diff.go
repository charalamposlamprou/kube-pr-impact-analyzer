// Package diff compares normalized rendered Kubernetes objects, never source YAML.
package diff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/model"
	"k8s.io/apimachinery/pkg/api/resource"
)

const Absent = "—"

var sensitive = regexp.MustCompile(`(?i)(password|passwd|token|credential|private.?key|api.?key|secret.?value|authorization)`)
var keyedLists = map[string]string{"containers": "name", "initContainers": "name", "ephemeralContainers": "name", "env": "name", "volumes": "name", "volumeMounts": "mountPath", "imagePullSecrets": "name"}

// Fields produces a stable structural representation. Associative Kubernetes lists
// are keyed by identity; ordered lists such as command/args retain their order.
func Fields(r model.Resource) map[string]string {
	out := map[string]string{}
	var walk func(any, string)
	walk = func(v any, p string) {
		switch x := v.(type) {
		case map[string]any:
			if len(x) == 0 {
				out[p] = "{}"
			}
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				np := k
				if strings.ContainsAny(k, ".[]") {
					np = p + "[" + strconv.Quote(k) + "]"
				} else if p != "" {
					np = p + "." + k
				}
				if p == "" && k == "status" {
					continue
				}
				if p == "metadata" && (k == "managedFields" || k == "resourceVersion" || k == "uid" || k == "creationTimestamp" || k == "generation") {
					continue
				}
				if p == "metadata.annotations" && k == "kubectl.kubernetes.io/last-applied-configuration" {
					continue
				}
				walk(x[k], np)
			}
		case []any:
			if len(x) == 0 {
				out[p] = "[]"
				return
			}
			segment := p[strings.LastIndex(p, ".")+1:]
			if segment == "rules" && (r.ID.Kind == "Role" || r.ID.Kind == "ClusterRole") && r.ID.Group == "rbac.authorization.k8s.io" {
				groups := map[string]map[string]any{}
				valid := true
				for _, item := range x {
					rule, ok := item.(map[string]any)
					if !ok {
						valid = false
						break
					}
					scope := map[string]any{}
					for k, v := range rule {
						if k != "verbs" {
							scope[k] = v
						}
					}
					identity := canonical(scope)
					merged, ok := groups[identity]
					if !ok {
						merged = map[string]any{}
						for k, v := range rule {
							merged[k] = v
						}
						groups[identity] = merged
					} else {
						old, _ := merged["verbs"].([]any)
						extra, _ := rule["verbs"].([]any)
						merged["verbs"] = append(old, extra...)
					}
				}
				if valid {
					for identity, rule := range groups {
						verbs, _ := rule["verbs"].([]any)
						seen := map[string]bool{}
						unique := []any{}
						for _, verb := range verbs {
							k := canonical(verb)
							if !seen[k] {
								seen[k] = true
								unique = append(unique, verb)
							}
						}
						sort.Slice(unique, func(i, j int) bool { return canonical(unique[i]) < canonical(unique[j]) })
						rule["verbs"] = unique
						walk(rule, p+"["+strconv.Quote(identity)+"]")
					}
					return
				}
			}
			key := keyedLists[segment]
			if key != "" {
				seen := map[string]bool{}
				valid := true
				for _, item := range x {
					m, ok := item.(map[string]any)
					s, _ := m[key].(string)
					if !ok || s == "" || seen[s] {
						valid = false
						break
					}
					seen[s] = true
				}
				if valid {
					for _, item := range x {
						m := item.(map[string]any)
						walk(item, p+"["+strconv.Quote(m[key].(string))+"]")
					}
					return
				}
			}
			for i, item := range x {
				walk(item, fmt.Sprintf("%s[%d]", p, i))
			}
		default:
			s := fmt.Sprint(v)
			if v == nil {
				s = "null"
			}
			if IsQuantity(p) {
				if q, e := resource.ParseQuantity(s); e == nil {
					s = QuantityDisplay(p, q)
				}
			}
			out[p] = s
		}
	}
	// Clone through JSON so caller objects are never mutated.
	b, _ := json.Marshal(r.Object)
	var obj map[string]any
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	_ = decoder.Decode(&obj)
	meta, _ := obj["metadata"].(map[string]any)
	if meta != nil {
		if r.ID.Namespace == "" {
			delete(meta, "namespace")
		} else {
			meta["namespace"] = r.ID.Namespace
		}
	}
	if r.ID.Group == "" || r.ID.Group == "apps" || r.ID.Group == "rbac.authorization.k8s.io" || r.ID.Group == "networking.k8s.io" || r.ID.Group == "policy" || r.ID.Group == "autoscaling" {
		normalizeSets(obj, "", r.ID.Kind)
	}
	walk(obj, "")
	return out
}
func canonical(v any) string { b, _ := json.Marshal(v); return string(b) }
func IsQuantity(p string) bool {
	return (strings.Contains(p, ".resources.requests.") || strings.Contains(p, ".resources.limits.") || strings.HasPrefix(p, "spec.resources.requests.") || strings.HasPrefix(p, "spec.resources.limits.")) && (strings.HasSuffix(p, ".cpu") || strings.HasSuffix(p, ".memory") || strings.HasSuffix(p, ".storage") || strings.HasSuffix(p, ".ephemeral-storage"))
}
func QuantityDisplay(p string, q resource.Quantity) string {
	n, ok := new(big.Rat).SetString(q.AsDec().String())
	if !ok {
		return q.String()
	}
	suffix := ""
	if strings.HasSuffix(p, ".cpu") {
		n.Mul(n, big.NewRat(1000, 1))
		suffix = "m"
	}
	value := strings.TrimRight(strings.TrimRight(n.FloatString(9), "0"), ".")
	if value == "" || value == "-0" {
		value = "0"
	}
	return value + suffix
}
func Display(p, s string) string {
	if s == Absent {
		return s
	}
	if IsQuantity(p) && !strings.HasSuffix(p, ".cpu") {
		n, e := strconv.ParseFloat(s, 64)
		if e == nil {
			for _, u := range []struct {
				v float64
				s string
			}{{1 << 40, "Ti"}, {1 << 30, "Gi"}, {1 << 20, "Mi"}, {1 << 10, "Ki"}} {
				if n >= u.v && math.Mod(n, u.v) == 0 {
					return strconv.FormatFloat(n/u.v, 'f', 0, 64) + u.s
				}
			}
		}
	}
	return s
}
func Safe(r model.ID, p, s string) string {
	if s == Absent {
		return s
	}
	if r.Kind == "Secret" && p != "kind" && p != "apiVersion" && p != "metadata.name" && p != "metadata.namespace" {
		return "[REDACTED]"
	}
	envLiteral := strings.Contains(p, ".env[") && (strings.HasSuffix(p, ".value") || strings.Contains(p, ".value.") || strings.Contains(p, ".value["))
	opaque := p == "data" || p == "binaryData" || p == "stringData" || strings.HasSuffix(p, ".env") || strings.HasSuffix(p, ".command") || strings.HasSuffix(p, ".args")
	if envLiteral || opaque || sensitive.MatchString(p) || (strings.Contains(p, ".annotations.") || strings.Contains(p, ".annotations[")) || (strings.HasPrefix(p, "data.") || strings.HasPrefix(p, "data[")) || (strings.HasPrefix(p, "binaryData.") || strings.HasPrefix(p, "binaryData[")) || (strings.HasPrefix(p, "stringData.") || strings.HasPrefix(p, "stringData[")) || strings.Contains(p, ".env[") && strings.HasSuffix(p, ".value") || strings.Contains(p, ".command[") || strings.Contains(p, ".args[") || strings.Contains(p, ".httpHeaders[") && strings.HasSuffix(p, ".value") {
		return "[REDACTED]"
	}
	value := Display(p, s)
	if len(value) > 2048 {
		value = string([]rune(value)[:min(len([]rune(value)), 512)]) + "… [truncated]"
	}
	return value
}
func Compare(base, head []model.Resource) []model.Change {
	before, after := map[model.ID]model.Resource{}, map[model.ID]model.Resource{}
	ids := map[model.ID]bool{}
	for _, r := range base {
		before[r.ID] = r
		ids[r.ID] = true
	}
	for _, r := range head {
		after[r.ID] = r
		ids[r.ID] = true
	}
	order := make([]model.ID, 0, len(ids))
	for id := range ids {
		order = append(order, id)
	}
	sort.Slice(order, func(i, j int) bool { return order[i].String() < order[j].String() })
	changes := []model.Change{}
	for _, id := range order {
		a, hasA := before[id]
		b, hasB := after[id]
		af, bf := map[string]string{}, map[string]string{}
		if hasA {
			af = Fields(a)
		}
		if hasB {
			bf = Fields(b)
		}
		action := "modified"
		if !hasA {
			action = "added"
		}
		if !hasB {
			action = "deleted"
		}
		paths := map[string]bool{}
		for p := range af {
			paths[p] = true
		}
		for p := range bf {
			paths[p] = true
		}
		keys := make([]string, 0, len(paths))
		for p := range paths {
			keys = append(keys, p)
		}
		sort.Strings(keys)
		fields := []model.Field{}
		for _, p := range keys {
			av, aok := af[p]
			bv, bok := bf[p]
			if aok && bok && av == bv {
				continue
			}
			if !aok {
				av = Absent
			}
			if !bok {
				bv = Absent
			}
			delta := ""
			if aok && bok && IsQuantity(p) {
				aq, e1 := resource.ParseQuantity(av)
				bq, e2 := resource.ParseQuantity(bv)
				if e1 == nil && e2 == nil && aq.Sign() > 0 {
					pct := (bq.AsApproximateFloat64()/aq.AsApproximateFloat64() - 1) * 100
					delta = fmt.Sprintf("%+.1f%%", pct)
				}
			}
			fields = append(fields, model.Field{Path: p, Before: Safe(id, p, av), After: Safe(id, p, bv), Change: delta})
		}
		if len(fields) > 0 || action != "modified" {
			changes = append(changes, model.Change{Resource: id, Action: action, Fields: fields})
		}
	}
	return changes
}

// normalizeSets handles known unordered Kubernetes list fields recursively.
func normalizeSets(v any, path, kind string) {
	switch x := v.(type) {
	case map[string]any:
		for key, item := range x {
			normalizeSets(item, path+"."+key, kind)
		}
	case []any:
		for _, item := range x {
			normalizeSets(item, path, kind)
		}
		segment := path[strings.LastIndex(path, ".")+1:]
		set := false
		if kind == "Role" || kind == "ClusterRole" {
			set = segment == "rules" || segment == "verbs" || segment == "apiGroups" || segment == "resources" || segment == "resourceNames" || segment == "nonResourceURLs"
		}
		if kind == "RoleBinding" || kind == "ClusterRoleBinding" {
			set = segment == "subjects"
		}
		if strings.Contains(path, ".capabilities.") && (segment == "add" || segment == "drop") {
			set = true
		}
		if segment == "accessModes" || segment == "matchExpressions" || strings.HasSuffix(path, ".matchExpressions.values") {
			set = true
		}
		if kind == "NetworkPolicy" && (segment == "ingress" || segment == "egress" || segment == "from" || segment == "to" || segment == "ports" || segment == "policyTypes") {
			set = true
		}
		if set {
			sort.Slice(x, func(i, j int) bool { return canonical(x[i]) < canonical(x[j]) })
		}
	}
}
