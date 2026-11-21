package diff_test

import (
	"encoding/json"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/diff"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/model"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/renderer"
	"strings"
	"testing"
)

func parse(t *testing.T, s string) []model.Resource {
	t.Helper()
	r, e := renderer.Parse([]byte(s), "default")
	if e != nil {
		t.Fatal(e)
	}
	if e = renderer.ResolveScope(r); e != nil {
		t.Fatal(e)
	}
	return r
}

const deployment = `apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: api
          image: demo:1
          resources:
            requests: {cpu: 250m, memory: 256Mi}
            limits: {cpu: "1", memory: 1Gi}
`

func TestSemanticQuantities(t *testing.T) {
	for _, tc := range []struct {
		name, old, new string
		changed        bool
	}{{"cpu core", "250m", "0.25", false}, {"cpu limit", "\"1\"", "1000m", false}, {"memory units", "256Mi", "268435456", false}, {"memory binary", "1Gi", "1024Mi", false}, {"cpu doubles", "250m", "500m", true}, {"memory doubles", "256Mi", "512Mi", true}} {
		t.Run(tc.name, func(t *testing.T) {
			b := parse(t, deployment)
			h := parse(t, strings.ReplaceAll(deployment, tc.old, tc.new))
			cs := diff.Compare(b, h)
			if (len(cs) > 0) != tc.changed {
				t.Fatalf("unexpected diff %+v", cs)
			}
			if tc.changed && cs[0].Fields[0].Change != "+100.0%" {
				t.Fatalf("wrong percent %+v", cs)
			}
		})
	}
}
func TestFormatOrderAndNamespace(t *testing.T) {
	a := `apiVersion: v1
kind: ConfigMap
metadata: {name: settings}
data: {x: a, y: b}`
	b := `# comment
kind: ConfigMap
data: {y: b, x: a}
metadata: {namespace: default, name: settings}
apiVersion: v1`
	if got := diff.Compare(parse(t, a), parse(t, b)); len(got) != 0 {
		t.Fatalf("false changes %+v", got)
	}
}
func TestAddDeleteAndGroupIdentity(t *testing.T) {
	a := parse(t, "apiVersion: one.io/v1\nkind: Widget\nmetadata: {name: x}\n")
	b := parse(t, "apiVersion: two.io/v1\nkind: Widget\nmetadata: {name: x}\n")
	cs := diff.Compare(a, b)
	if len(cs) != 2 || cs[0].Action != "deleted" || cs[1].Action != "added" {
		t.Fatalf("%+v", cs)
	}
	b = parse(t, "apiVersion: one.io/v2\nkind: Widget\nmetadata: {name: x}\n")
	cs = diff.Compare(a, b)
	if len(cs) != 1 || cs[0].Action != "modified" {
		t.Fatal(cs)
	}
}
func TestSecretAndEnvironmentRedaction(t *testing.T) {
	a := deployment + "---\napiVersion: v1\nkind: Secret\nmetadata: {name: password}\nstringData: {password: old-secret}\n"
	b := strings.ReplaceAll(a, "old-secret", "super-secret")
	b = strings.Replace(b, "image: demo:1", "image: demo:1\n          env:\n            - {name: PUBLIC_OR_PRIVATE, value: secret-env}", 1)
	cs := diff.Compare(parse(t, a), parse(t, b))
	j, _ := json.Marshal(cs)
	for _, value := range []string{"old-secret", "super-secret", "secret-env"} {
		if strings.Contains(string(j), value) {
			t.Fatalf("leaked %s", value)
		}
	}
	if !strings.Contains(string(j), "REDACTED") {
		t.Fatal("no redaction")
	}
}
func TestMissingAndZeroNeverPercent(t *testing.T) {
	for _, base := range []string{strings.ReplaceAll(deployment, "250m", "0"), strings.ReplaceAll(deployment, "requests: {cpu: 250m, memory: 256Mi}", "requests: {memory: 256Mi}")} {
		cs := diff.Compare(parse(t, base), parse(t, deployment))
		for _, f := range cs[0].Fields {
			if f.Change != "" {
				t.Fatalf("misleading delta %+v", f)
			}
		}
	}
}
func TestContainerOrdering(t *testing.T) {
	a := strings.Replace(deployment, "      containers:", "      containers:\n        - {name: sidecar, image: demo:2}", 1)
	b := strings.Replace(deployment, "      containers:", "      containers:", 1) + "        - {name: sidecar, image: demo:2}\n"
	if cs := diff.Compare(parse(t, a), parse(t, b)); len(cs) != 0 {
		t.Fatalf("container reorder changed: %+v", cs)
	}
}
func TestUnknownStructuralAndRuntimeMetadata(t *testing.T) {
	a := `apiVersion: example.io/v1
kind: Widget
metadata: {name: foo, resourceVersion: "1"}
spec: {count: 1}
status: {ready: false}`
	b := strings.ReplaceAll(strings.ReplaceAll(a, "\"1\"", "\"2\""), "false", "true")
	if len(diff.Compare(parse(t, a), parse(t, b))) != 0 {
		t.Fatal("runtime state creates diff")
	}
	b = strings.ReplaceAll(b, "count: 1", "count: 2")
	if len(diff.Compare(parse(t, a), parse(t, b))) != 1 {
		t.Fatal("unknown resource not diffed")
	}
}

func TestRBACSetOrdering(t *testing.T) {
	a := `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: reader}
rules:
- apiGroups: ["", apps]
  resources: [pods, deployments]
  verbs: [get, list]
- apiGroups: [batch]
  resources: [jobs]
  verbs: [watch, list]
`
	b := `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: reader}
rules:
- verbs: [list, watch]
  resources: [jobs]
  apiGroups: [batch]
- verbs: [list, get]
  resources: [deployments, pods]
  apiGroups: [apps, ""]
`
	if cs := diff.Compare(parse(t, a), parse(t, b)); len(cs) != 0 {
		t.Fatalf("RBAC set order created diff: %+v", cs)
	}
}
func TestUnknownOrderedListsPreserved(t *testing.T) {
	a := "apiVersion: example.io/v1\nkind: Widget\nmetadata: {name: a}\nspec: {rules: [a,b]}"
	b := strings.ReplaceAll(a, "[a,b]", "[b,a]")
	if len(diff.Compare(parse(t, a), parse(t, b))) != 1 {
		t.Fatal("unknown schema ordering lost")
	}
}

func TestLargeIntegerChangesRemainExact(t *testing.T) {
	a := "apiVersion: example.io/v1\nkind: Widget\nmetadata: {name: a}\nspec: {counter: 9007199254740992}"
	b := strings.ReplaceAll(a, "9007199254740992", "9007199254740993")
	cs := diff.Compare(parse(t, a), parse(t, b))
	if len(cs) != 1 || cs[0].Fields[0].After != "9007199254740993" {
		t.Fatalf("large integer lost: %+v", cs)
	}
}
func TestDottedKeysCannotCollide(t *testing.T) {
	a := `apiVersion: example.io/v1
kind: Widget
metadata: {name: a}
spec: {"a.b": 1}`
	b := `apiVersion: example.io/v1
kind: Widget
metadata: {name: a}
spec: {a: {b: 1}}`
	if len(diff.Compare(parse(t, a), parse(t, b))) != 1 {
		t.Fatal("structurally different keys collided")
	}
}
func TestProbeHeaderAndDottedConfigRedaction(t *testing.T) {
	a := "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, annotations: {example.com/value: abc}}\ndata: {\"private.config\": abc}"
	b := strings.ReplaceAll(a, "abc", "sensitive-payload")
	j, _ := json.Marshal(diff.Compare(parse(t, a), parse(t, b)))
	if strings.Contains(string(j), "sensitive-payload") || strings.Contains(string(j), "abc") {
		t.Fatal("dotted value leaked")
	}
}

func TestMalformedSensitiveValuesStillRedacted(t *testing.T) {
	a := `apiVersion: v1
kind: ConfigMap
metadata: {name: a}
data: first-private-value
`
	b := strings.ReplaceAll(a, "first-private-value", "second-private-value")
	raw, _ := json.Marshal(diff.Compare(parse(t, a), parse(t, b)))
	if strings.Contains(string(raw), "private-value") {
		t.Fatal("malformed ConfigMap leaked")
	}
	a = strings.Replace(deployment, "image: demo:1", "image: demo:1\n          env:\n            - name: PRIVATE\n              value: {unexpected: first-private-value}", 1)
	b = strings.ReplaceAll(a, "first-private-value", "second-private-value")
	raw, _ = json.Marshal(diff.Compare(parse(t, a), parse(t, b)))
	if strings.Contains(string(raw), "private-value") {
		t.Fatal("malformed env leaked")
	}
}

func TestRBACRuleInsertionAndSplitAreSemantic(t *testing.T) {
	a := `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: a}
rules:
- apiGroups: [apps]
  resources: [deployments]
  verbs: ["*"]
`
	b := a + `- apiGroups: [""]
  resources: [pods]
  verbs: [get]
`
	cs := diff.Compare(parse(t, a), parse(t, b))
	if len(cs) != 1 {
		t.Fatal(cs)
	}
	for _, f := range cs[0].Fields {
		if f.After == "*" || f.Before == "*" {
			t.Fatal("unchanged wildcard appeared in diff")
		}
	}
	a = strings.ReplaceAll(a, `"*"`, "get, list")
	b = strings.ReplaceAll(a, "get, list", "get") + `- apiGroups: [apps]
  resources: [deployments]
  verbs: [list]
`
	if cs := diff.Compare(parse(t, a), parse(t, b)); len(cs) != 0 {
		t.Fatalf("splitting an equivalent permission rule created diff %+v", cs)
	}
}
