// Package renderer renders each revision independently, without shell evaluation.
package renderer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/model"
	yaml3 "gopkg.in/yaml.v3"
	"sigs.k8s.io/yaml"
)

const MaxBytes = 16 << 20

type Target struct {
	Path      string   `json:"path"`
	Mode      string   `json:"mode"`
	Namespace string   `json:"namespace"`
	Release   string   `json:"release"`
	Values    []string `json:"values"`
}
type Config struct {
	Targets []Target `json:"targets"`
}
type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type ExecRunner struct{}
type cappedBuffer struct{ bytes.Buffer }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > MaxBytes {
		return 0, errors.New("render output exceeds 16 MiB")
	}
	return b.Buffer.Write(p)
}
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, name, args...)
	var out cappedBuffer
	c.Stdout = &out
	// Tool diagnostics can echo Secret values. Deliberately do not capture stderr.
	c.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.TempDir(), "HELM_NO_PLUGINS=1"}
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("%s failed (diagnostics suppressed to protect manifest values): %w", name, err)
	}
	return out.Bytes(), nil
}

type Renderer struct{ Runner Runner }

func New() Renderer { return Renderer{Runner: ExecRunner{}} }
func LoadConfig(path string) (Config, error) {
	var c Config
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	e = yaml.UnmarshalStrict(b, &c)
	if e == nil && len(c.Targets) == 0 {
		e = errors.New("configuration requires at least one target")
	}
	return c, e
}
func safePath(root, rel string) (string, error) {
	if filepath.IsAbs(rel) {
		return "", errors.New("target paths must be relative")
	}
	p := filepath.Join(root, rel)
	r, e := filepath.Rel(root, p)
	if e != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", errors.New("target escapes revision root")
	}
	// Check existing ancestors too: a target may be beneath a symlink.
	for ancestor := p; ; ancestor = filepath.Dir(ancestor) {
		info, err := os.Lstat(ancestor)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("target ancestors must not be symlinks")
		}
		if ancestor == root || ancestor == filepath.Dir(ancestor) {
			break
		}
	}
	return p, nil
}
func rejectLinks(root string) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlinks are not allowed in render input: %s", p)
		}
		return nil
	})
}
func (r Renderer) Render(ctx context.Context, root string, targets []Target) ([]model.Resource, error) {
	root, e := filepath.Abs(root)
	if e != nil {
		return nil, e
	}
	if len(targets) == 0 {
		targets = []Target{{Path: ".", Mode: "auto"}}
	}
	var objects []model.Resource
	for _, t := range targets {
		p, e := safePath(root, t.Path)
		if e != nil {
			return nil, e
		}
		if _, e = os.Stat(p); os.IsNotExist(e) {
			continue
		} else if e != nil {
			return nil, errors.New("cannot access render target")
		}
		if e = rejectLinks(p); e != nil {
			return nil, e
		}
		mode := t.Mode
		if mode == "" || mode == "auto" {
			mode = "yaml"
			if exists(filepath.Join(p, "Chart.yaml")) {
				mode = "helm"
			} else if exists(filepath.Join(p, "kustomization.yaml")) || exists(filepath.Join(p, "kustomization.yml")) || exists(filepath.Join(p, "Kustomization")) {
				mode = "kustomize"
			}
		}
		var data []byte
		switch mode {
		case "helm":
			release := t.Release
			if release == "" {
				release = "kube-impact"
			}
			ns := t.Namespace
			if ns == "" {
				ns = "default"
			}
			args := []string{"template", release, p, "--namespace", ns, "--include-crds", "--kube-version", "1.35.0"}
			for _, v := range t.Values {
				vp, err := safePath(p, v)
				if err != nil {
					return nil, err
				}
				args = append(args, "--values", vp)
			}
			data, e = r.Runner.Run(ctx, "helm", args...)
		case "kustomize":
			data, e = r.Runner.Run(ctx, "kustomize", "build", p, "--load-restrictor=LoadRestrictionsRootOnly")
		case "yaml":
			data, e = readYAML(p)
		default:
			return nil, fmt.Errorf("unsupported render mode %q", mode)
		}
		if e != nil {
			return nil, e
		}
		parsed, e := Parse(data, t.Namespace)
		if e != nil {
			return nil, fmt.Errorf("render target %s: %w", t.Path, e)
		}
		objects = append(objects, parsed...)
	}
	if err := ResolveScope(objects); err != nil {
		return nil, err
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].ID.String() < objects[j].ID.String() })
	return objects, nil
}
func exists(p string) bool { _, e := os.Stat(p); return e == nil }
func readYAML(root string) ([]byte, error) {
	var out bytes.Buffer
	e := filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			if p != root && (d.Name() == ".git" || d.Name() == "charts" || d.Name() == "templates") {
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(p); ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		if info.Size()+int64(out.Len()) > MaxBytes {
			return errors.New("manifest input exceeds 16 MiB")
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		out.WriteString("\n---\n")
		out.Write(b)
		return nil
	})
	return out.Bytes(), e
}
func Parse(data []byte, namespace string) ([]model.Resource, error) {
	if len(data) > MaxBytes {
		return nil, errors.New("manifest input exceeds 16 MiB")
	}
	if namespace == "" {
		namespace = "default"
	}
	dec := yaml3.NewDecoder(bytes.NewReader(data))
	var result []model.Resource
	for doc := 1; ; doc++ {
		var node yaml3.Node
		e := dec.Decode(&node)
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, fmt.Errorf("invalid YAML document %d (content withheld)", doc)
		}
		if len(node.Content) == 0 {
			continue
		}
		var v any
		if e = node.Decode(&v); e != nil {
			return nil, fmt.Errorf("invalid or duplicate YAML keys in document %d", doc)
		}
		b, e := yaml3.Marshal(v)
		if e != nil {
			return nil, errors.New("invalid YAML value")
		}
		j, e := yaml.YAMLToJSONStrict(b)
		if e != nil {
			return nil, errors.New("invalid YAML mapping")
		}
		var obj map[string]any
		jd := json.NewDecoder(bytes.NewReader(j))
		jd.UseNumber()
		if e = jd.Decode(&obj); e != nil {
			return nil, errors.New("manifest must be an object")
		}
		if len(obj) == 0 {
			continue
		}
		var add func(map[string]any) error
		add = func(o map[string]any) error {
			kind, _ := o["kind"].(string)
			api, _ := o["apiVersion"].(string)
			if kind == "List" {
				items, ok := o["items"].([]any)
				if !ok {
					return errors.New("list.items must be an array")
				}
				for _, v := range items {
					m, ok := v.(map[string]any)
					if !ok {
						return errors.New("list item must be an object")
					}
					if err := add(m); err != nil {
						return err
					}
				}
				return nil
			}
			m, _ := o["metadata"].(map[string]any)
			name, _ := m["name"].(string)
			ns, _ := m["namespace"].(string)
			if kind == "" || api == "" || name == "" {
				return errors.New("resource requires apiVersion, kind and metadata.name")
			}
			if ns == "" {
				ns = namespace
			}
			group := ""
			if strings.Contains(api, "/") {
				group = strings.SplitN(api, "/", 2)[0]
			}
			result = append(result, model.Resource{ID: model.ID{Group: group, Kind: kind, Namespace: ns, Name: name}, Object: o})
			return nil
		}
		if e = add(obj); e != nil {
			return nil, fmt.Errorf("document %d: %w", doc, e)
		}
	}
	return result, nil
}

// ResolveScope also uses CRDs in this render to identify custom cluster-scoped resources.
func ResolveScope(rs []model.Resource) error {
	cluster := map[string]bool{"/Namespace": true, "/Node": true, "/PersistentVolume": true, "rbac.authorization.k8s.io/ClusterRole": true, "rbac.authorization.k8s.io/ClusterRoleBinding": true, "apiextensions.k8s.io/CustomResourceDefinition": true, "storage.k8s.io/StorageClass": true, "admissionregistration.k8s.io/MutatingWebhookConfiguration": true, "admissionregistration.k8s.io/ValidatingWebhookConfiguration": true, "apiregistration.k8s.io/APIService": true, "scheduling.k8s.io/PriorityClass": true}
	for _, r := range rs {
		if r.ID.Kind == "CustomResourceDefinition" {
			spec, _ := r.Object["spec"].(map[string]any)
			names, _ := spec["names"].(map[string]any)
			if spec["scope"] == "Cluster" {
				cluster[fmt.Sprint(spec["group"])+"/"+fmt.Sprint(names["kind"])] = true
			}
		}
	}
	seen := map[model.ID]bool{}
	for i := range rs {
		if cluster[rs[i].ID.Group+"/"+rs[i].ID.Kind] {
			rs[i].ID.Namespace = ""
		}
		if seen[rs[i].ID] {
			return fmt.Errorf("duplicate resource identity: %s", rs[i].ID.String())
		}
		seen[rs[i].ID] = true
	}
	return nil
}
