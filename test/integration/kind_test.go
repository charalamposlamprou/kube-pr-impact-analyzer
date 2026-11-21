//go:build integration

package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
)

func kubectl(t *testing.T, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	all := append([]string{"--context", os.Getenv("KUBE_IMPACT_CONTEXT"), "-n", "impact-demo"}, args...)
	b, e := exec.CommandContext(ctx, "kubectl", all...).Output()
	if e != nil {
		t.Fatalf("kubectl failed (output suppressed): %v", e)
	}
	return b
}
func TestLiveDemo(t *testing.T) {
	if os.Getenv("KUBE_IMPACT_CONTEXT") == "" || os.Getenv("KUBE_IMPACT_EXPECTED") == "" {
		t.Fatal("run scripts/kind-test.sh to create an isolated cluster first")
	}
	type container struct {
		Image     string `json:"image"`
		Resources struct {
			Requests map[string]string `json:"requests"`
			Limits   map[string]string `json:"limits"`
		} `json:"resources"`
	}
	type deploy struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Replicas int `json:"replicas"`
			Template struct {
				Spec struct {
					Containers []container `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
		Status struct {
			Available int `json:"availableReplicas"`
			Updated   int `json:"updatedReplicas"`
		} `json:"status"`
	}
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	raw, e := os.ReadFile(os.Getenv("KUBE_IMPACT_EXPECTED"))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &list); e != nil {
		t.Fatal(e)
	}
	var expected deploy
	for _, item := range list.Items {
		var d deploy
		_ = json.Unmarshal(item, &d)
		if d.Kind == "Deployment" && d.Metadata.Name == "payment-api" {
			expected = d
		}
	}
	var live deploy
	if e = json.Unmarshal(kubectl(t, "get", "deployment/payment-api", "-o", "json"), &live); e != nil {
		t.Fatal(e)
	}
	if expected.Spec.Replicas < 1 || live.Status.Available != expected.Spec.Replicas || live.Status.Updated != expected.Spec.Replicas {
		t.Fatalf("readiness mismatch: available %d, expected %d", live.Status.Available, expected.Spec.Replicas)
	}
	got, want := live.Spec.Template.Spec.Containers, expected.Spec.Template.Spec.Containers
	if len(got) != 1 || len(want) != 1 || got[0].Image != want[0].Image {
		t.Fatal("image differs from proposed manifest")
	}
	for _, key := range []string{"cpu", "memory"} {
		for _, pair := range [][2]string{{got[0].Resources.Requests[key], want[0].Resources.Requests[key]}, {got[0].Resources.Limits[key], want[0].Resources.Limits[key]}} {
			a, e1 := resource.ParseQuantity(pair[0])
			b, e2 := resource.ParseQuantity(pair[1])
			if e1 != nil || e2 != nil || a.Cmp(b) != 0 {
				t.Fatal("resource allocation differs from proposal")
			}
		}
	}
	var endpoints struct {
		Items []struct {
			Endpoints []struct {
				Conditions struct {
					Ready *bool `json:"ready"`
				} `json:"conditions"`
			} `json:"endpoints"`
		} `json:"items"`
	}
	if e = json.Unmarshal(kubectl(t, "get", "endpointslices", "-l", "kubernetes.io/service-name=payment-api", "-o", "json"), &endpoints); e != nil {
		t.Fatal(e)
	}
	ready := 0
	for _, slice := range endpoints.Items {
		for _, ep := range slice.Endpoints {
			if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
				ready++
			}
		}
	}
	if ready != expected.Spec.Replicas {
		t.Fatalf("ready Service endpoints: got %d want %d", ready, expected.Spec.Replicas)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", "--context", os.Getenv("KUBE_IMPACT_CONTEXT"), "-n", "impact-demo", "port-forward", "--address=127.0.0.1", "service/payment-api", "0:80")
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	scan := bufio.NewScanner(stdout)
	re := regexp.MustCompile(`127\.0\.0\.1:(\d+)`)
	port := ""
	for scan.Scan() {
		if m := re.FindStringSubmatch(scan.Text()); len(m) == 2 {
			port = m[1]
			break
		}
	}
	if port == "" {
		t.Fatal("port forward did not become ready")
	}
	client := http.Client{Timeout: 5 * time.Second}
	for _, path := range []string{"/healthz", "/readyz", "/"} {
		resp, e := client.Get(fmt.Sprintf("http://127.0.0.1:%s%s", port, path))
		if e != nil {
			t.Fatal(e)
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatal("HTTP health check failed")
		}
		if path == "/" && !strings.Contains(string(b), "kube-impact-demo") {
			t.Fatal("unexpected application response")
		}
	}
}
