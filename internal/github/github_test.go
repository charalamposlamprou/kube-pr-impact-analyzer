package github

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/model"
	api "github.com/google/go-github/v93/github"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeComments struct {
	comments         []*api.IssueComment
	creates, updates int
	err              bool
	pages            bool
}

func (f *fakeComments) ListComments(_ context.Context, _, _ string, _ int, o *api.IssueListCommentsOptions) ([]*api.IssueComment, *api.Response, error) {
	if f.err {
		return nil, nil, errors.New("network")
	}
	if f.pages && o.Page == 0 {
		return nil, &api.Response{NextPage: 2}, nil
	}
	return f.comments, &api.Response{}, nil
}
func (f *fakeComments) CreateComment(_ context.Context, _, _ string, _ int, c api.IssueCommentRequest) (*api.IssueComment, *api.Response, error) {
	f.creates++
	comment := &api.IssueComment{ID: new(int64(1)), Body: new(c.Body), User: &api.User{Login: new("github-actions[bot]"), Type: new("Bot")}}
	f.comments = append(f.comments, comment)
	return comment, nil, nil
}
func (f *fakeComments) UpdateComment(_ context.Context, _, _ string, id int64, c api.IssueCommentRequest) (*api.IssueComment, *api.Response, error) {
	f.updates++
	for _, comment := range f.comments {
		if comment.GetID() == id {
			comment.Body = new(c.Body)
			return comment, nil, nil
		}
	}
	return nil, nil, errors.New("missing")
}
func TestCommentIdempotency(t *testing.T) {
	ctx := context.Background()
	f := &fakeComments{}
	a := model.Marker + "\nreport one"
	b := model.Marker + "\nreport two"
	for _, body := range []string{a, a, b, b} {
		if e := Upsert(ctx, f, "owner", "repo", 1, body); e != nil {
			t.Fatal(e)
		}
	}
	if f.creates != 1 || f.updates != 1 || len(f.comments) != 1 {
		t.Fatalf("duplicates: %+v", f)
	}
}
func TestUserMarkerCannotHijackComment(t *testing.T) {
	f := &fakeComments{pages: true, comments: []*api.IssueComment{{ID: new(int64(9)), Body: new(model.Marker), User: &api.User{Login: new("attacker"), Type: new("User")}}}}
	if e := Upsert(context.Background(), f, "o", "r", 1, model.Marker+" report"); e != nil {
		t.Fatal(e)
	}
	if f.creates != 1 || f.updates != 0 {
		t.Fatal("edited attacker comment")
	}
}
func TestCommentErrors(t *testing.T) {
	if e := Upsert(context.Background(), &fakeComments{err: true}, "o", "r", 1, model.Marker); e == nil {
		t.Fatal("expected error")
	}
	if e := Upsert(context.Background(), &fakeComments{}, "o", "r", 1, "unmarked"); e == nil {
		t.Fatal("unmarked accepted")
	}
}
func archive(t *testing.T, name, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, e := w.Create(name)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = f.Write([]byte(body))
	_ = w.Close()
	return b.Bytes()
}
func TestArtifactValidation(t *testing.T) {
	valid := `{"schemaVersion":1,"changes":[],"findings":[],"checks":[]}`
	if _, e := Extract(archive(t, "report.json", valid)); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ name, body string }{{"../report.json", valid}, {"report.json", `{"schemaVersion":2}`}, {"report.json", `{"schemaVersion":1,"code":"evil"}`}, {"report.json", valid + valid}} {
		if _, e := Extract(archive(t, tc.name, tc.body)); e == nil {
			t.Fatal("accepted invalid artifact")
		}
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestPublisherProvenanceAndFallbacks(t *testing.T) {
	for _, tc := range []struct {
		name, event, path, head, artifact string
		fallback, moveHead, missing       bool
		wantPosts                         int
		wantErr                           bool
	}{{name: "valid", wantPosts: 1}, {name: "fork association fallback", fallback: true, wantPosts: 1}, {name: "stale", head: "old", wantPosts: 0}, {name: "head moves before post", moveHead: true, wantPosts: 0}, {name: "wrong trigger", event: "push", wantErr: true}, {name: "wrong workflow", path: "evil.yml", wantErr: true}, {name: "missing artifact", missing: true, wantPosts: 1}, {name: "poisoned artifact", artifact: `{"schemaVersion":1,"script":"evil"}`, wantPosts: 1}} {
		t.Run(tc.name, func(t *testing.T) {
			posts, reads := 0, 0
			body := ""
			event, path, head := tc.event, tc.path, tc.head
			if event == "" {
				event = "pull_request"
			}
			if path == "" {
				path = WorkflowPath
			}
			if head == "" {
				head = "current"
			}
			runPRs := []map[string]any{{"number": 1}}
			if tc.fallback {
				runPRs = nil
			}
			mux := http.NewServeMux()
			mux.HandleFunc("/repos/o/r/actions/runs/42", func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "event": event, "path": path, "status": "completed", "conclusion": "success", "head_sha": head, "repository": map[string]any{"full_name": "o/r"}, "head_repository": map[string]any{"id": 7}, "pull_requests": runPRs})
			})
			mux.HandleFunc("/repos/o/r/commits/current/pulls", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `[{"number":1}]`) })
			mux.HandleFunc("/repos/o/r/pulls/1", func(w http.ResponseWriter, r *http.Request) {
				reads++
				sha := "current"
				if tc.moveHead && reads > 1 {
					sha = "newer"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"number": 1, "state": "open", "head": map[string]any{"sha": sha, "repo": map[string]any{"id": 7}}, "base": map[string]any{"repo": map[string]any{"full_name": "o/r"}}})
			})
			mux.HandleFunc("/repos/o/r/actions/runs/42/artifacts", func(w http.ResponseWriter, r *http.Request) {
				if tc.missing {
					_, _ = io.WriteString(w, `{"total_count":0,"artifacts":[]}`)
					return
				}
				_, _ = io.WriteString(w, `{"total_count":1,"artifacts":[{"id":2,"name":"kube-impact-report","size_in_bytes":200,"expired":false}]}`)
			})
			mux.HandleFunc("/repos/o/r/actions/artifacts/2/zip", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://artifacts.invalid/report.zip", http.StatusFound)
			})
			mux.HandleFunc("/repos/o/r/issues/1/comments", func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts++
					var c api.IssueCommentRequest
					_ = json.NewDecoder(r.Body).Decode(&c)
					body = c.Body
					_, _ = io.WriteString(w, `{"id":10}`)
				} else {
					_, _ = io.WriteString(w, `[]`)
				}
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()
			base := srv.URL + "/"
			client, e := api.NewClient(api.WithURLs(&base, nil))
			if e != nil {
				t.Fatal(e)
			}
			artifact := tc.artifact
			if artifact == "" {
				artifact = `{"schemaVersion":1,"changes":[],"findings":[],"checks":[]}`
			}
			payload := archive(t, "report.json", artifact)
			download := &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("Authorization") != "" {
					t.Error("credential sent to artifact host")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(payload)), Request: r}, nil
			})}
			e = publish(context.Background(), "o/r", 42, client, download)
			if (e != nil) != tc.wantErr || posts != tc.wantPosts {
				t.Fatalf("error=%v posts=%d", e, posts)
			}
			if posts > 0 {
				if !strings.Contains(body, "https://github.com/o/r/actions/runs/42") {
					t.Fatal("missing verified link")
				}
				if (tc.missing || tc.artifact != "") && !strings.Contains(body, "failed") {
					t.Fatal("missing artifact wrongly passed")
				}
			}
		})
	}
}
