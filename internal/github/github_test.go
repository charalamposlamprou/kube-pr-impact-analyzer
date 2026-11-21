package github

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/model"
	api "github.com/google/go-github/v93/github"
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
