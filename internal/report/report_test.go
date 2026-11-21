package report_test

import (
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/model"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/report"
	"strings"
	"testing"
)

func TestEscapingAndExpandableSummary(t *testing.T) {
	r := model.Report{SchemaVersion: 1, Changes: []model.Change{{Action: "modified", Resource: model.ID{Kind: "Deployment", Name: "<img src=x> @everyone"}, Fields: []model.Field{{Path: "x", Before: "[click](https://bad)", After: "|\n<script>"}}}}}
	md := report.Markdown(r, "")
	for _, bad := range []string{"<img", "<script>", "@everyone", "[click]"} {
		if strings.Contains(md, bad) {
			t.Fatalf("unsafe markdown %s", bad)
		}
	}
	if !strings.HasPrefix(md, model.Marker) || !strings.Contains(md, "<details>") {
		t.Fatal("missing report structure")
	}
}
func TestDecodeContract(t *testing.T) {
	for _, s := range []string{`{}`, `{"schemaVersion":1,"extra":1}`, `{"schemaVersion":1,"checks":[{"name":"a","status":"unknown","detail":"a"}]}`, `{"schemaVersion":1} {}`} {
		if _, e := report.Decode([]byte(s)); e == nil {
			t.Fatalf("invalid report accepted: %s", s)
		}
	}
}
func TestCommentBudget(t *testing.T) {
	r := model.Report{SchemaVersion: 1}
	for i := 0; i < 1000; i++ {
		r.Changes = append(r.Changes, model.Change{Action: "added", Resource: model.ID{Kind: "ConfigMap", Name: "test"}, Fields: []model.Field{{Path: "metadata.name", After: strings.Repeat("x", 100)}}})
	}
	md := report.Markdown(r, "")
	if len(md) > report.MaxComment || !strings.Contains(md, "omitted") {
		t.Fatal("unbounded report")
	}
}
