// Package github publishes one report per PR using the maintained go-github client.
// The publisher consumes data only and never executes or checks out artifact code.
package github

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/model"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/report"
	api "github.com/google/go-github/v93/github"
)

const WorkflowPath = ".github/workflows/pr-analysis.yml"
const ArtifactName = "kube-impact-report"

type Comments interface {
	ListComments(context.Context, string, string, int, *api.IssueListCommentsOptions) ([]*api.IssueComment, *api.Response, error)
	CreateComment(context.Context, string, string, int, api.IssueCommentRequest) (*api.IssueComment, *api.Response, error)
	UpdateComment(context.Context, string, string, int64, api.IssueCommentRequest) (*api.IssueComment, *api.Response, error)
}

// Upsert recognizes only github-actions[bot] comments, not attacker-authored markers.
// Workflow concurrency serializes publishers for the repository.
func Upsert(ctx context.Context, c Comments, owner, repo string, pr int, body string) error {
	if !strings.HasPrefix(body, model.Marker) || len(body) > report.MaxComment {
		return errors.New("invalid comment body")
	}
	opts := &api.IssueListCommentsOptions{ListOptions: api.ListOptions{PerPage: 100}}
	for {
		comments, resp, e := c.ListComments(ctx, owner, repo, pr, opts)
		if e != nil {
			return errors.New("cannot list PR comments")
		}
		for _, comment := range comments {
			if comment.GetUser().GetLogin() == "github-actions[bot]" && comment.GetUser().GetType() == "Bot" && strings.HasPrefix(comment.GetBody(), model.Marker) {
				if comment.GetBody() == body {
					return nil
				}
				_, _, e = c.UpdateComment(ctx, owner, repo, comment.GetID(), api.IssueCommentRequest{Body: body})
				if e != nil {
					return errors.New("cannot update PR report")
				}
				return nil
			}
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	_, _, e := c.CreateComment(ctx, owner, repo, pr, api.IssueCommentRequest{Body: body})
	if e != nil {
		return errors.New("cannot create PR report")
	}
	return nil
}
func Extract(data []byte) (model.Report, error) {
	var empty model.Report
	if len(data) > report.MaxArtifact {
		return empty, errors.New("compressed artifact exceeds size limit")
	}
	z, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if e != nil || len(z.File) != 1 {
		return empty, errors.New("artifact must contain exactly one report.json")
	}
	f := z.File[0]
	if f.Name != "report.json" || f.FileInfo().IsDir() || !f.Mode().IsRegular() || f.UncompressedSize64 > report.MaxArtifact {
		return empty, errors.New("invalid artifact file")
	}
	rd, e := f.Open()
	if e != nil {
		return empty, errors.New("cannot open artifact")
	}
	defer rd.Close()
	b, e := io.ReadAll(io.LimitReader(rd, report.MaxArtifact+1))
	if e != nil {
		return empty, errors.New("cannot read artifact")
	}
	return report.Decode(b)
}
func Publish(ctx context.Context, repository string, runID int64, token string) error {
	parts := strings.Split(repository, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || token == "" {
		return errors.New("publish requires owner/repo and GITHUB_TOKEN")
	}
	owner, repo := parts[0], parts[1]
	client, clientErr := api.NewClient(api.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}), api.WithAuthToken(token))
	if clientErr != nil {
		return errors.New("cannot initialize GitHub client")
	}
	run, _, e := client.Actions.GetWorkflowRunByID(ctx, owner, repo, runID)
	if e != nil {
		return errors.New("cannot read analysis workflow run")
	}
	if run.GetEvent() != "pull_request" || run.GetPath() != WorkflowPath || run.GetStatus() != "completed" || run.GetRepository().GetFullName() != repository {
		return errors.New("run is not a completed PR analysis for this repository")
	}
	prs := run.PullRequests
	// Fork workflow_run payloads can omit pull_requests. Resolve by commit via API.
	if len(prs) == 0 {
		prs, _, e = client.PullRequests.ListPullRequestsWithCommit(ctx, owner, repo, run.GetHeadSHA(), &api.ListOptions{PerPage: 100})
		if e != nil {
			return errors.New("cannot resolve pull request from workflow commit")
		}
	}
	var selected *api.PullRequest
	for _, candidate := range prs {
		pr, _, err := client.PullRequests.Get(ctx, owner, repo, candidate.GetNumber())
		if err != nil {
			return errors.New("cannot read pull request")
		}
		if pr.GetState() == "open" && pr.GetBase().GetRepo().GetFullName() == repository && pr.GetHead().GetSHA() == run.GetHeadSHA() && pr.GetHead().GetRepo().GetID() == run.GetHeadRepository().GetID() {
			if selected != nil {
				return errors.New("ambiguous pull request association")
			}
			selected = pr
		}
	}
	if selected == nil {
		return nil
	} // stale run, closed PR, or unrelated head: do not overwrite newer reports.
	r := model.Report{SchemaVersion: 1, Changes: []model.Change{}, Findings: []model.Finding{}, Checks: []model.Check{{Name: "Analysis artifact", Status: "failed", Detail: "A valid report artifact was not available; inspect the linked Actions run."}}}
	artifacts, _, err := client.Actions.ListWorkflowRunArtifacts(ctx, owner, repo, runID, &api.ListOptions{PerPage: 100})
	if err != nil {
		return errors.New("cannot list report artifacts")
	}
	var artifactID int64
	for _, a := range artifacts.Artifacts {
		if a.GetName() == ArtifactName && !a.GetExpired() {
			if artifactID != 0 {
				return errors.New("duplicate report artifacts")
			}
			if a.GetSizeInBytes() > report.MaxArtifact {
				return errors.New("report artifact exceeds size limit")
			}
			artifactID = a.GetID()
		}
	}
	if artifactID != 0 {
		url, _, err := client.Actions.DownloadArtifact(ctx, owner, repo, artifactID, 5)
		if err != nil {
			return errors.New("cannot obtain report artifact")
		}
		if url.Scheme != "https" {
			return errors.New("artifact download requires HTTPS")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
		if err != nil {
			return errors.New("invalid artifact URL")
		}
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if err != nil {
			return errors.New("artifact download failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return errors.New("artifact download failed")
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, report.MaxArtifact+1))
		if err != nil {
			return errors.New("cannot read artifact")
		}
		parsed, err := Extract(data)
		if err == nil {
			r = parsed
		} else {
			r.Checks[0].Detail = "Artifact rejected by schema and size validation; inspect the Actions run."
		}
	}
	status := "failed"
	if run.GetConclusion() == "success" {
		status = "passed"
	}
	r.Checks = append(r.Checks, model.Check{Name: "GitHub workflow conclusion", Status: status, Detail: "Verified via GitHub API. Report contents are produced in the unprivileged PR analysis job."})
	runURL := fmt.Sprintf("https://github.com/%s/actions/runs/%d", repository, runID)
	body := report.Markdown(r, runURL)
	// Re-read immediately before writing to reduce stale-run races.
	latest, _, err := client.PullRequests.Get(ctx, owner, repo, selected.GetNumber())
	if err != nil {
		return errors.New("cannot recheck PR head")
	}
	if latest.GetHead().GetSHA() != run.GetHeadSHA() || latest.GetState() != "open" {
		return nil
	}
	return Upsert(ctx, client.Issues, owner, repo, selected.GetNumber(), body)
}
