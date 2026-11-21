// Package analyzer coordinates rendering, semantic comparison, policy and validation.
package analyzer

import (
	"context"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/diff"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/model"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/policy"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/renderer"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/validator"
)

type ManifestRenderer interface {
	Render(context.Context, string, []renderer.Target) ([]model.Resource, error)
}
type Analyzer struct{ Renderer ManifestRenderer }

func (a Analyzer) Analyze(ctx context.Context, base, head string, targets []renderer.Target, p policy.Policy) (model.Report, error) {
	r := model.Report{SchemaVersion: model.SchemaVersion, Changes: []model.Change{}, Findings: []model.Finding{}, Checks: []model.Check{}}
	b, e := a.Renderer.Render(ctx, base, targets)
	if e != nil {
		return r, e
	}
	h, e := a.Renderer.Render(ctx, head, targets)
	if e != nil {
		return r, e
	}
	r.Changes = diff.Compare(b, h)
	r.Findings = p.Evaluate(r.Changes, h)
	r.Checks = validator.Static(h)
	return r, nil
}
