// kube-impact analyzes rendered Kubernetes changes without requiring GitHub credentials.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/analyzer"
	gh "github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/github"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/model"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/policy"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/renderer"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/report"
	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/validator"
)

var version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:]))
}
func run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: kube-impact <diff|analyze|validate|report|render|publish|version> [flags]")
		return 1
	}
	if args[0] == "version" {
		fmt.Println(version)
		return 0
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	base := fs.String("base", "", "base manifest directory or revision root")
	head := fs.String("head", "", "head manifest directory or revision root")
	manifests := fs.String("manifests", "", "manifest directory")
	format := fs.String("format", "markdown", "markdown or json")
	output := fs.String("output", "", "output file (default stdout)")
	policyPath := fs.String("policy", "", "policy YAML")
	targetsPath := fs.String("targets", "", "target configuration YAML")
	mode := fs.String("mode", "auto", "auto, yaml, helm or kustomize")
	ns := fs.String("namespace", "default", "default namespace")
	server := fs.Bool("server", false, "also use Kubernetes API server dry-run")
	kubeContext := fs.String("context", "", "explicit kubeconfig context")
	demoGate := fs.Bool("demo-safe", false, "require isolated demo application safety gate")
	checksPath := fs.String("checks", "", "append checks from integration JSON")
	input := fs.String("input", "", "existing JSON report to format")
	runURL := fs.String("run-url", "", "GitHub Actions URL for local Markdown")
	repo := fs.String("repo", "", "owner/repository for publishing")
	runID := fs.Int64("run-id", 0, "completed PR analysis Actions run ID")
	timeout := fs.Duration("timeout", 2*time.Minute, "render and API operation timeout")
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}
	if len(fs.Args()) > 0 {
		return fail(errors.New("unexpected positional arguments"))
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if args[0] == "publish" {
		if *repo == "" || *runID <= 0 {
			return fail(errors.New("publish requires --repo and --run-id"))
		}
		if e := gh.Publish(ctx, *repo, *runID, os.Getenv("GITHUB_TOKEN")); e != nil {
			return fail(e)
		}
		return 0
	}
	if *format != "markdown" && *format != "json" {
		return fail(errors.New("--format must be markdown or json"))
	}
	targets := []renderer.Target{{Path: ".", Mode: *mode, Namespace: *ns}}
	if *targetsPath != "" {
		cfg, e := renderer.LoadConfig(*targetsPath)
		if e != nil {
			return fail(e)
		}
		targets = cfg.Targets
	}
	p, e := policy.Load(*policyPath)
	if e != nil {
		return fail(e)
	}
	r := model.Report{SchemaVersion: model.SchemaVersion, Changes: []model.Change{}, Findings: []model.Finding{}, Checks: []model.Check{}}
	ren := renderer.New()
	switch args[0] {
	case "render", "validate":
		if *manifests == "" {
			return fail(errors.New("--manifests is required"))
		}
		if _, e = os.Stat(*manifests); e != nil {
			return fail(errors.New("manifest input path does not exist"))
		}
		rs, err := ren.Render(ctx, *manifests, targets)
		if err != nil {
			return fail(err)
		}
		if *demoGate {
			if err = validator.DemoSafe(rs); err != nil {
				return failValidation(err)
			}
		}
		if args[0] == "render" {
			if *output == "" {
				return fail(errors.New("render requires --output; rendered files can contain secrets"))
			}
			if e = validator.Write(rs, *output); e != nil {
				return fail(e)
			}
			return 0
		}
		r.Checks = validator.Static(rs)
		if *server {
			r.Checks = append(r.Checks, validator.Server(ctx, rs, *kubeContext))
		}
	case "diff", "analyze", "report":
		if *input != "" {
			b, err := os.ReadFile(*input)
			if err != nil {
				return fail(err)
			}
			r, e = report.Decode(b)
		} else {
			if *base == "" || *head == "" {
				return fail(errors.New("--base and --head are required"))
			}
			for _, path := range []string{*base, *head} {
				if _, err := os.Stat(path); err != nil {
					return fail(errors.New("revision input path does not exist"))
				}
			}
			r, e = (analyzer.Analyzer{Renderer: ren}).Analyze(ctx, *base, *head, targets, p)
		}
		if e != nil {
			return fail(e)
		}
	default:
		return fail(errors.New("unknown command"))
	}
	if *checksPath != "" {
		b, err := os.ReadFile(*checksPath)
		if err != nil {
			return fail(err)
		}
		var cs []model.Check
		if err = json.Unmarshal(b, &cs); err != nil {
			return fail(errors.New("invalid checks JSON"))
		}
		r.Checks = append(r.Checks, cs...)
	}
	var data []byte
	if *format == "json" {
		data, e = report.JSON(r)
	} else {
		if *runURL != "" && !strings.HasPrefix(*runURL, "https://github.com/") {
			return fail(errors.New("--run-url must use https://github.com/"))
		}
		data = []byte(report.Markdown(r, *runURL))
	}
	if e != nil {
		return fail(e)
	}
	if *output == "" {
		_, e = os.Stdout.Write(data)
	} else {
		e = os.MkdirAll(filepath.Dir(*output), 0755)
		if e == nil {
			e = os.WriteFile(*output, data, 0600)
		}
	}
	if e != nil {
		return fail(e)
	}
	if validator.ValidationFailed(r.Checks) {
		return 2
	}
	if args[0] == "analyze" && p.Violated(r.Findings) {
		return 3
	}
	return 0
}
func fail(e error) int           { slog.Error("operation failed", "error", e.Error()); return 1 }
func failValidation(e error) int { slog.Error("validation failed", "error", e.Error()); return 2 }
