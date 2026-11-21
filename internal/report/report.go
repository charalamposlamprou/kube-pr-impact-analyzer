// Package report formats redacted semantic reports and validates artifact input.
package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/charalamposlamprou/kube-pr-impact-analyzer/internal/model"
)

const MaxArtifact = 2 << 20
const MaxComment = 60000

func Escape(s string) string {
	s = html.EscapeString(s)
	r := strings.NewReplacer("|", "&#124;", "\n", " ", "\r", " ", "`", "&#96;", "[", "&#91;", "]", "&#93;", "*", "&#42;", "_", "&#95;", "@", "&#64;", "!", "&#33;", "\\", "&#92;")
	return r.Replace(s)
}
func Markdown(r model.Report, runURL string) string {
	var b strings.Builder
	b.WriteString(model.Marker + "\n### Kubernetes Change Impact Report\n\n")
	counts := map[string]int{}
	risk := "none"
	for _, c := range r.Changes {
		counts[c.Action]++
	}
	for _, f := range r.Findings {
		if model.Rank(f.Severity) > model.Rank(risk) {
			risk = f.Severity
		}
	}
	fmt.Fprintf(&b, "**%d added · %d modified · %d deleted** · **Risk level: %s**\n\n", counts["added"], counts["modified"], counts["deleted"], risk)
	if runURL != "" {
		fmt.Fprintf(&b, "[GitHub Actions run](%s)\n\n", runURL)
	}
	if len(r.Changes) == 0 {
		b.WriteString("No semantic Kubernetes configuration changes.\n\n")
	}
	b.WriteString("**Validation and integration checks**\n\n| Check | Result | Detail |\n|---|---|---|\n")
	for _, c := range r.Checks {
		if b.Len() > 12000 {
			b.WriteString("| Additional checks | see artifact | Check details truncated; download report.json. |\n")
			break
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", Escape(c.Name), Escape(c.Status), Escape(c.Detail))
	}
	b.WriteString("\nStatic checks, API dry-run, application and readiness are separate results. kind does not validate production capacity, policies, networking or availability.\n\n")
	for _, c := range r.Changes {
		var section strings.Builder
		fmt.Fprintf(&section, "<details>\n<summary>%s: %s / %s / %s</summary>\n\n**API group:** %s\n\n| Configuration | Before | After | Change |\n|---|---|---|---|\n", Escape(c.Action), Escape(c.Resource.Kind), Escape(c.Resource.Namespace), Escape(c.Resource.Name), Escape(c.Resource.Group))
		for _, f := range c.Fields {
			fmt.Fprintf(&section, "| %s | %s | %s | %s |\n", Escape(label(f.Path)), Escape(f.Before), Escape(f.After), Escape(f.Change))
		}
		section.WriteString("\n**Operational and security impact**\n\n")
		for _, f := range r.Findings {
			if f.Resource == c.Resource {
				fmt.Fprintf(&section, "- **%s** (%s): %s **Recommended action:** %s\n", Escape(f.Severity), Escape(f.Field), Escape(f.Explanation), Escape(f.Recommendation))
			}
		}
		section.WriteString("\n</details>\n\n")
		if b.Len()+section.Len() > MaxComment-1000 {
			b.WriteString("Further detail omitted to stay within GitHub's comment limit. Download the JSON report artifact from the Actions run.\n\n")
			break
		}
		b.WriteString(section.String())
	}
	b.WriteString("Confirmed changes are shown above; operational consequences are possibilities, not proof of an outage. Secret data, literal environment values, ConfigMap values, command arguments and annotations are redacted.\n")
	return b.String()
}
func label(p string) string {
	for _, x := range []struct{ suffix, label string }{{".resources.requests.cpu", "CPU Request"}, {".resources.limits.cpu", "CPU Limit"}, {".resources.requests.memory", "Memory Request"}, {".resources.limits.memory", "Memory Limit"}} {
		if strings.HasSuffix(p, x.suffix) {
			return x.label + " · " + strings.TrimSuffix(p, x.suffix)
		}
	}
	return p
}
func JSON(r model.Report) ([]byte, error) {
	b, e := json.MarshalIndent(r, "", "  ")
	return append(b, '\n'), e
}

// Decode rejects unknown fields, trailing data, oversized or malformed artifacts.
// Artifact strings are always escaped at presentation; no input is executed.
func Decode(data []byte) (model.Report, error) {
	var r model.Report
	if len(data) > MaxArtifact || !utf8.Valid(data) {
		return r, errors.New("report artifact is too large or not UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e := d.Decode(&r); e != nil {
		return r, errors.New("invalid report schema")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return r, errors.New("trailing report data")
	}
	if r.SchemaVersion != model.SchemaVersion || len(r.Changes) > 1000 || len(r.Findings) > 5000 || len(r.Checks) > 2000 {
		return r, errors.New("unsupported or excessive report structure")
	}
	validString := func(s string) bool { return len(s) <= 4096 && !strings.ContainsRune(s, '\x00') }
	idOK := func(id model.ID) bool {
		return validString(id.Group) && validString(id.Kind) && validString(id.Name) && validString(id.Namespace) && id.Kind != "" && id.Name != ""
	}
	for _, c := range r.Changes {
		if !idOK(c.Resource) || len(c.Fields) > 10000 || (c.Action != "added" && c.Action != "modified" && c.Action != "deleted") {
			return r, errors.New("invalid change")
		}
		for _, f := range c.Fields {
			if !validString(f.Path) || !validString(f.Before) || !validString(f.After) || !validString(f.Change) {
				return r, errors.New("invalid field")
			}
		}
	}
	for _, f := range r.Findings {
		if !idOK(f.Resource) || model.Rank(f.Severity) == 0 || !validString(f.Rule) || !validString(f.Field) || !validString(f.Before) || !validString(f.After) || !validString(f.Explanation) || !validString(f.Recommendation) {
			return r, errors.New("invalid finding")
		}
	}
	for _, c := range r.Checks {
		if !validString(c.Name) || !validString(c.Detail) || (c.Status != "passed" && c.Status != "failed" && c.Status != "skipped") {
			return r, errors.New("invalid check")
		}
	}
	return r, nil
}
