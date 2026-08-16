package render

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Beeeeen/krinos/internal/model"
	"github.com/Beeeeen/krinos/internal/policy"
	"github.com/Beeeeen/krinos/internal/triage"
)

// GitHub renders a report as native GitHub Actions integration.
//
// This mode does three things at once, because a developer opening a pull
// request looks in three places and we would rather be in all of them than
// hope they scroll the build log:
//
//   - inline annotations on the changed lines, so a finding appears next to
//     the code that caused it;
//   - a job summary, so the funnel and the ranked list are on the run page;
//   - step outputs, so the surrounding workflow can branch on the counts
//     without anyone having to shell out to jq.
//
// Writing to GitHub's environment files is not a side effect to hide: the
// mode is called "github", and doing all of its integration is what it
// promises.
type GitHub struct {
	// SummaryPath is $GITHUB_STEP_SUMMARY. Empty disables the summary.
	SummaryPath string
	// OutputPath is $GITHUB_OUTPUT. Empty disables step outputs.
	OutputPath string
	// Annotate emits inline annotations. Disable it when a run would bury
	// the diff — GitHub caps annotations at ten per level per step anyway.
	Annotate bool
	// AnnotateWatch also annotates watch-level findings as warnings.
	AnnotateWatch bool
	// Limit caps the findings included in the job summary.
	Limit int
}

// Render writes annotations to w and, when configured, the summary and
// outputs to their respective files.
//
// A failure to write the summary or the outputs is reported but does not
// abort: the annotations are the part the developer sees, and losing the
// summary is not a reason to fail someone's build.
func (g GitHub) Render(w io.Writer, r triage.Report, intake map[string]int, gate policy.Decision, version string) error {
	if g.Annotate {
		g.writeAnnotations(w, r)
	}

	var firstErr error

	if g.SummaryPath != "" {
		md := Markdown{Limit: g.Limit, ShowWatch: true}
		if err := appendToFile(g.SummaryPath, func(f io.Writer) error {
			return md.Render(f, r, intake, gate, version)
		}); err != nil {
			fmt.Fprintf(w, "::warning title=Krinos::could not write the job summary: %s\n", escapeData(err.Error()))
			firstErr = err
		}
	}

	if g.OutputPath != "" {
		if err := g.writeOutputs(r, gate); err != nil {
			fmt.Fprintf(w, "::warning title=Krinos::could not write step outputs: %s\n", escapeData(err.Error()))
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	return firstErr
}

// writeAnnotations emits one workflow command per finding.
//
// Suppressed findings are never annotated. An annotation is a claim on a
// reviewer's attention, and spending it on something we have already decided
// is harmless is how a tool gets muted.
func (g GitHub) writeAnnotations(w io.Writer, r triage.Report) {
	for _, res := range r.Results {
		var level string
		switch res.Verdict {
		case triage.VerdictAct:
			level = "error"
		case triage.VerdictWatch:
			if !g.AnnotateWatch {
				continue
			}
			level = "warning"
		default:
			continue
		}

		f := res.Finding
		ident := f.PrimaryCVE()
		if ident == "" {
			ident = f.RuleID
		}

		title := fmt.Sprintf("Krinos %s (%.0f) · %s",
			strings.ToUpper(string(res.Verdict)), res.Score, ident)

		message := f.Title
		if f.Package != nil && f.Package.Name != "" {
			message = fmt.Sprintf("%s@%s — %s", f.Package.Name, f.Package.Version, f.Title)
		}
		// The evidence is why this is on the reviewer's screen at all, so it
		// belongs in the annotation rather than only in the log.
		for _, ev := range res.Evidence {
			message += "\n· " + ev.Reason
		}
		if f.Package != nil && f.Package.FixedIn != "" {
			message += "\n→ fix: upgrade " + f.Package.Name + " to " + f.Package.FixedIn
		}

		props := []string{"title=" + escapeProperty(title)}
		if path := model.NormalizePath(f.Location.Path); path != "" {
			props = append(props, "file="+escapeProperty(path))
			if f.Location.StartLine > 0 {
				props = append(props, fmt.Sprintf("line=%d", f.Location.StartLine))
				if f.Location.EndLine >= f.Location.StartLine {
					props = append(props, fmt.Sprintf("endLine=%d", f.Location.EndLine))
				}
			}
		}

		fmt.Fprintf(w, "::%s %s::%s\n", level, strings.Join(props, ","), escapeData(message))
	}
}

// writeOutputs appends step outputs in GitHub's key=value format.
func (g GitHub) writeOutputs(r triage.Report, gate policy.Decision) error {
	return appendToFile(g.OutputPath, func(f io.Writer) error {
		_, err := fmt.Fprintf(f,
			"ingested=%d\nunique=%d\nduplicates=%d\nact=%d\nwatch=%d\nsuppressed=%d\nreduction=%.1f\npassed=%t\n",
			r.Funnel.Ingested, r.Funnel.Unique, r.Funnel.Duplicates,
			r.Funnel.Act, r.Funnel.Watch, r.Funnel.Suppressed,
			r.Funnel.Reduction()*100, gate.Pass)
		return err
	})
}

// appendToFile opens path for appending and hands the writer to fn.
//
// Append, never truncate: GitHub's summary and output files are shared by
// every step in the job, and clobbering them would silently delete another
// action's work.
func appendToFile(path string, fn func(io.Writer) error) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := fn(f); err != nil {
		return err
	}
	return f.Close()
}

// escapeData escapes a workflow command's message body.
//
// Unescaped, a finding whose description contains a newline would terminate
// the command early and dump the rest into the log as plain text — and a
// description containing "::" could forge a command of its own. Scanner
// output is untrusted input; this is the boundary that treats it that way.
func escapeData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

// escapeProperty escapes a workflow command property value, which
// additionally may not contain the separators GitHub parses.
func escapeProperty(s string) string {
	s = escapeData(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return s
}
