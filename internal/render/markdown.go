package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Beeeeen/krinos/internal/model"
	"github.com/Beeeeen/krinos/internal/policy"
	"github.com/Beeeeen/krinos/internal/triage"
)

// Markdown renders a report for a pull request comment or a CI job summary.
//
// The audience is different from the terminal renderer's: someone glancing at
// a PR who has not read the build log and will not scroll. So the verdict
// comes first, the evidence is collapsed behind a disclosure, and nothing
// requires horizontal scrolling on a phone.
type Markdown struct {
	// Limit caps how many findings appear per section. Zero means all.
	Limit int
	// ShowWatch includes the watch list.
	ShowWatch bool
}

// Render writes the markdown report.
func (m Markdown) Render(w io.Writer, r triage.Report, intake map[string]int, gate policy.Decision, version string) error {
	var b strings.Builder

	m.writeHeadline(&b, r, gate)
	m.writeFunnel(&b, r.Funnel, intake)
	m.writeSection(&b, r, triage.VerdictAct, "Act now")
	if m.ShowWatch {
		m.writeSection(&b, r, triage.VerdictWatch, "Worth tracking")
	}
	m.writeSuppressedNote(&b, r)

	fmt.Fprintf(&b, "\n<sub>krinos %s · <a href=\"https://github.com/Beeeeen/krinos\">what is this?</a></sub>\n", version)

	_, err := io.WriteString(w, b.String())
	return err
}

func (m Markdown) writeHeadline(b *strings.Builder, r triage.Report, gate policy.Decision) {
	switch {
	case r.Funnel.Act == 0:
		b.WriteString("## Krinos — nothing needs action\n\n")
		b.WriteString("Every finding your scanners reported has evidence against it. ")
		b.WriteString("Details below.\n\n")
	case r.Funnel.Act == 1:
		b.WriteString("## Krinos — 1 finding needs action\n\n")
	default:
		fmt.Fprintf(b, "## Krinos — %s findings need action\n\n", comma(r.Funnel.Act))
	}

	if gate.Pass {
		fmt.Fprintf(b, "**Gate passed** — %s\n\n", gate.Summary)
	} else {
		fmt.Fprintf(b, "**Gate failed** — %s\n\n", gate.Summary)
	}
}

func (m Markdown) writeFunnel(b *strings.Builder, f triage.Funnel, intake map[string]int) {
	fmt.Fprintf(b, "`%s`  **%.1f%%** of what your scanners reported needs no action today.\n\n",
		markdownBar(f.Reduction()), f.Reduction()*100)

	b.WriteString("| | |\n|---|--:|\n")
	fmt.Fprintf(b, "| Reported by scanners | %s |\n", comma(f.Ingested))
	fmt.Fprintf(b, "| Unique after dedup | %s |\n", comma(f.Unique))
	fmt.Fprintf(b, "| **Needs action** | **%s** |\n", comma(f.Act))
	fmt.Fprintf(b, "| Worth tracking | %s |\n", comma(f.Watch))
	fmt.Fprintf(b, "| Suppressed with reasons | %s |\n", comma(f.Suppressed))
	b.WriteString("\n")

	if len(intake) == 0 {
		return
	}
	names := make([]string, 0, len(intake))
	for n := range intake {
		names = append(names, n)
	}
	sort.Strings(names)

	b.WriteString("<details><summary>What each scanner contributed</summary>\n\n")
	b.WriteString("| Scanner | Findings |\n|---|--:|\n")
	for _, n := range names {
		fmt.Fprintf(b, "| `%s` | %s |\n", n, comma(intake[n]))
	}
	b.WriteString("\n</details>\n\n")
}

func (m Markdown) writeSection(b *strings.Builder, r triage.Report, verdict triage.Verdict, title string) {
	var rows []triage.Result
	for _, res := range r.Results {
		if res.Verdict == verdict {
			rows = append(rows, res)
		}
	}
	if len(rows) == 0 {
		return
	}

	shown := rows
	if m.Limit > 0 && len(shown) > m.Limit {
		shown = shown[:m.Limit]
	}

	fmt.Fprintf(b, "### %s — %s\n\n", title, comma(len(rows)))
	b.WriteString("| | Score | Finding | Location |\n|---|--:|---|---|\n")

	for _, res := range shown {
		f := res.Finding
		ident := f.PrimaryCVE()
		if ident == "" {
			ident = f.RuleID
		}

		subject := escapePipes(f.Title)
		if f.Package != nil && f.Package.Name != "" {
			subject = fmt.Sprintf("`%s@%s` %s",
				escapePipes(f.Package.Name), escapePipes(f.Package.Version), subject)
		}

		loc := "—"
		if l := locationLine(f); l != "" {
			loc = "`" + escapePipes(l) + "`"
		}

		fmt.Fprintf(b, "| %s | %.0f | **%s**<br>%s | %s |\n",
			strings.ToUpper(string(f.Severity)),
			res.Score,
			escapePipes(ident),
			truncate(subject, 90),
			loc)
	}
	if len(shown) < len(rows) {
		fmt.Fprintf(b, "\n_… and %s more._\n", comma(len(rows)-len(shown)))
	}
	b.WriteString("\n")

	// Evidence lives behind a disclosure: the table answers "what", and
	// anyone who wants "why" is one click away rather than three screens
	// down.
	b.WriteString("<details><summary>Why these verdicts</summary>\n\n")
	for _, res := range shown {
		f := res.Finding
		ident := f.PrimaryCVE()
		if ident == "" {
			ident = f.RuleID
		}
		fmt.Fprintf(b, "**%s** — score %.0f\n\n", escapePipes(ident), res.Score)
		if len(res.Evidence) == 0 {
			fmt.Fprintf(b, "- No evidence layer had an opinion; the verdict is the scanner's severity alone.\n")
		}
		for _, ev := range res.Evidence {
			mark := "·"
			if ev.Method.Proven() {
				mark = "✔"
			}
			fmt.Fprintf(b, "- %s `%s` — %s\n", mark, ev.Method, ev.Reason)
		}
		if f.Package != nil && f.Package.FixedIn != "" {
			fmt.Fprintf(b, "- → **fix:** upgrade `%s` to `%s`\n", f.Package.Name, f.Package.FixedIn)
		}
		if len(f.Scanners) > 1 {
			fmt.Fprintf(b, "- confirmed by %s\n", strings.Join(f.Scanners, ", "))
		}
		b.WriteString("\n")
	}
	b.WriteString("</details>\n\n")
}

func (m Markdown) writeSuppressedNote(b *strings.Builder, r triage.Report) {
	if r.Funnel.Suppressed == 0 {
		return
	}
	fmt.Fprintf(b,
		"> %s findings were suppressed, each with a recorded reason. Nothing is discarded — run `krinos scan --show suppressed` to audit every one.\n\n",
		comma(r.Funnel.Suppressed))
}

// markdownBar draws the reduction proportion using block characters, which
// render identically in GitHub summaries, PR comments and most chat clients.
func markdownBar(fraction float64) string {
	const cells = 28
	quiet := int(float64(cells) * fraction)
	if quiet > cells {
		quiet = cells
	}
	if quiet < 0 {
		quiet = 0
	}
	return strings.Repeat("░", quiet) + strings.Repeat("█", cells-quiet)
}

// escapePipes keeps scanner-supplied text from breaking out of a markdown
// table. Rule descriptions routinely contain pipes and newlines, and a
// finding that mangles the report is a finding nobody reads.
func escapePipes(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// locationLine is shared with the terminal renderer.
var _ = model.NormalizePath
