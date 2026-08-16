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

const width = 74

// Terminal renders a triage report for a human reading a build log.
//
// The layout answers three questions in order, because that is the order a
// developer asks them: how much noise did you remove, what must I fix, and
// why did you decide that. Anything that does not serve one of those three
// questions does not get printed.
type Terminal struct {
	Style Style
	// ShowWatch includes the watch list in full rather than as a count.
	ShowWatch bool
	// ShowSuppressed includes suppressed findings, so a user can always
	// audit what we dismissed on their behalf.
	ShowSuppressed bool
	// Limit caps how many findings are printed per section. Zero means all.
	Limit int
}

// Render writes the whole report.
func (t Terminal) Render(w io.Writer, r triage.Report, intake map[string]int, gate policy.Decision, version string) {
	s := t.Style

	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s %s\n", s.bold(s.fg(colSignal, "krinos")), s.faint(version))
	fmt.Fprintln(w)

	t.renderIntake(w, intake)
	t.renderFunnel(w, r.Funnel)
	t.renderSection(w, r, triage.VerdictAct)

	if t.ShowWatch {
		t.renderSection(w, r, triage.VerdictWatch)
	} else if r.Funnel.Watch > 0 {
		t.note(w, fmt.Sprintf("%s findings are worth tracking but do not gate the build. Show them with --show watch.",
			s.bold(comma(r.Funnel.Watch))))
	}

	if t.ShowSuppressed {
		t.renderSection(w, r, triage.VerdictSuppress)
	} else if r.Funnel.Suppressed > 0 {
		t.note(w, fmt.Sprintf("%s findings were suppressed with reasons. Audit them with --show suppressed.",
			s.bold(comma(r.Funnel.Suppressed))))
	}

	t.renderGate(w, gate)
	fmt.Fprintln(w)
}

// renderGate states the build outcome in one unambiguous line.
//
// It is the last thing printed because it is the only line a CI log reader
// scrolling to the bottom will actually see, and it must answer "am I
// blocked?" without them reading anything above it.
func (t Terminal) renderGate(w io.Writer, gate policy.Decision) {
	s := t.Style
	fmt.Fprintln(w)

	if gate.Pass {
		fmt.Fprintf(w, "  %s  %s\n",
			s.chip(colOK, "PASS"),
			s.dim(gate.Summary))
		return
	}
	fmt.Fprintf(w, "  %s  %s\n",
		s.chip(colCritical, "FAIL"),
		s.bold(gate.Summary))
}

// renderIntake shows what each scanner contributed, which is how a user
// confirms we actually read the file they meant.
func (t Terminal) renderIntake(w io.Writer, intake map[string]int) {
	if len(intake) == 0 {
		return
	}
	s := t.Style
	t.heading(w, "INTAKE")

	names := make([]string, 0, len(intake))
	total := 0
	for name, n := range intake {
		names = append(names, name)
		total += n
	}
	sort.Strings(names)

	for _, name := range names {
		fmt.Fprintf(w, "    %s %s\n",
			s.dim(pad(name, 14)),
			padLeft(comma(intake[name]), 7))
	}
	fmt.Fprintf(w, "    %s %s\n",
		strings.Repeat(" ", 14),
		s.faint(strings.Repeat(s.rule(), 7)))
	fmt.Fprintf(w, "    %s %s %s\n\n",
		strings.Repeat(" ", 14),
		s.bold(padLeft(comma(total), 7)),
		s.dim("reported"))
}

// renderFunnel is the money shot: the reduction, stated plainly.
func (t Terminal) renderFunnel(w io.Writer, f triage.Funnel) {
	s := t.Style
	t.heading(w, "TRIAGE")

	fmt.Fprintf(w, "    %s %s  %s %s  %s %s\n",
		s.bold(comma(f.Ingested)), s.dim("reported"),
		s.faint(s.arrow()),
		s.bold(comma(f.Unique))+" "+s.dim("unique"),
		s.faint(s.arrow()),
		s.bold(s.fg(colSignal, comma(f.Act)))+" "+s.fg(colSignal, "to act on"))

	fmt.Fprintln(w)
	t.renderBar(w, f)
	fmt.Fprintln(w)
}

// renderBar draws the suppressed/act proportion. The bar is deliberately
// mostly "empty": the visual claim is that almost none of the backlog needed
// a human, and the shape should say that before the number does.
func (t Terminal) renderBar(w io.Writer, f triage.Funnel) {
	s := t.Style
	const cells = 46

	if f.Unique == 0 {
		fmt.Fprintf(w, "    %s\n", s.dim("nothing to triage"))
		return
	}

	quiet := int(float64(cells) * f.Reduction())
	if quiet > cells {
		quiet = cells
	}
	// A non-zero remainder must always render as at least one cell, or the
	// bar lies about a repository that has real work in it.
	signal := cells - quiet
	if signal == 0 && f.Act > 0 {
		signal, quiet = 1, cells-1
	}

	bar := s.fg(colFaint, strings.Repeat(s.barEmpty(), quiet)) +
		s.fg(colSignal, strings.Repeat(s.barFull(), signal))

	fmt.Fprintf(w, "    %s  %s %s\n",
		bar,
		s.bold(fmt.Sprintf("%.1f%%", f.Reduction()*100)),
		s.dim("needs no action today"))
}

// renderSection prints one verdict's findings, ranked.
func (t Terminal) renderSection(w io.Writer, r triage.Report, verdict triage.Verdict) {
	s := t.Style

	var rows []triage.Result
	for _, res := range r.Results {
		if res.Verdict == verdict {
			rows = append(rows, res)
		}
	}
	if len(rows) == 0 {
		if verdict == triage.VerdictAct {
			t.heading(w, "ACT")
			fmt.Fprintf(w, "    %s  %s\n\n",
				s.fg(colOK, s.glyph("✔", "+")),
				s.fg(colOK, "Nothing in this repository needs action today."))
		}
		return
	}

	label := strings.ToUpper(string(verdict))
	t.heading(w, fmt.Sprintf("%s %s %s findings", label, s.rule()+s.rule(), comma(len(rows))))

	shown := rows
	if t.Limit > 0 && len(shown) > t.Limit {
		shown = shown[:t.Limit]
	}

	for i, res := range shown {
		t.renderFinding(w, i+1, res)
	}

	if len(shown) < len(rows) {
		fmt.Fprintf(w, "    %s\n\n", s.dim(fmt.Sprintf(
			"... and %s more. Raise the cap with --limit 0.", comma(len(rows)-len(shown)))))
	}
}

// renderFinding prints one finding and the evidence behind its verdict.
func (t Terminal) renderFinding(w io.Writer, n int, res triage.Result) {
	s := t.Style
	f := res.Finding

	// Headline: rank, severity chip, score, identity.
	ident := f.PrimaryCVE()
	if ident == "" {
		ident = f.RuleID
	}

	// The severity label is padded to a fixed width so the score column lines
	// up down the page. A ranked list whose numbers do not align is a list
	// people skim instead of read.
	fmt.Fprintf(w, "  %s %s %s  %s\n",
		s.faint(padLeft(itoa(n), 3)+"."),
		s.chip(severityColor(f.Severity), pad(strings.ToUpper(string(f.Severity)), 8)),
		s.bold(s.fg(verdictColor(res.Verdict), padLeft(fmt.Sprintf("%.0f", res.Score), 3))),
		s.bold(ident))

	// Subject line: what and where.
	fmt.Fprintf(w, "       %s\n", t.subjectLine(f))

	if loc := locationLine(f); loc != "" {
		fmt.Fprintf(w, "       %s\n", s.dim(loc))
	}

	// Evidence: why this score and not the raw severity.
	for _, ev := range res.Evidence {
		fmt.Fprintf(w, "       %s %s %s\n",
			s.methodMark(ev.Method.Proven()),
			s.faint(pad(string(ev.Method), 10)),
			s.dim(truncate(ev.Reason, width-14)))
	}

	// The fix, when we know it. This is the line the developer actually wants.
	if f.Package != nil && f.Package.FixedIn != "" {
		fmt.Fprintf(w, "       %s %s\n",
			s.fg(colOK, s.glyph("→", ">")),
			s.fg(colOK, "fix: upgrade "+f.Package.Name+" to "+f.Package.FixedIn))
	}

	// Corroboration across scanners is signal; show it when it exists.
	if len(f.Scanners) > 1 {
		fmt.Fprintf(w, "       %s\n", s.faint("confirmed by "+strings.Join(f.Scanners, ", ")))
	}

	fmt.Fprintln(w)
}

// subjectLine renders "package@version  title" within the layout width.
//
// The colouring happens after trimming, never before. Truncating a string
// that already contains ANSI sequences both miscounts the visible width — the
// escape bytes are counted as characters — and can slice an escape in half,
// which leaks the previous colour across the rest of the output. Trim first,
// colour second.
func (t Terminal) subjectLine(f model.Finding) string {
	s := t.Style

	head := ""
	if f.Package != nil && f.Package.Name != "" {
		head = f.Package.Name + "@" + f.Package.Version
	}
	if head == "" {
		return truncate(f.Title, width)
	}

	head = truncate(head, width)
	room := width - len([]rune(head)) - 2
	if room < 12 || f.Title == "" {
		return head
	}
	return head + s.dim("  "+truncate(f.Title, room))
}

func (t Terminal) heading(w io.Writer, label string) {
	s := t.Style
	plain := "  " + s.rule() + s.rule() + " " + label + " "
	fill := width - len([]rune(plain)) + 2
	if fill < 2 {
		fill = 2
	}
	fmt.Fprintf(w, "%s%s\n\n",
		s.fg(colAccent, "  "+s.rule()+s.rule()+" "+label+" "),
		s.faint(strings.Repeat(s.rule(), fill)))
}

func (t Terminal) note(w io.Writer, msg string) {
	fmt.Fprintf(w, "  %s %s\n", t.Style.faint(t.Style.glyph("ℹ", "i")), t.Style.dim(msg))
}

// locationLine formats where the finding lives, omitting noise when the
// scanner gave us nothing useful.
func locationLine(f model.Finding) string {
	path := model.NormalizePath(f.Location.Path)
	if path == "" {
		return ""
	}
	if f.Location.StartLine > 0 {
		return path + ":" + itoa(f.Location.StartLine)
	}
	return path
}

// truncate shortens to n runes with an ellipsis, counting runes rather than
// bytes so that non-ASCII descriptions do not get cut mid-character.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}
