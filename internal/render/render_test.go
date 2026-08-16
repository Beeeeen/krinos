package render

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Beeeeen/krinos/internal/evidence"
	"github.com/Beeeeen/krinos/internal/model"
	"github.com/Beeeeen/krinos/internal/policy"
	"github.com/Beeeeen/krinos/internal/triage"
)

func result(verdict triage.Verdict, score float64, mutate func(*model.Finding)) triage.Result {
	f := model.Finding{
		Fingerprint: "abc123",
		RuleID:      "go.lang.security.sqli",
		Title:       "SQL query built by string formatting",
		Class:       model.ClassCode,
		Severity:    model.SeverityHigh,
		CVEs:        []string{"CVE-2021-44228"},
		Location:    model.Location{Path: "internal/payments/ledger.go", StartLine: 214, EndLine: 218},
		Scanners:    []string{"semgrep"},
	}
	if mutate != nil {
		mutate(&f)
	}
	return triage.Result{
		Finding: f,
		Score:   score,
		Verdict: verdict,
		Evidence: []evidence.Evidence{
			{Kind: evidence.KindBlastRadius, Method: evidence.MethodPathRule, Multiplier: 1.6,
				Reason: "sits on the payments path — a compromise here reaches sensitive data"},
		},
	}
}

func sampleReport(results ...triage.Result) triage.Report {
	r := triage.Report{Results: results}
	r.Funnel.Ingested = 31
	r.Funnel.Unique = 28
	r.Funnel.Duplicates = 3
	for _, res := range results {
		switch res.Verdict {
		case triage.VerdictAct:
			r.Funnel.Act++
		case triage.VerdictWatch:
			r.Funnel.Watch++
		default:
			r.Funnel.Suppressed++
		}
	}
	return r
}

// Scanner output is untrusted input, and workflow commands are a control
// channel. A rule description containing a newline followed by "::error::"
// must not be able to forge an annotation — or, worse, a command that
// modifies the runner environment.
func TestGitHub_CannotForgeWorkflowCommands(t *testing.T) {
	hostile := result(triage.VerdictAct, 95, func(f *model.Finding) {
		f.Title = "evil\n::error::forged\n::add-mask::x"
	})

	var buf bytes.Buffer
	GitHub{Annotate: true}.Render(&buf, sampleReport(hostile), nil, policy.Decision{}, "test")

	out := buf.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")

	// The Actions runner parses workflow commands per line, so the property
	// that matters is that untrusted text can never *start* a line. A "::"
	// surviving inside a message body is fine — and must survive, because
	// rule descriptions legitimately contain things like std::string.
	if len(lines) != 1 {
		t.Fatalf("a hostile title must stay on one line; got %d lines:\n%s", len(lines), out)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "::error ") {
			t.Fatalf("a line the runner would parse as a forged command escaped: %q", line)
		}
	}
	if !strings.Contains(out, "%0A") {
		t.Error("newlines should be percent-encoded, not dropped")
	}
}

// Percent must be escaped before anything else, or an attacker supplying the
// literal text "%0A" would have it decoded into a real newline by the runner
// — smuggling a line break past an escaper that only looked for "\n".
func TestGitHub_EscapesPercentFirst(t *testing.T) {
	res := result(triage.VerdictAct, 95, func(f *model.Finding) {
		f.Title = `literal %0A should stay literal`
	})

	var buf bytes.Buffer
	GitHub{Annotate: true}.Render(&buf, sampleReport(res), nil, policy.Decision{}, "test")

	if !strings.Contains(buf.String(), "%250A") {
		t.Errorf("a literal %%0A must be double-encoded to %%250A, got:\n%s", buf.String())
	}
}

func TestGitHub_EscapesPropertySeparators(t *testing.T) {
	res := result(triage.VerdictAct, 95, func(f *model.Finding) {
		f.RuleID = "rule,with:separators"
		f.CVEs = nil
	})

	var buf bytes.Buffer
	GitHub{Annotate: true}.Render(&buf, sampleReport(res), nil, policy.Decision{}, "test")

	// The title property carries the rule ID. Raw commas or colons there
	// would split the property list and corrupt every property after it.
	head := strings.SplitN(buf.String(), "::", 3)
	if len(head) < 2 {
		t.Fatalf("unexpected annotation shape: %q", buf.String())
	}
	props := head[1]
	if strings.Contains(props, "rule,with") || strings.Contains(props, "with:separators") {
		t.Errorf("property separators were not escaped: %q", props)
	}
}

func TestGitHub_AnnotatesByVerdict(t *testing.T) {
	report := sampleReport(
		result(triage.VerdictAct, 95, nil),
		result(triage.VerdictWatch, 50, func(f *model.Finding) { f.Fingerprint = "watch1" }),
		result(triage.VerdictSuppress, 10, func(f *model.Finding) { f.Fingerprint = "supp1" }),
	)

	var buf bytes.Buffer
	GitHub{Annotate: true}.Render(&buf, report, nil, policy.Decision{}, "test")
	out := buf.String()

	if strings.Count(out, "::error ") != 1 {
		t.Errorf("expected exactly one error annotation, got:\n%s", out)
	}
	if strings.Contains(out, "::warning ") {
		t.Error("watch findings must not be annotated unless AnnotateWatch is set")
	}
	// A suppressed finding has already been judged harmless. Spending a
	// reviewer's attention on it is how a tool gets muted.
	if strings.Count(out, "::") > 2 {
		t.Errorf("suppressed findings must never be annotated:\n%s", out)
	}

	buf.Reset()
	GitHub{Annotate: true, AnnotateWatch: true}.Render(&buf, report, nil, policy.Decision{}, "test")
	if !strings.Contains(buf.String(), "::warning ") {
		t.Error("AnnotateWatch should promote watch findings to warnings")
	}
}

func TestGitHub_IncludesFileAndLine(t *testing.T) {
	var buf bytes.Buffer
	GitHub{Annotate: true}.Render(&buf, sampleReport(result(triage.VerdictAct, 95, nil)), nil, policy.Decision{}, "test")

	out := buf.String()
	for _, want := range []string{"file=internal/payments/ledger.go", "line=214", "endLine=218"} {
		if !strings.Contains(out, want) {
			t.Errorf("annotation missing %q:\n%s", want, out)
		}
	}
}

func TestGitHub_WritesSummaryAndOutputs(t *testing.T) {
	dir := t.TempDir()
	summary := filepath.Join(dir, "summary.md")
	outputs := filepath.Join(dir, "output.txt")

	report := sampleReport(
		result(triage.VerdictAct, 95, nil),
		result(triage.VerdictWatch, 50, func(f *model.Finding) { f.Fingerprint = "w1" }),
	)
	gate := policy.Decision{Pass: false, ExitCode: 1, Summary: "1 finding(s) at or above \"act\" — build gated"}

	var buf bytes.Buffer
	gh := GitHub{SummaryPath: summary, OutputPath: outputs, Annotate: true}
	if err := gh.Render(&buf, report, map[string]int{"semgrep": 31}, gate, "v0.2.0"); err != nil {
		t.Fatal(err)
	}

	md, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "## Krinos") {
		t.Errorf("job summary was not written:\n%s", md)
	}

	kv, err := os.ReadFile(outputs)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"act=1", "watch=1", "ingested=31", "unique=28", "passed=false"} {
		if !strings.Contains(string(kv), want) {
			t.Errorf("step outputs missing %q:\n%s", want, kv)
		}
	}
}

// GitHub's summary and output files are shared by every step in a job.
// Truncating them would silently delete another action's work.
func TestGitHub_AppendsRatherThanTruncates(t *testing.T) {
	dir := t.TempDir()
	outputs := filepath.Join(dir, "output.txt")
	if err := os.WriteFile(outputs, []byte("someone-elses=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	gh := GitHub{OutputPath: outputs}
	if err := gh.Render(&buf, sampleReport(result(triage.VerdictAct, 95, nil)), nil, policy.Decision{}, "test"); err != nil {
		t.Fatal(err)
	}

	got, _ := os.ReadFile(outputs)
	if !strings.Contains(string(got), "someone-elses=value") {
		t.Fatalf("a prior step's output was clobbered:\n%s", got)
	}
}

// A summary we cannot write is a degraded report, not a failed build. Only
// the gate's verdict may decide the exit code.
func TestGitHub_UnwritableSummaryWarnsButDoesNotPanic(t *testing.T) {
	var buf bytes.Buffer
	gh := GitHub{SummaryPath: filepath.Join(t.TempDir(), "no", "such", "dir", "s.md"), Annotate: true}

	err := gh.Render(&buf, sampleReport(result(triage.VerdictAct, 95, nil)), nil, policy.Decision{}, "test")
	if err == nil {
		t.Error("the failure should be reported to the caller")
	}
	if !strings.Contains(buf.String(), "::warning") {
		t.Errorf("the user should see a warning in the log:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "::error ") {
		t.Error("annotations must still be emitted when the summary fails")
	}
}

func TestMarkdown_EscapesTableBreakingCharacters(t *testing.T) {
	res := result(triage.VerdictAct, 95, func(f *model.Finding) {
		f.Title = "a | b | c\nwith a newline"
	})

	var buf bytes.Buffer
	if err := (Markdown{}).Render(&buf, sampleReport(res), nil, policy.Decision{Pass: false}, "test"); err != nil {
		t.Fatal(err)
	}

	// Find the table row and confirm the pipes inside the title are escaped
	// rather than creating phantom columns.
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "with a newline") {
			if strings.Contains(line, "a | b") {
				t.Errorf("unescaped pipes broke the table row: %q", line)
			}
			return
		}
	}
	t.Fatal("the finding never made it into the markdown")
}

func TestMarkdown_HeadlineMatchesTheVerdict(t *testing.T) {
	clean := sampleReport()
	clean.Funnel.Act = 0

	var buf bytes.Buffer
	_ = Markdown{}.Render(&buf, clean, nil, policy.Decision{Pass: true, Summary: "ok"}, "test")
	if !strings.Contains(buf.String(), "nothing needs action") {
		t.Errorf("a clean run should say so plainly:\n%s", buf.String())
	}

	buf.Reset()
	one := sampleReport(result(triage.VerdictAct, 95, nil))
	_ = Markdown{}.Render(&buf, one, nil, policy.Decision{}, "test")
	if !strings.Contains(buf.String(), "1 finding needs action") {
		t.Errorf("singular should not read as '1 findings':\n%s", buf.String())
	}
}

func TestMarkdown_AlwaysDisclosesSuppressedCount(t *testing.T) {
	report := sampleReport(result(triage.VerdictSuppress, 8, nil))

	var buf bytes.Buffer
	_ = Markdown{}.Render(&buf, report, nil, policy.Decision{Pass: true}, "test")

	if !strings.Contains(buf.String(), "suppressed") {
		t.Error("suppressed findings must always be disclosed, never silently omitted")
	}
	if !strings.Contains(buf.String(), "--show suppressed") {
		t.Error("the report must tell the reader how to audit what we dismissed")
	}
}

func TestMarkdownBar_StaysInBounds(t *testing.T) {
	for _, f := range []float64{-1, 0, 0.5, 1, 2} {
		bar := markdownBar(f)
		if n := len([]rune(bar)); n != 28 {
			t.Errorf("markdownBar(%v) produced %d cells, want 28", f, n)
		}
	}
}
