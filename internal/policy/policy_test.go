package policy

import (
	"testing"

	"github.com/krinos-dev/krinos/internal/model"
	"github.com/krinos-dev/krinos/internal/triage"
)

func report(verdicts ...triage.Verdict) triage.Report {
	r := triage.Report{}
	for _, v := range verdicts {
		r.Results = append(r.Results, triage.Result{Verdict: v})
		switch v {
		case triage.VerdictAct:
			r.Funnel.Act++
		case triage.VerdictWatch:
			r.Funnel.Watch++
		default:
			r.Funnel.Suppressed++
		}
	}
	r.Funnel.Unique = len(verdicts)
	return r
}

func TestGate_FailsOnAct(t *testing.T) {
	d := Policy{FailOn: triage.VerdictAct}.Gate(report(triage.VerdictAct, triage.VerdictWatch))
	if d.Pass {
		t.Fatal("an actionable finding must fail the gate")
	}
	if d.ExitCode != 1 {
		t.Errorf("exit code: want 1, got %d", d.ExitCode)
	}
}

func TestGate_PassesWhenOnlyWatch(t *testing.T) {
	d := Policy{FailOn: triage.VerdictAct}.Gate(report(triage.VerdictWatch, triage.VerdictSuppress))
	if !d.Pass || d.ExitCode != 0 {
		t.Fatalf("watch-only findings must not break the build: %+v", d)
	}
}

// Lowering the threshold to watch must also catch everything above it.
func TestGate_ThresholdIsInclusiveUpward(t *testing.T) {
	d := Policy{FailOn: triage.VerdictWatch}.Gate(report(triage.VerdictAct))
	if d.Pass {
		t.Fatal("a threshold of watch must also gate on act")
	}
}

func TestGate_DisabledReportsOnly(t *testing.T) {
	d := Policy{FailOn: ""}.Gate(report(triage.VerdictAct, triage.VerdictAct))
	if !d.Pass || d.ExitCode != 0 {
		t.Fatalf("report-only mode must never fail the build: %+v", d)
	}
}

func TestParseVerdict(t *testing.T) {
	for _, in := range []string{"act", "ACT", " watch ", "never", "none", "off"} {
		if _, err := ParseVerdict(in); err != nil {
			t.Errorf("ParseVerdict(%q) returned %v", in, err)
		}
	}
	// A typo must be an error. Silently defaulting a security gate to
	// something weaker than the user asked for is the worst possible
	// failure mode for this flag.
	if _, err := ParseVerdict("acct"); err == nil {
		t.Fatal("a misspelled threshold must be rejected, never defaulted")
	}
}

func TestFilter_MatchesFingerprintCVEAndRule(t *testing.T) {
	findings := []model.Finding{
		{Fingerprint: "aaa111", RuleID: "rule-a", CVEs: []string{"CVE-2021-44228"}},
		{Fingerprint: "bbb222", RuleID: "rule-b"},
		{Fingerprint: "ccc333", RuleID: "rule-c", CVEs: []string{"CVE-2029-00001"}},
	}

	out, dropped := Policy{Ignore: []string{"cve-2021-44228", "rule-b"}}.Filter(findings)

	if dropped != 2 {
		t.Fatalf("want 2 dropped, got %d", dropped)
	}
	if len(out) != 1 || out[0].Fingerprint != "ccc333" {
		t.Fatalf("wrong survivor: %+v", out)
	}
}

func TestFilter_NoIgnoresIsAPassThrough(t *testing.T) {
	in := []model.Finding{{Fingerprint: "aaa"}}
	out, dropped := Policy{}.Filter(in)
	if dropped != 0 || len(out) != 1 {
		t.Fatalf("an empty ignore list must not touch the findings: %d dropped", dropped)
	}
}
