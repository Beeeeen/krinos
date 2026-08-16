package triage

import (
	"encoding/json"
	"testing"

	"github.com/krinos-dev/krinos/internal/evidence"
	"github.com/krinos-dev/krinos/internal/model"
)

func finding(mutate func(*model.Finding)) model.Finding {
	f := model.Finding{
		Class:    model.ClassDependency,
		Severity: model.SeverityCritical,
		CVSS:     9.8,
		Title:    "Remote code execution",
		Location: model.Location{Path: "go.mod"},
		Scanners: []string{"trivy"},
		Package:  &model.Package{Ecosystem: "gomod", Name: "example.com/acme", Version: "1.0.0", Depth: 0},
	}
	if mutate != nil {
		mutate(&f)
	}
	f.Fingerprint = f.ComputeFingerprint()
	return f
}

// This is the product thesis expressed as an assertion: a CRITICAL finding
// that cannot reach production must not break the build. If this test ever
// fails, Krinos has become just another scanner.
func TestEngine_SuppressesUnreachableCritical(t *testing.T) {
	f := finding(func(f *model.Finding) {
		f.CVEs = []string{"CVE-2029-11111"} // not in KEV
		f.Package.DevOnly = true
	})

	report := NewEngine().Run([]model.Finding{f}, &evidence.Context{})

	if got := report.Results[0].Verdict; got != VerdictSuppress {
		t.Fatalf("a critical CVE in a dev-only dependency must be suppressed, got %s (score %.1f)",
			got, report.Results[0].Score)
	}
	if len(report.Results[0].Evidence) == 0 {
		t.Fatal("a suppressed finding must carry the reason it was suppressed")
	}
}

// The mirror image: known exploitation in the wild must survive everything.
func TestEngine_KEVEscalatesToAct(t *testing.T) {
	f := finding(func(f *model.Finding) {
		f.CVEs = []string{"CVE-2021-44228"}
		f.Package.Name = "log4j-core"
	})

	report := NewEngine().Run([]model.Finding{f}, &evidence.Context{})

	if got := report.Results[0].Verdict; got != VerdictAct {
		t.Fatalf("a KEV-listed CVE in a direct dependency must demand action, got %s (score %.1f)",
			got, report.Results[0].Score)
	}
}

// A dev-only dependency is discounted, but a KEV entry inside one still
// deserves attention. This pins the interaction rather than letting one layer
// silently cancel the other.
func TestEngine_KEVSurvivesDevOnlyDiscount(t *testing.T) {
	devKEV := finding(func(f *model.Finding) {
		f.CVEs = []string{"CVE-2021-44228"}
		f.Package.DevOnly = true
	})
	devPlain := finding(func(f *model.Finding) {
		f.CVEs = []string{"CVE-2029-11111"}
		f.Package.DevOnly = true
		f.Package.Name = "other"
	})

	report := NewEngine().Run([]model.Finding{devKEV, devPlain}, &evidence.Context{})

	var kevScore, plainScore float64
	for _, r := range report.Results {
		if r.Finding.PrimaryCVE() == "CVE-2021-44228" {
			kevScore = r.Score
		} else {
			plainScore = r.Score
		}
	}
	if kevScore <= plainScore {
		t.Fatalf("known exploitation must still outrank an ordinary CVE in the same package: kev=%.1f plain=%.1f",
			kevScore, plainScore)
	}
}

func TestEngine_FunnelCountsAddUp(t *testing.T) {
	dup := finding(func(f *model.Finding) { f.CVEs = []string{"CVE-2021-44228"} })
	dup2 := dup
	dup2.Scanners = []string{"grype"}

	unreachable := finding(func(f *model.Finding) {
		f.CVEs = []string{"CVE-2029-22222"}
		f.Package.Name = "deep"
		f.Package.Depth = 5
	})

	report := NewEngine().Run([]model.Finding{dup, dup2, unreachable}, &evidence.Context{})

	if report.Funnel.Ingested != 3 {
		t.Errorf("ingested: want 3, got %d", report.Funnel.Ingested)
	}
	if report.Funnel.Duplicates != 1 {
		t.Errorf("duplicates: want 1, got %d", report.Funnel.Duplicates)
	}
	if report.Funnel.Unique != 2 {
		t.Errorf("unique: want 2, got %d", report.Funnel.Unique)
	}
	if sum := report.Funnel.Act + report.Funnel.Watch + report.Funnel.Suppressed; sum != report.Funnel.Unique {
		t.Errorf("every unique finding must land in exactly one verdict: %d verdicts vs %d unique",
			sum, report.Funnel.Unique)
	}
}

func TestFunnel_ReductionHandlesEmptyRepo(t *testing.T) {
	report := NewEngine().Run(nil, &evidence.Context{})
	if report.Funnel.Reduction() != 0 {
		t.Fatalf("an empty scan must report 0%% reduction, not divide by zero: %v", report.Funnel.Reduction())
	}
	if len(report.Acting()) != 0 {
		t.Fatal("an empty scan has nothing to act on")
	}
}

// Severity alone must never break a build. This is the threshold the whole
// product rests on: a HIGH with no evidence behind it is something to track,
// not something to stop a release for.
func TestEngine_SeverityAloneDoesNotGate(t *testing.T) {
	plain := finding(func(f *model.Finding) {
		f.Severity = model.SeverityHigh
		f.CVSS = 7.5
		f.CVEs = []string{"CVE-2029-55555"}
		f.Package.Name = "ordinary"
		f.Package.Depth = 0           // direct: reachability is neutral
		f.Location = model.Location{} // no path signal either way
	})

	report := NewEngine().Run([]model.Finding{plain}, &evidence.Context{})

	if got := report.Results[0].Verdict; got == VerdictAct {
		t.Fatalf("a HIGH with no supporting evidence must not gate the build, got %s at score %.1f",
			got, report.Results[0].Score)
	}
}

// And the same finding, once evidence argues it up, must gate.
func TestEngine_EvidencePromotesToAct(t *testing.T) {
	promoted := finding(func(f *model.Finding) {
		f.Severity = model.SeverityHigh
		f.CVSS = 7.5
		f.CVEs = []string{"CVE-2029-55555"}
		f.Package.Name = "ordinary"
		f.Location = model.Location{Path: "services/payments/charge.go"}
	})

	report := NewEngine().Run([]model.Finding{promoted}, &evidence.Context{})

	if got := report.Results[0].Verdict; got != VerdictAct {
		t.Fatalf("a HIGH on the payments path must gate, got %s at score %.1f",
			got, report.Results[0].Score)
	}
}

// Determinism is a product requirement, not an implementation detail: the
// same inputs must produce byte-identical output, or CI diffs become noise
// and teams stop reading them.
func TestEngine_IsDeterministic(t *testing.T) {
	var in []model.Finding
	for _, cve := range []string{
		"CVE-2021-44228", "CVE-2022-22965", "CVE-2029-1", "CVE-2029-2", "CVE-2029-3",
	} {
		in = append(in, finding(func(f *model.Finding) {
			f.CVEs = []string{cve}
			f.Package.Name = "pkg-" + cve
		}))
	}

	first, err := json.Marshal(NewEngine().Run(in, &evidence.Context{}))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		again, err := json.Marshal(NewEngine().Run(in, &evidence.Context{}))
		if err != nil {
			t.Fatal(err)
		}
		if string(first) != string(again) {
			t.Fatalf("report differed on run %d", i)
		}
	}
}

func TestEngine_RanksActBeforeWatchBeforeSuppress(t *testing.T) {
	in := []model.Finding{
		finding(func(f *model.Finding) {
			f.CVEs = []string{"CVE-2029-33333"}
			f.Package.Name = "buried"
			f.Package.Depth = 6
		}),
		finding(func(f *model.Finding) {
			f.CVEs = []string{"CVE-2021-44228"}
			f.Package.Name = "log4j"
		}),
	}

	report := NewEngine().Run(in, &evidence.Context{})

	for i := 1; i < len(report.Results); i++ {
		if report.Results[i-1].Verdict.Rank() < report.Results[i].Verdict.Rank() {
			t.Fatalf("results are not ranked most-urgent-first: %s before %s",
				report.Results[i-1].Verdict, report.Results[i].Verdict)
		}
	}
	if report.Results[0].Finding.Package.Name != "log4j" {
		t.Errorf("the actionable finding must be first, got %q", report.Results[0].Finding.Package.Name)
	}
}

// CVSS is more precise than a vendor severity label, so the engine re-derives
// the band from the score when one is present.
func TestEngine_PrefersCVSSOverVendorLabel(t *testing.T) {
	mislabelled := finding(func(f *model.Finding) {
		f.Severity = model.SeverityLow // vendor says low
		f.CVSS = 9.9                   // the score says otherwise
		f.CVEs = []string{"CVE-2029-44444"}
	})

	report := NewEngine().Run([]model.Finding{mislabelled}, &evidence.Context{})

	if report.Results[0].Base != model.SeverityCritical.BaseScore() {
		t.Fatalf("a CVSS of 9.9 must set the base score, not the vendor's 'low' label: base=%.1f",
			report.Results[0].Base)
	}
}

func TestEngine_ScoreStaysInRange(t *testing.T) {
	// KEV plus an amplifying path plus a direct dependency multiplies well
	// past 100; the score must still be reportable.
	f := finding(func(f *model.Finding) {
		f.CVEs = []string{"CVE-2021-44228"}
		f.Location = model.Location{Path: "services/payment/auth/charge.go"}
	})

	report := NewEngine().Run([]model.Finding{f}, &evidence.Context{})
	got := report.Results[0].Score

	if got < 0 || got > 100 {
		t.Fatalf("score must be clamped to [0,100], got %v", got)
	}
}
