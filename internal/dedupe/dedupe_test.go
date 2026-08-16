package dedupe

import (
	"reflect"
	"testing"

	"github.com/Beeeeen/krinos/internal/model"
)

func log4shell(scanner, reportedPath string) model.Finding {
	f := model.Finding{
		Class:    model.ClassDependency,
		Severity: model.SeverityCritical,
		CVSS:     10.0,
		CVEs:     []string{"CVE-2021-44228"},
		Location: model.Location{Path: reportedPath},
		Scanners: []string{scanner},
		Package:  &model.Package{Ecosystem: "maven", Name: "log4j-core", Version: "2.14.1", Depth: -1},
	}
	f.Fingerprint = f.ComputeFingerprint()
	return f
}

// The headline claim of the product is that a backlog of thousands is mostly
// the same problems counted repeatedly. This is that claim, as a test.
func TestCollapse_FoldsTheSameCVEFromThreeScanners(t *testing.T) {
	in := []model.Finding{
		log4shell("trivy", "pom.xml"),
		log4shell("grype", "/app/lib/log4j-core-2.14.1.jar"),
		log4shell("osv-scanner", "pom.xml"),
	}

	out, collapsed := Collapse(in)

	if len(out) != 1 {
		t.Fatalf("three reports of one vulnerability must collapse to one finding, got %d", len(out))
	}
	if collapsed != 2 {
		t.Errorf("collapsed count: want 2, got %d", collapsed)
	}
	if len(out[0].Scanners) != 3 {
		t.Errorf("corroboration must survive the merge, got %v", out[0].Scanners)
	}
}

func TestCollapse_KeepsDistinctFindingsApart(t *testing.T) {
	a := log4shell("trivy", "pom.xml")
	b := log4shell("trivy", "pom.xml")
	b.CVEs = []string{"CVE-2021-45046"}
	b.Fingerprint = b.ComputeFingerprint()

	out, collapsed := Collapse([]model.Finding{a, b})

	if len(out) != 2 {
		t.Fatalf("two different CVEs are two findings, got %d", len(out))
	}
	if collapsed != 0 {
		t.Errorf("nothing should have been collapsed, got %d", collapsed)
	}
}

// Go randomizes map iteration deliberately. If Collapse ever iterates a map
// to build its output, this test catches it — and a security gate whose
// output reorders between runs is a gate teams learn to ignore.
func TestCollapse_IsDeterministic(t *testing.T) {
	in := []model.Finding{
		log4shell("trivy", "pom.xml"),
		log4shell("grype", "lib.jar"),
	}
	for _, cve := range []string{"CVE-2022-22965", "CVE-2023-4863", "CVE-2019-0708"} {
		f := log4shell("trivy", "pom.xml")
		f.CVEs = []string{cve}
		f.Fingerprint = f.ComputeFingerprint()
		in = append(in, f)
	}

	first, _ := Collapse(in)
	for i := 0; i < 50; i++ {
		again, _ := Collapse(in)
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("Collapse is not deterministic; run %d differed", i)
		}
	}
}

func TestCollapse_AssignsMissingFingerprints(t *testing.T) {
	f := model.Finding{
		Class:    model.ClassCode,
		RuleID:   "sql-injection",
		Location: model.Location{Path: "api/query.go", StartLine: 12},
		Scanners: []string{"semgrep"},
	}
	out, _ := Collapse([]model.Finding{f})

	if len(out) != 1 || out[0].Fingerprint == "" {
		t.Fatal("Collapse must fingerprint findings that arrived without one")
	}
}

// SARIF cannot express package coordinates, so a Grype-via-SARIF report and a
// Trivy report of the same CVE arrive with different fingerprints. They are
// still one problem, and counting them twice would inflate the very metric we
// use to claim noise reduction.
func TestCollapse_ReconcilesSARIFDependencyWithoutCoordinates(t *testing.T) {
	trivy := log4shell("trivy", "pom.xml")

	sarif := model.Finding{
		Class:    model.ClassDependency, // classified from a "dependency" tag
		Severity: model.SeverityCritical,
		CVEs:     []string{"CVE-2021-44228"},
		Location: model.Location{Path: "go.sum"},
		Scanners: []string{"grype"},
		// No Package: SARIF has nowhere to put it.
	}
	sarif.Fingerprint = sarif.ComputeFingerprint()

	if trivy.Fingerprint == sarif.Fingerprint {
		t.Fatal("precondition failed: these should not fingerprint alike")
	}

	out, collapsed := Collapse([]model.Finding{trivy, sarif})

	if len(out) != 1 {
		t.Fatalf("want one reconciled finding, got %d", len(out))
	}
	if collapsed != 1 {
		t.Errorf("collapsed count: want 1, got %d", collapsed)
	}
	if out[0].Package.Coordinates() == "" {
		t.Error("the surviving finding must keep the package coordinates")
	}
	if len(out[0].Scanners) != 2 {
		t.Errorf("both scanners must be credited, got %v", out[0].Scanners)
	}
}

// When a CVE affects several packages there is no honest way to pick which
// one an uncoordinated finding belongs to, so it must stay separate. Guessing
// here would attribute a vulnerability to the wrong package, which is worse
// than reporting it twice.
func TestCollapse_DoesNotGuessWhenCVEAffectsSeveralPackages(t *testing.T) {
	a := log4shell("trivy", "pom.xml")
	b := log4shell("trivy", "pom.xml")
	b.Package = &model.Package{Ecosystem: "maven", Name: "log4j-api", Version: "2.14.1", Depth: 1}
	b.Fingerprint = b.ComputeFingerprint()

	ambiguous := model.Finding{
		Class:    model.ClassDependency,
		Severity: model.SeverityCritical,
		CVEs:     []string{"CVE-2021-44228"},
		Scanners: []string{"grype"},
	}
	ambiguous.Fingerprint = ambiguous.ComputeFingerprint()

	out, _ := Collapse([]model.Finding{a, b, ambiguous})

	if len(out) != 3 {
		t.Fatalf("an ambiguous attribution must not be guessed: want 3 findings, got %d", len(out))
	}
}

func TestCollapse_Empty(t *testing.T) {
	out, collapsed := Collapse(nil)
	if out != nil || collapsed != 0 {
		t.Fatalf("empty input must produce empty output, got %v / %d", out, collapsed)
	}
}
