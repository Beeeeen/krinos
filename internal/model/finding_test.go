package model

import "testing"

// The dependency fingerprint deliberately ignores the file path. This test
// exists because it is the single behaviour that makes cross-scanner dedup
// work, and it looks like a bug to anyone reading ComputeFingerprint without
// context. If someone "fixes" it by adding the path, this fails loudly.
func TestFingerprint_DependencyIgnoresReportedPath(t *testing.T) {
	trivy := Finding{
		Class:    ClassDependency,
		CVEs:     []string{"CVE-2021-44228"},
		Location: Location{Path: "go.sum"},
		Package:  &Package{Ecosystem: "gomod", Name: "example.com/log", Version: "1.2.3"},
	}
	grype := Finding{
		Class:    ClassDependency,
		CVEs:     []string{"CVE-2021-44228"},
		Location: Location{Path: "/app/vendor/example.com/log"},
		Package:  &Package{Ecosystem: "gomod", Name: "example.com/log", Version: "1.2.3"},
	}

	if trivy.ComputeFingerprint() != grype.ComputeFingerprint() {
		t.Fatalf("same CVE in the same package must fingerprint identically regardless of the path each scanner reported\n trivy=%s\n grype=%s",
			trivy.ComputeFingerprint(), grype.ComputeFingerprint())
	}
}

func TestFingerprint_DependencyDistinguishesVersion(t *testing.T) {
	a := Finding{Class: ClassDependency, CVEs: []string{"CVE-2021-44228"},
		Package: &Package{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}}
	b := a
	b.Package = &Package{Ecosystem: "npm", Name: "left-pad", Version: "1.0.1"}

	if a.ComputeFingerprint() == b.ComputeFingerprint() {
		t.Fatal("two versions of the same package are two distinct findings")
	}
}

func TestFingerprint_CodeUsesLocation(t *testing.T) {
	a := Finding{Class: ClassCode, RuleID: "go.lang.security.audit",
		Location: Location{Path: "internal/api/handler.go", StartLine: 10}}
	b := a
	b.Location.StartLine = 84

	if a.ComputeFingerprint() == b.ComputeFingerprint() {
		t.Fatal("the same rule firing twice in one file is two things to fix")
	}

	// Path separators and prefixes vary by platform and by scanner working
	// directory; they must not split one finding into two.
	c := a
	c.Location.Path = "./internal/api/handler.go"
	if a.ComputeFingerprint() != c.ComputeFingerprint() {
		t.Fatal("path normalization failed: ./ prefix produced a different fingerprint")
	}
}

func TestMerge_KeepsWorstAndUnions(t *testing.T) {
	base := Finding{
		Title:    "Remote code execution",
		Severity: SeverityMedium,
		CVSS:     5.0,
		CVEs:     []string{"CVE-2021-44228"},
		Scanners: []string{"trivy"},
		Package:  &Package{Ecosystem: "maven", Name: "log4j-core", Version: "2.14.1", Depth: -1},
	}
	other := Finding{
		Severity:    SeverityCritical,
		CVSS:        10.0,
		Description: "JNDI lookup",
		CVEs:        []string{"CVE-2021-45046"},
		Scanners:    []string{"grype"},
		Location:    Location{Path: "pom.xml", StartLine: 3},
		Package:     &Package{Ecosystem: "maven", Name: "log4j-core", Version: "2.14.1", Depth: 0, FixedIn: "2.17.1"},
	}

	base.Merge(other)

	if base.Severity != SeverityCritical {
		t.Errorf("severity: want critical, got %s", base.Severity)
	}
	if base.CVSS != 10.0 {
		t.Errorf("cvss: want 10.0, got %v", base.CVSS)
	}
	if len(base.CVEs) != 2 {
		t.Errorf("cves: want both, got %v", base.CVEs)
	}
	if len(base.Scanners) != 2 {
		t.Errorf("scanners: want both, got %v", base.Scanners)
	}
	if base.Description != "JNDI lookup" {
		t.Errorf("description: empty side should adopt the other, got %q", base.Description)
	}
	if base.Package.Depth != 0 {
		t.Errorf("depth: unknown (-1) must yield to a known value, got %d", base.Package.Depth)
	}
	if base.Package.FixedIn != "2.17.1" {
		t.Errorf("fixed version must never be lost in a merge, got %q", base.Package.FixedIn)
	}
	if base.Location.Path != "pom.xml" {
		t.Errorf("a real location should beat an absent one, got %q", base.Location.Path)
	}
	if base.Title != "Remote code execution" {
		t.Errorf("a present title must not be overwritten by an empty one, got %q", base.Title)
	}
}

func TestMerge_DoesNotDowngrade(t *testing.T) {
	base := Finding{Severity: SeverityCritical, CVSS: 9.8}
	base.Merge(Finding{Severity: SeverityLow, CVSS: 2.0})

	if base.Severity != SeverityCritical || base.CVSS != 9.8 {
		t.Fatalf("a second scanner disagreeing downward must not lower the verdict: got %s / %v", base.Severity, base.CVSS)
	}
}

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"CRITICAL":   SeverityCritical,
		"High":       SeverityHigh,
		"error":      SeverityHigh, // SARIF
		"moderate":   SeverityMedium,
		"warning":    SeverityMedium, // SARIF
		"note":       SeverityLow,    // SARIF
		"negligible": SeverityInfo,   // Grype
		"  low  ":    SeverityLow,
		"":           SeverityUnknown,
		"purple":     SeverityUnknown,
	}
	for in, want := range cases {
		if got := ParseSeverity(in); got != want {
			t.Errorf("ParseSeverity(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		score float64
		want  Severity
	}{
		{10.0, SeverityCritical},
		{9.0, SeverityCritical},
		{8.9, SeverityHigh},
		{7.0, SeverityHigh},
		{4.0, SeverityMedium},
		{3.9, SeverityLow},
		{0.1, SeverityLow},
		{0, SeverityUnknown},
	}
	for _, c := range cases {
		if got := SeverityFromCVSS(c.score); got != c.want {
			t.Errorf("SeverityFromCVSS(%v) = %s, want %s", c.score, got, c.want)
		}
	}
}

// Unknown severity must not be treated as harmless. A scanner that failed to
// grade something is not a scanner saying it is safe.
func TestUnknownSeverityOutranksLow(t *testing.T) {
	if SeverityUnknown.BaseScore() <= SeverityLow.BaseScore() {
		t.Fatal("unknown severity must score above low: absence of data is not evidence of safety")
	}
}

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		`./src/main.go`:            "src/main.go",
		`/src/main.go`:             "src/main.go",
		`src\windows\a.go`:         "src/windows/a.go",
		`.\src\windows\a.go`:       "src/windows/a.go",
		`  spaced/path.go  `:       "spaced/path.go",
		`internal\auth\testdata\x`: "internal/auth/testdata/x",
	}
	for in, want := range cases {
		if got := NormalizePath(in); got != want {
			t.Errorf("NormalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// Regression, found by cross-platform CI: NormalizePath used filepath.ToSlash,
// which is a no-op on Unix. A report produced on Windows and triaged on a
// Linux runner therefore kept its backslashes, and the consequences were both
// silent — dedup stopped folding, and every path rule stopped matching
// because the blast-radius layer splits on "/".
//
// These paths are data from a scanner report, not paths on the host, so the
// separator conversion can never be platform-conditional.
func TestNormalizePath_IsPlatformIndependent(t *testing.T) {
	windowsReport := Finding{
		Class:    ClassCode,
		RuleID:   "sqli",
		Location: Location{Path: `backend\internal\payments\ledger.go`, StartLine: 214},
	}
	unixReport := Finding{
		Class:    ClassCode,
		RuleID:   "sqli",
		Location: Location{Path: "backend/internal/payments/ledger.go", StartLine: 214},
	}

	if windowsReport.ComputeFingerprint() != unixReport.ComputeFingerprint() {
		t.Fatalf("the same finding reported from Windows and Unix must fingerprint identically\n windows=%s\n unix   =%s",
			windowsReport.ComputeFingerprint(), unixReport.ComputeFingerprint())
	}
}
