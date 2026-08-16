package ingest

import (
	"strings"
	"testing"

	"github.com/krinos-dev/krinos/internal/model"
)

const trivyJSON = `{
  "SchemaVersion": 2,
  "ArtifactName": ".",
  "Results": [
    {
      "Target": "go.mod",
      "Class": "lang-pkgs",
      "Type": "gomod",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2021-44228",
          "PkgName": "example.com/log4j",
          "InstalledVersion": "2.14.1",
          "FixedVersion": "2.17.1",
          "Severity": "CRITICAL",
          "Title": "Remote code execution via JNDI",
          "Relationship": "direct",
          "CVSS": { "nvd": { "V3Score": 10.0 }, "redhat": { "V3Score": 9.8 } }
        },
        {
          "VulnerabilityID": "CVE-2029-00001",
          "PkgName": "example.com/deep",
          "InstalledVersion": "0.1.0",
          "Severity": "HIGH",
          "Relationship": "indirect"
        }
      ],
      "Secrets": [
        { "RuleID": "aws-access-key", "Category": "AWS", "Severity": "CRITICAL",
          "Title": "AWS Access Key", "StartLine": 12, "EndLine": 12 }
      ],
      "Misconfigurations": [
        { "ID": "AVD-AWS-0088", "Title": "S3 bucket is public",
          "Severity": "HIGH", "Resolution": "Set the bucket ACL to private" }
      ]
    }
  ]
}`

const sarifJSON = `{
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": {
        "name": "Semgrep",
        "rules": [
          { "id": "go.lang.security.sqli",
            "shortDescription": { "text": "SQL injection via string concatenation" },
            "properties": { "security-severity": "8.8", "tags": ["security", "cwe-89"] },
            "defaultConfiguration": { "level": "error" } },
          { "id": "generic.secrets.token",
            "shortDescription": { "text": "Hardcoded credential" },
            "properties": { "tags": ["secret"] },
            "defaultConfiguration": { "level": "warning" } }
        ]
      }},
      "results": [
        { "ruleId": "go.lang.security.sqli",
          "level": "error",
          "message": { "text": "Untrusted input flows into a query" },
          "locations": [{ "physicalLocation": {
            "artifactLocation": { "uri": "internal/payment/query.go" },
            "region": { "startLine": 42, "endLine": 44 } } }] },
        { "ruleId": "generic.secrets.token",
          "level": "warning",
          "message": { "text": "Hardcoded token" },
          "locations": [{ "physicalLocation": {
            "artifactLocation": { "uri": "testdata/sample.go" },
            "region": { "startLine": 7 } } }] }
      ]
    }
  ]
}`

const gitleaksJSON = `[
  { "Description": "AWS Access Key", "StartLine": 3, "EndLine": 3,
    "File": "config/production.yaml", "RuleID": "aws-access-token",
    "Entropy": 4.2, "Commit": "abc123", "Author": "someone" }
]`

func TestTrivy_ParsesAllThreeSections(t *testing.T) {
	got, adapter, err := ParseBytes("trivy.json", []byte(trivyJSON))
	if err != nil {
		t.Fatal(err)
	}
	if adapter != "trivy" {
		t.Fatalf("adapter: want trivy, got %s", adapter)
	}
	if len(got) != 4 {
		t.Fatalf("want 2 vulns + 1 secret + 1 misconfig = 4 findings, got %d", len(got))
	}

	byClass := map[model.Class]int{}
	for _, f := range got {
		byClass[f.Class]++
		if f.Fingerprint == "" {
			t.Errorf("every finding must leave ingest fingerprinted: %+v", f)
		}
		if len(f.Scanners) != 1 || f.Scanners[0] != "trivy" {
			t.Errorf("scanner attribution missing: %v", f.Scanners)
		}
	}
	if byClass[model.ClassDependency] != 2 || byClass[model.ClassSecret] != 1 || byClass[model.ClassConfig] != 1 {
		t.Errorf("class distribution wrong: %v", byClass)
	}
}

func TestTrivy_TakesHighestCVSSAcrossProviders(t *testing.T) {
	got, _, _ := ParseBytes("trivy.json", []byte(trivyJSON))
	for _, f := range got {
		if f.PrimaryCVE() == "CVE-2021-44228" {
			if f.CVSS != 10.0 {
				t.Fatalf("want the highest provider score 10.0, got %v", f.CVSS)
			}
			return
		}
	}
	t.Fatal("CVE-2021-44228 not found")
}

func TestTrivy_MapsRelationshipToDepth(t *testing.T) {
	got, _, _ := ParseBytes("trivy.json", []byte(trivyJSON))
	depths := map[string]int{}
	for _, f := range got {
		if f.Package != nil {
			depths[f.Package.Name] = f.Package.Depth
		}
	}
	if depths["example.com/log4j"] != 0 {
		t.Errorf("direct dependency must be depth 0, got %d", depths["example.com/log4j"])
	}
	if depths["example.com/deep"] != 1 {
		t.Errorf("indirect dependency must be depth 1, got %d", depths["example.com/deep"])
	}
}

// A scanner report is not a safe place to copy a live credential into, and
// Krinos writes its output to CI logs. The secret value must never survive
// ingest.
func TestTrivy_DoesNotCarrySecretValues(t *testing.T) {
	got, _, _ := ParseBytes("trivy.json", []byte(trivyJSON))
	for _, f := range got {
		if f.Class != model.ClassSecret {
			continue
		}
		if strings.Contains(f.Description, "AKIA") || strings.Contains(f.Title, "AKIA") {
			t.Fatal("a secret value leaked into the normalized finding")
		}
	}
}

func TestSARIF_PrefersSecuritySeverityOverLevel(t *testing.T) {
	got, adapter, err := ParseBytes("semgrep.sarif", []byte(sarifJSON))
	if err != nil {
		t.Fatal(err)
	}
	if adapter != "sarif" {
		t.Fatalf("adapter: want sarif, got %s", adapter)
	}

	for _, f := range got {
		if f.RuleID != "go.lang.security.sqli" {
			continue
		}
		if f.CVSS != 8.8 {
			t.Errorf("security-severity 8.8 should become the CVSS, got %v", f.CVSS)
		}
		if f.Severity != model.SeverityHigh {
			t.Errorf("8.8 is High, got %s", f.Severity)
		}
		if f.Location.Path != "internal/payment/query.go" || f.Location.StartLine != 42 {
			t.Errorf("location lost: %+v", f.Location)
		}
		return
	}
	t.Fatal("sqli rule not found")
}

func TestSARIF_ReadsToolNameAsScanner(t *testing.T) {
	got, _, _ := ParseBytes("x.sarif", []byte(sarifJSON))
	if len(got) == 0 || got[0].Scanners[0] != "semgrep" {
		t.Fatalf("the SARIF driver name should become the scanner attribution, got %v", got[0].Scanners)
	}
}

func TestSARIF_ClassifiesFromTags(t *testing.T) {
	got, _, _ := ParseBytes("x.sarif", []byte(sarifJSON))
	classes := map[string]model.Class{}
	for _, f := range got {
		classes[f.RuleID] = f.Class
	}
	if classes["generic.secrets.token"] != model.ClassSecret {
		t.Errorf("a rule tagged 'secret' must classify as a secret, got %s", classes["generic.secrets.token"])
	}
	if classes["go.lang.security.sqli"] != model.ClassCode {
		t.Errorf("an untagged security rule should default to code, got %s", classes["go.lang.security.sqli"])
	}
}

func TestGitleaks_Parses(t *testing.T) {
	got, adapter, err := ParseBytes("gitleaks.json", []byte(gitleaksJSON))
	if err != nil {
		t.Fatal(err)
	}
	if adapter != "gitleaks" {
		t.Fatalf("adapter: want gitleaks, got %s", adapter)
	}
	if len(got) != 1 || got[0].Class != model.ClassSecret {
		t.Fatalf("want one secret finding, got %+v", got)
	}
	// A committed credential is disclosed, not "possibly exploitable". It is
	// the one class of finding with no maybe in it, and it is graded that way.
	if got[0].Severity != model.SeverityCritical {
		t.Errorf("a committed credential is critical by construction, got %s", got[0].Severity)
	}
}

// An empty gitleaks run is a successful run reporting no secrets. It must be
// claimed by the adapter rather than falling through to "unrecognized
// format", which would turn a clean scan into a CI failure.
func TestGitleaks_EmptyArrayIsAValidReport(t *testing.T) {
	got, adapter, err := ParseBytes("gitleaks.json", []byte(`[]`))
	if err != nil {
		t.Fatalf("an empty gitleaks report must parse cleanly, got %v", err)
	}
	if adapter != "gitleaks" || len(got) != 0 {
		t.Fatalf("want gitleaks/0 findings, got %s/%d", adapter, len(got))
	}
}

func TestParseBytes_RejectsUnrecognizedFormats(t *testing.T) {
	_, _, err := ParseBytes("mystery.json", []byte(`{"hello": "world"}`))
	if err == nil {
		t.Fatal("unknown JSON must be rejected, not silently ignored")
	}
	if !strings.Contains(err.Error(), "supported formats") {
		t.Errorf("the error must tell the user what we do accept, got %q", err)
	}
}

func TestParseBytes_RejectsNonJSON(t *testing.T) {
	if _, _, err := ParseBytes("notes.txt", []byte("this is not json")); err == nil {
		t.Fatal("non-JSON input must produce a clear error")
	}
}

// Adapters must survive arbitrary bytes without panicking: users point tools
// at the wrong file constantly, and a stack trace is not an error message.
func TestAdapters_DoNotPanicOnHostileInput(t *testing.T) {
	inputs := []string{
		`null`, `[]`, `{}`, `[[[]]]`, `{"Results": null, "SchemaVersion": 2}`,
		`{"version":"2.1.0","runs":null}`, `{"version":"2.1.0","runs":[{}]}`,
		`{"SchemaVersion":2,"Results":[{"Vulnerabilities":null}]}`,
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic on input %s: %v", in, r)
				}
			}()
			_, _, _ = ParseBytes("fuzz.json", []byte(in))
		}()
	}
}

func TestParseAll_ContinuesPastABrokenReport(t *testing.T) {
	dir := t.TempDir()
	good := writeTemp(t, dir, "trivy.json", trivyJSON)
	bad := writeTemp(t, dir, "broken.json", `{"nope": true}`)

	findings, used, errs := ParseAll([]string{good, bad})

	if len(findings) == 0 {
		t.Fatal("one malformed report must not discard the others")
	}
	if len(errs) != 1 {
		t.Errorf("want exactly one reported error, got %d", len(errs))
	}
	if used["trivy"] == 0 {
		t.Error("intake accounting lost the trivy findings")
	}
}
