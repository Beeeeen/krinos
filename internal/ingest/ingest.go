// Package ingest converts vendor scanner output into normalized findings.
//
// Every adapter in here is a competitor we consume rather than compete with.
// The rule for this package is strict: nothing vendor-specific may escape it.
// If a downstream package ever needs to know which scanner produced a
// finding in order to behave correctly, the normalization is incomplete and
// the fix belongs here, not there.
package ingest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/krinos-dev/krinos/internal/model"
)

// Adapter reads one scanner's output format.
type Adapter interface {
	// Name is the format identifier shown to users, e.g. "trivy".
	Name() string
	// Detect reports whether this adapter recognizes the payload. It must be
	// cheap and must not panic on arbitrary bytes — users will point us at
	// the wrong file constantly, and that has to produce a clear message
	// rather than a stack trace.
	Detect(data []byte) bool
	// Parse converts the payload into normalized findings.
	Parse(data []byte) ([]model.Finding, error)
}

// adapters is the detection order. SARIF is last because it is the most
// permissive format: several tools emit Trivy-flavoured or Gitleaks-flavoured
// JSON that would also satisfy a loose SARIF probe.
func adapters() []Adapter {
	return []Adapter{
		Trivy{},
		Gitleaks{},
		SARIF{},
	}
}

// ErrUnrecognized is returned when no adapter claims the payload.
type ErrUnrecognized struct{ Source string }

func (e ErrUnrecognized) Error() string {
	return fmt.Sprintf("%s: unrecognized scanner output — supported formats: trivy json, gitleaks json, sarif 2.1.0", e.Source)
}

// ParseBytes normalizes a scanner payload, returning the findings and the
// name of the adapter that claimed it.
func ParseBytes(source string, data []byte) ([]model.Finding, string, error) {
	if !json.Valid(data) {
		return nil, "", fmt.Errorf("%s: not valid JSON", source)
	}

	for _, a := range adapters() {
		if !a.Detect(data) {
			continue
		}
		findings, err := a.Parse(data)
		if err != nil {
			return nil, a.Name(), fmt.Errorf("%s: parsing as %s: %w", source, a.Name(), err)
		}
		// Fingerprints are assigned centrally so that no adapter can invent
		// its own identity scheme and silently break cross-scanner dedup.
		for i := range findings {
			findings[i].Fingerprint = findings[i].ComputeFingerprint()
		}
		return findings, a.Name(), nil
	}

	return nil, "", ErrUnrecognized{Source: source}
}

// ParseFile reads and normalizes one scanner report from disk.
func ParseFile(path string) ([]model.Finding, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("reading %s: %w", path, err)
	}
	return ParseBytes(filepath.Base(path), data)
}

// ParseAll normalizes several reports, accumulating per-file errors instead
// of aborting.
//
// Failing the whole run because one of six scanner outputs was malformed is
// exactly the kind of brittleness that makes teams disable a gate. We report
// what broke and triage everything else.
func ParseAll(paths []string) (findings []model.Finding, used map[string]int, errs []error) {
	used = make(map[string]int, len(paths))
	for _, p := range paths {
		got, adapter, err := ParseFile(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		// Attribute intake to the tool, not the file format. Two SARIF files
		// from Semgrep and Grype are two scanners, and reporting them as one
		// line called "sarif" tells the user nothing about what ran.
		for _, f := range got {
			if len(f.Scanners) > 0 && f.Scanners[0] != "" {
				used[f.Scanners[0]]++
			} else {
				used[adapter]++
			}
		}
		findings = append(findings, got...)
	}
	return findings, used, errs
}

// text pulls a nested {"text": "..."} value, which SARIF uses everywhere.
type text struct {
	Text string `json:"text"`
}
