// Package model defines the normalized finding representation that every
// scanner adapter converts into.
//
// This is the narrow waist of the whole system: ingest widens outward into
// vendor formats, triage narrows inward into verdicts, and nothing past the
// ingest boundary is ever allowed to see a vendor-specific structure.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// Severity is the scanner-reported severity, normalized across vendors.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityUnknown  Severity = "unknown"
)

// Rank orders severities so findings can be sorted. Higher is worse.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// BaseScore is the starting point for triage, before any evidence is applied.
// The gaps between tiers are deliberately wide: evidence should be able to
// move a finding between tiers, but only with a strong multiplier.
func (s Severity) BaseScore() float64 {
	switch s {
	case SeverityCritical:
		return 90
	case SeverityHigh:
		return 70
	case SeverityMedium:
		return 45
	case SeverityLow:
		return 20
	case SeverityInfo:
		return 8
	default:
		return 30 // unknown sits above low: absence of data is not safety
	}
}

// ParseSeverity normalizes the many spellings vendors use. SARIF speaks in
// "error"/"warning"/"note", GitHub in "moderate", most SCA tools in CVSS
// bands. They all land here.
func ParseSeverity(raw string) Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "crit":
		return SeverityCritical
	case "high", "error", "severe":
		return SeverityHigh
	case "medium", "moderate", "warning", "warn":
		return SeverityMedium
	case "low", "note", "minor":
		return SeverityLow
	case "info", "informational", "none", "negligible":
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}

// SeverityFromCVSS maps a CVSS v3 base score onto our severity bands using
// the standard FIRST qualitative ranges.
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// Class distinguishes what kind of thing was found. It matters because the
// evidence that applies differs by class: a dependency CVE can be proven
// unreachable, a committed secret never can — it is already disclosed.
type Class string

const (
	ClassDependency Class = "dependency" // SCA: a CVE in a package we depend on
	ClassCode       Class = "code"       // SAST: a pattern in our own source
	ClassSecret     Class = "secret"     // a credential committed to the repo
	ClassConfig     Class = "config"     // IaC / cloud configuration
	ClassLicense    Class = "license"    // license policy violation
	ClassUnknown    Class = "unknown"
)

// Location is where in the repository the finding sits.
type Location struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
}

// Package identifies the dependency a ClassDependency finding belongs to.
type Package struct {
	Ecosystem string `json:"ecosystem"` // gomod, npm, pypi, maven, ...
	Name      string `json:"name"`
	Version   string `json:"version"`
	FixedIn   string `json:"fixed_in,omitempty"`

	// Depth is 0 for a direct dependency, 1 for a dependency of a direct
	// dependency, and so on. -1 means the scanner did not tell us.
	Depth int `json:"depth"`

	// DevOnly marks a dependency that never ships to production.
	DevOnly bool `json:"dev_only,omitempty"`
}

// Direct reports whether this is a first-order dependency of the project.
func (p *Package) Direct() bool { return p != nil && p.Depth == 0 }

// Coordinates renders the package as a stable identity string.
func (p *Package) Coordinates() string {
	if p == nil {
		return ""
	}
	return p.Ecosystem + "/" + p.Name + "@" + p.Version
}

// Finding is one normalized issue. Adapters produce these; everything
// downstream consumes only these.
type Finding struct {
	// Fingerprint is the stable cross-scanner identity. Two scanners
	// reporting the same real-world problem must produce the same value.
	Fingerprint string `json:"fingerprint"`

	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Class       Class    `json:"class"`
	Severity    Severity `json:"severity"`
	CVSS        float64  `json:"cvss,omitempty"`
	CVEs        []string `json:"cves,omitempty"`

	Location Location `json:"location"`
	Package  *Package `json:"package,omitempty"`

	// Scanners lists every tool that reported this finding. After dedup a
	// finding corroborated by three scanners carries all three names — that
	// corroboration is itself signal, and users want to see it.
	Scanners []string `json:"scanners"`
}

// PrimaryCVE returns the lowest-sorted CVE, or the empty string. Sorting
// makes the choice deterministic when a finding carries several.
func (f *Finding) PrimaryCVE() string {
	if len(f.CVEs) == 0 {
		return ""
	}
	ids := append([]string(nil), f.CVEs...)
	sort.Strings(ids)
	return ids[0]
}

// NormalizePath makes paths comparable across scanners running on different
// platforms and with different working directories.
//
// It deliberately does NOT use filepath.ToSlash. That function is a no-op on
// Unix, and these paths arrive inside scanner reports — they are data, not
// paths on the machine running Krinos. A Trivy report generated on a Windows
// developer's laptop and triaged on a Linux runner must normalize to the same
// string, or two things break silently: fingerprints diverge so cross-scanner
// dedup stops folding anything, and every path rule stops matching because
// the blast-radius layer splits on "/".
//
// Cross-platform CI caught this. It passed on Windows.
func NormalizePath(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), `\`, "/")
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	return p
}

// ComputeFingerprint derives the cross-scanner identity for a finding.
//
// The important subtlety is in the dependency case: it deliberately ignores
// the file path. Trivy reports a Go CVE against "go.sum", Grype reports it
// against the module path, and OSV-Scanner against "go.mod" — three paths,
// one real-world problem. Keying on package coordinates plus CVE is what
// collapses them into a single finding instead of three.
func (f *Finding) ComputeFingerprint() string {
	var parts []string

	switch f.Class {
	case ClassDependency:
		parts = []string{
			string(ClassDependency),
			f.Package.Coordinates(),
			f.PrimaryCVE(),
		}
	default:
		// For everything anchored in our own source, the path and rule are
		// the identity. The line number is included because two instances of
		// the same rule in one file are two things to fix.
		parts = []string{
			string(f.Class),
			NormalizePath(f.Location.Path),
			strings.ToLower(f.RuleID),
			strconv.Itoa(f.Location.StartLine),
		}
	}

	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])[:16]
}

// Merge folds another report of the same finding into f. It is called when
// two scanners agree, and it keeps the most useful field from each: the
// worst severity, the richest package metadata, the union of CVEs.
//
// Merge assumes both findings share a fingerprint; callers must check.
func (f *Finding) Merge(other Finding) {
	if other.Severity.Rank() > f.Severity.Rank() {
		f.Severity = other.Severity
	}
	if other.CVSS > f.CVSS {
		f.CVSS = other.CVSS
	}
	if f.Description == "" {
		f.Description = other.Description
	}
	if f.Title == "" {
		f.Title = other.Title
	}

	f.CVEs = mergeStrings(f.CVEs, other.CVEs)
	f.Scanners = mergeStrings(f.Scanners, other.Scanners)

	// Prefer whichever side actually knows the dependency depth, and never
	// lose a known fix version.
	if other.Package != nil {
		if f.Package == nil {
			f.Package = other.Package
		} else {
			if f.Package.Depth < 0 && other.Package.Depth >= 0 {
				f.Package.Depth = other.Package.Depth
			}
			if f.Package.FixedIn == "" {
				f.Package.FixedIn = other.Package.FixedIn
			}
			f.Package.DevOnly = f.Package.DevOnly || other.Package.DevOnly
		}
	}

	// A finding with a real location beats one without.
	if f.Location.Path == "" && other.Location.Path != "" {
		f.Location = other.Location
	}
}

// mergeStrings returns the sorted, de-duplicated union of two slices.
func mergeStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string(nil), a...), b...) {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
