// Package dedupe collapses the same real-world problem reported by several
// scanners into a single finding.
//
// This is the first and cheapest noise reduction in the pipeline. A team
// running Trivy, Grype and OSV-Scanner over one Go module gets the same CVE
// three times; a team that also runs Semgrep and CodeQL gets its SAST hits
// twice. None of that is new information, and all of it inflates the backlog
// number that makes people give up.
package dedupe

import (
	"sort"

	"github.com/Beeeeen/krinos/internal/model"
)

// Collapse merges findings that share a fingerprint.
//
// It returns the merged findings and the number of reports that were folded
// away. Order is deterministic: findings come back sorted by fingerprint so
// that two runs over the same input produce identical output.
func Collapse(in []model.Finding) (out []model.Finding, collapsed int) {
	if len(in) == 0 {
		return nil, 0
	}

	byPrint := make(map[string]*model.Finding, len(in))
	// Track insertion order separately rather than relying on map iteration,
	// which Go randomizes on purpose.
	order := make([]string, 0, len(in))

	for _, f := range in {
		if f.Fingerprint == "" {
			f.Fingerprint = f.ComputeFingerprint()
		}

		existing, seen := byPrint[f.Fingerprint]
		if !seen {
			cp := f
			byPrint[f.Fingerprint] = &cp
			order = append(order, f.Fingerprint)
			continue
		}

		existing.Merge(f)
		collapsed++
	}

	out = make([]model.Finding, 0, len(order))
	for _, fp := range order {
		out = append(out, *byPrint[fp])
	}

	out, reconciled := reconcileDependencies(out)
	collapsed += reconciled

	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out, collapsed
}

// reconcileDependencies folds dependency findings that carry no package
// coordinates into the finding for the same CVE that does.
//
// This exists because SARIF has no field for package coordinates. Grype and
// OSV-Scanner reporting through SARIF say "CVE-X affects this project";
// Trivy says "CVE-X in pkg@version". Those are the same problem, but the
// fingerprints cannot match because one side has nothing to key on.
//
// The merge is deliberately conservative: it happens only when the CVE maps
// to exactly one coordinate-bearing finding. A CVE affecting several packages
// gives us no honest way to choose, so those stay separate and get counted
// twice rather than attributed wrongly. Over-reporting is a nuisance;
// mis-attributing a vulnerability to the wrong package is a wrong answer.
func reconcileDependencies(in []model.Finding) (out []model.Finding, merged int) {
	anchors := make(map[string][]int)
	for i, f := range in {
		if f.Class != model.ClassDependency || f.Package.Coordinates() == "" {
			continue
		}
		if cve := f.PrimaryCVE(); cve != "" {
			anchors[cve] = append(anchors[cve], i)
		}
	}
	if len(anchors) == 0 {
		return in, 0
	}

	absorbed := make(map[int]bool, len(in))
	for i, f := range in {
		if f.Class != model.ClassDependency || f.Package.Coordinates() != "" {
			continue
		}
		cve := f.PrimaryCVE()
		if cve == "" {
			continue
		}
		candidates, ok := anchors[cve]
		if !ok || len(candidates) != 1 {
			continue
		}
		in[candidates[0]].Merge(f)
		absorbed[i] = true
		merged++
	}

	if merged == 0 {
		return in, 0
	}

	out = make([]model.Finding, 0, len(in)-merged)
	for i, f := range in {
		if absorbed[i] {
			continue
		}
		out = append(out, f)
	}
	return out, merged
}
