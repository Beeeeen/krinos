// Package policy decides whether a report should break the build.
//
// The engine decides what is true; policy decides what to do about it. They
// are separate packages because customers will want to change the second
// without ever being allowed to change the first.
package policy

import (
	"fmt"
	"strings"

	"github.com/krinos-dev/krinos/internal/model"
	"github.com/krinos-dev/krinos/internal/triage"
)

// Policy is the gate configuration for one run.
type Policy struct {
	// FailOn is the least-urgent verdict that fails the build. Empty means
	// the gate never fails, which is a legitimate configuration for teams
	// adopting Krinos in report-only mode first.
	FailOn triage.Verdict

	// Ignore holds fingerprints, CVE IDs or rule IDs to drop before triage.
	//
	// Ignores are applied at intake rather than at gate time on purpose: an
	// ignored finding should not appear in the funnel at all, because
	// counting things the team has already decided about inflates the
	// numbers we use to claim noise reduction. We will not cheat our own
	// headline metric.
	Ignore []string
}

// Decision is the outcome of the gate.
type Decision struct {
	Pass     bool   `json:"pass"`
	ExitCode int    `json:"exit_code"`
	Summary  string `json:"summary"`
}

// Filter removes findings matching the ignore list, returning the survivors
// and how many were dropped.
func (p Policy) Filter(in []model.Finding) (out []model.Finding, dropped int) {
	if len(p.Ignore) == 0 {
		return in, 0
	}

	ignore := make(map[string]struct{}, len(p.Ignore))
	for _, raw := range p.Ignore {
		if v := strings.ToUpper(strings.TrimSpace(raw)); v != "" {
			ignore[v] = struct{}{}
		}
	}

	out = make([]model.Finding, 0, len(in))
	for _, f := range in {
		if p.matches(f, ignore) {
			dropped++
			continue
		}
		out = append(out, f)
	}
	return out, dropped
}

func (Policy) matches(f model.Finding, ignore map[string]struct{}) bool {
	candidates := make([]string, 0, len(f.CVEs)+2)
	candidates = append(candidates, f.Fingerprint, f.RuleID)
	candidates = append(candidates, f.CVEs...)

	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, hit := ignore[strings.ToUpper(c)]; hit {
			return true
		}
	}
	return false
}

// Gate evaluates a report against the policy.
func (p Policy) Gate(r triage.Report) Decision {
	if p.FailOn == "" {
		return Decision{
			Pass:     true,
			ExitCode: 0,
			Summary:  "gate disabled (--fail-on never) — reporting only",
		}
	}

	var breaching int
	for _, res := range r.Results {
		if res.Verdict.Rank() >= p.FailOn.Rank() {
			breaching++
		}
	}

	if breaching == 0 {
		return Decision{
			Pass:     true,
			ExitCode: 0,
			Summary:  fmt.Sprintf("no findings at or above %q", p.FailOn),
		}
	}

	return Decision{
		Pass:     false,
		ExitCode: 1,
		Summary: fmt.Sprintf("%d finding(s) at or above %q — build gated",
			breaching, p.FailOn),
	}
}

// ParseVerdict converts a CLI value into a gate threshold. "never" disables
// the gate; anything unrecognized is an error rather than a silent default,
// because a typo in a security gate must never quietly weaken it.
func ParseVerdict(s string) (triage.Verdict, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "act":
		return triage.VerdictAct, nil
	case "watch":
		return triage.VerdictWatch, nil
	case "never", "none", "off":
		return "", nil
	default:
		return "", fmt.Errorf("invalid gate threshold %q: expected act, watch or never", s)
	}
}
