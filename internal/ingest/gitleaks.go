package ingest

import (
	"encoding/json"

	"github.com/krinos-dev/krinos/internal/model"
)

// Gitleaks reads the Gitleaks JSON report.
//
// Secrets get their own adapter because they invert the usual triage logic.
// Every other class of finding asks "can this be reached?" — a committed
// credential is already disclosed to everyone who ever cloned the repository,
// so the only honest answer is that it must be rotated. The evidence layers
// know not to argue with that, and this adapter's job is to hand them a
// finding shaped correctly for that treatment.
type Gitleaks struct{}

func (Gitleaks) Name() string { return "gitleaks" }

type gitleaksFinding struct {
	Description string  `json:"Description"`
	StartLine   int     `json:"StartLine"`
	EndLine     int     `json:"EndLine"`
	File        string  `json:"File"`
	RuleID      string  `json:"RuleID"`
	Entropy     float64 `json:"Entropy"`
	Commit      string  `json:"Commit"`
	Author      string  `json:"Author"`
	Date        string  `json:"Date"`
}

func (Gitleaks) Detect(data []byte) bool {
	// Gitleaks emits a bare JSON array. An empty array is a legitimate
	// gitleaks report meaning "no secrets found", so it must be claimed
	// rather than falling through to the unrecognized-format error.
	var probe []gitleaksFinding
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	if len(probe) == 0 {
		return true
	}
	return probe[0].RuleID != "" && probe[0].File != ""
}

func (Gitleaks) Parse(data []byte) ([]model.Finding, error) {
	var raw []gitleaksFinding
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	out := make([]model.Finding, 0, len(raw))
	for _, g := range raw {
		out = append(out, model.Finding{
			RuleID: g.RuleID,
			Title:  firstNonEmpty(g.Description, g.RuleID),
			// The matched secret is never copied into the finding.
			Description: "A credential was committed to version control and must be treated as disclosed. Rotate it, then remove it from history.",
			Class:       model.ClassSecret,
			// Gitleaks does not grade its own findings, so we grade them.
			//
			// Critical, not high: every other class of finding carries a
			// "maybe" — maybe the code path is reachable, maybe someone
			// writes an exploit. A credential in version control has no
			// maybe. It is disclosed to everyone who has ever cloned the
			// repository, and it stays disclosed after the commit is
			// reverted. The only open question is blast radius, and that is
			// the blast-radius layer's job — including dampening the ones
			// that turn out to live in test fixtures.
			Severity: model.SeverityCritical,
			Location: model.Location{Path: g.File, StartLine: g.StartLine, EndLine: g.EndLine},
			Scanners: []string{"gitleaks"},
		})
	}
	return out, nil
}
