package render

import (
	"encoding/json"
	"io"

	"github.com/Beeeeen/krinos/internal/policy"
	"github.com/Beeeeen/krinos/internal/triage"
)

// Document is the machine-readable shape of a run.
//
// It carries an explicit schema version because this output will end up in
// customers' dashboards and compliance pipelines, and changing its shape
// without warning would break them silently. The version is part of the
// public contract from the first release, not bolted on at the first
// breaking change.
type Document struct {
	Schema  string          `json:"schema"`
	Version string          `json:"krinos_version"`
	Intake  map[string]int  `json:"intake"`
	Funnel  triage.Funnel   `json:"funnel"`
	Gate    policy.Decision `json:"gate"`
	Results []triage.Result `json:"results"`
}

// SchemaVersion identifies the JSON output contract.
const SchemaVersion = "krinos.report/v1"

// JSON writes the machine-readable report.
func JSON(w io.Writer, r triage.Report, intake map[string]int, gate policy.Decision, version string) error {
	doc := Document{
		Schema:  SchemaVersion,
		Version: version,
		Intake:  intake,
		Funnel:  r.Funnel,
		Gate:    gate,
		Results: r.Results,
	}
	if doc.Intake == nil {
		doc.Intake = map[string]int{}
	}
	if doc.Results == nil {
		doc.Results = []triage.Result{}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Escaping HTML would mangle rule descriptions containing angle brackets,
	// which SAST rules are full of.
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}
