// Package evidence holds the layers that decide whether a finding matters.
//
// A scanner tells us a problem exists. An evidence layer tells us whether it
// can hurt us. Each layer is independent, returns a multiplier against the
// base score, and — critically — records *how* it knows.
package evidence

import (
	"github.com/Beeeeen/krinos/internal/model"
)

// Kind names an evidence layer.
type Kind string

const (
	KindReachability   Kind = "reachability"
	KindExploitability Kind = "exploitability"
	KindBlastRadius    Kind = "blast-radius"
	KindProvenance     Kind = "provenance"
)

// order fixes the display and application sequence so that a given input
// always produces byte-identical output. Determinism is not a nicety here:
// a security gate that flaps between runs gets switched off.
var order = map[Kind]int{
	KindReachability:   0,
	KindExploitability: 1,
	KindBlastRadius:    2,
	KindProvenance:     3,
}

// Order returns the stable sort position of a kind.
func (k Kind) Order() int { return order[k] }

// Method records how a layer reached its conclusion.
//
// This exists because the single fastest way to destroy trust in a security
// tool is to present a guess as a proof. Every piece of evidence we show a
// user carries the method that produced it, and the renderer displays it.
type Method string

const (
	// MethodCallGraph means we traced actual call paths. This is a proof.
	MethodCallGraph Method = "call-graph"
	// MethodManifest means we read declared dependency metadata. Reliable
	// about structure, silent about whether the code is ever executed.
	MethodManifest Method = "manifest"
	// MethodDataset means we looked the identifier up in a curated dataset
	// such as CISA KEV. As good as the dataset, and no better.
	MethodDataset Method = "dataset"
	// MethodPathRule means we matched a configurable path pattern.
	MethodPathRule Method = "path-rule"
	// MethodHeuristic means an informed guess. Never phrase these as proof.
	MethodHeuristic Method = "heuristic"
)

// Proven reports whether this method constitutes evidence we are willing to
// describe to a user as proof.
func (m Method) Proven() bool {
	return m == MethodCallGraph || m == MethodDataset
}

// Evidence is one layer's conclusion about one finding.
type Evidence struct {
	Kind   Kind   `json:"kind"`
	Method Method `json:"method"`

	// Multiplier scales the base score. 1.0 is neutral. Values below 1
	// argue the finding matters less than its severity suggests; above 1,
	// more.
	Multiplier float64 `json:"multiplier"`

	// Reason is shown to the user verbatim, so it is written as a sentence
	// fragment a developer can act on, not as a log line.
	Reason string `json:"reason"`
}

// Context carries everything the layers may consult. It is assembled once per
// run and treated as read-only by every layer, which is what makes the layers
// safe to evaluate concurrently later.
type Context struct {
	// Root is the repository root the scan ran against.
	Root string

	// EPSS maps a CVE ID to its exploit-prediction probability in [0,1].
	// Empty when no dataset has been loaded — layers must handle absence
	// rather than assuming zero, because "no data" is not "no risk".
	EPSS map[string]float64
}

// Layer evaluates one dimension of whether a finding matters.
//
// Evaluate returns false when the layer has nothing to say. That is a
// first-class outcome, not a failure: reachability is meaningless for a
// committed secret, and a layer that invents an opinion anyway is worse than
// one that stays quiet.
type Layer interface {
	Kind() Kind
	Evaluate(f model.Finding, ctx *Context) (Evidence, bool)
}

// clamp keeps a multiplier inside sane bounds so that no single layer can
// dominate the composite score by returning something absurd.
func clamp(v float64) float64 {
	const (
		min = 0.05
		max = 2.5
	)
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
