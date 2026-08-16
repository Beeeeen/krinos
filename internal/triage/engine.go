// Package triage turns a pile of findings into a ranked list of decisions.
//
// This is the product. Everything else in the repository exists to feed this
// package or to display what it decided.
package triage

import (
	"sort"

	"github.com/Beeeeen/krinos/internal/dedupe"
	"github.com/Beeeeen/krinos/internal/evidence"
	"github.com/Beeeeen/krinos/internal/model"
)

// Verdict is the decision Krinos reaches about a single finding.
type Verdict string

const (
	// VerdictAct means fix this. It is the only verdict that breaks a build,
	// and the list of them should be short enough to read in a standup.
	VerdictAct Verdict = "act"
	// VerdictWatch means real but not urgent — track it, do not gate on it.
	VerdictWatch Verdict = "watch"
	// VerdictSuppress means the evidence says this cannot hurt you here.
	// Suppressed findings are never deleted, only folded away: a user must
	// always be able to ask why something was dismissed.
	VerdictSuppress Verdict = "suppress"
)

// Rank orders verdicts for sorting. Higher is more urgent.
func (v Verdict) Rank() int {
	switch v {
	case VerdictAct:
		return 3
	case VerdictWatch:
		return 2
	case VerdictSuppress:
		return 1
	default:
		return 0
	}
}

// Result is one finding after the evidence layers have had their say.
type Result struct {
	Finding  model.Finding       `json:"finding"`
	Base     float64             `json:"base_score"`
	Score    float64             `json:"score"`
	Verdict  Verdict             `json:"verdict"`
	Evidence []evidence.Evidence `json:"evidence"`
}

// Funnel records how many findings survived each stage.
//
// It is a first-class type rather than a few loose counters because it is the
// number that sells the product: "2,400 findings became 31 that matter" is
// this struct, rendered.
type Funnel struct {
	Ingested   int `json:"ingested"`   // raw reports from every scanner
	Duplicates int `json:"duplicates"` // folded away by cross-scanner dedup
	Unique     int `json:"unique"`     // distinct real-world problems
	Act        int `json:"act"`
	Watch      int `json:"watch"`
	Suppressed int `json:"suppressed"`
}

// Reduction is the fraction of everything the scanners reported that needs no
// action today, in [0,1].
//
// It is measured against Ingested rather than Unique on purpose. Ingested is
// the number the developer actually saw in their scanner output — the number
// that made them give up — so it is the only honest denominator for a claim
// about how much work we removed. Measuring against Unique would let us count
// our own dedup twice and flatter the result.
func (f Funnel) Reduction() float64 {
	if f.Ingested == 0 {
		return 0
	}
	return 1 - float64(f.Act)/float64(f.Ingested)
}

// Report is the complete output of a run.
type Report struct {
	Funnel  Funnel   `json:"funnel"`
	Results []Result `json:"results"`
}

// Acting returns just the findings that demand action, in ranked order.
func (r Report) Acting() []Result {
	out := make([]Result, 0, r.Funnel.Act)
	for _, res := range r.Results {
		if res.Verdict == VerdictAct {
			out = append(out, res)
		}
	}
	return out
}

// Engine applies the evidence layers and assigns verdicts.
type Engine struct {
	Layers []evidence.Layer

	// ActThreshold and WatchThreshold are the score cut-offs between
	// verdicts. They are fields rather than constants because enterprise
	// customers will want to tune them per-repository, and because a
	// threshold nobody can see is a threshold nobody trusts.
	ActThreshold   float64
	WatchThreshold float64
}

// NewEngine returns the engine with the default layer stack and thresholds.
func NewEngine() *Engine {
	return &Engine{
		Layers: []evidence.Layer{
			evidence.Reachability{},
			evidence.Exploitability{},
			evidence.NewBlastRadius(),
		},
		// ActThreshold sits deliberately above the base score of a plain
		// HIGH finding (70). The consequence is that severity alone never
		// breaks a build: something must argue the finding up — known
		// exploitation, a sensitive code path, a direct dependency.
		//
		// That is the entire product in one number. Set it to 70 and Krinos
		// becomes a scanner that gates on labels, which is the thing we
		// exist to replace.
		ActThreshold:   80,
		WatchThreshold: 35,
	}
}

// Run executes the full pipeline: dedup, evidence, scoring, ranking.
//
// It is deterministic. The same findings and context always produce the same
// report, byte for byte — including the order of the evidence attached to
// each result. A gate whose verdicts move on their own gets disabled by the
// first engineer it inconveniences.
func (e *Engine) Run(raw []model.Finding, ctx *evidence.Context) Report {
	if ctx == nil {
		ctx = &evidence.Context{}
	}

	unique, collapsed := dedupe.Collapse(raw)

	report := Report{
		Funnel: Funnel{
			Ingested:   len(raw),
			Duplicates: collapsed,
			Unique:     len(unique),
		},
		Results: make([]Result, 0, len(unique)),
	}

	for _, f := range unique {
		report.Results = append(report.Results, e.score(f, ctx))
	}

	for _, res := range report.Results {
		switch res.Verdict {
		case VerdictAct:
			report.Funnel.Act++
		case VerdictWatch:
			report.Funnel.Watch++
		case VerdictSuppress:
			report.Funnel.Suppressed++
		}
	}

	e.rank(report.Results)
	return report
}

// score applies every layer that has an opinion and composes the multipliers.
func (e *Engine) score(f model.Finding, ctx *evidence.Context) Result {
	base := f.Severity.BaseScore()
	// A reported CVSS is more precise than a severity band, so when we have
	// one we re-derive the band from it rather than trusting the vendor's
	// own labelling, which varies between tools for identical scores.
	if f.CVSS > 0 {
		base = model.SeverityFromCVSS(f.CVSS).BaseScore()
	}

	res := Result{Finding: f, Base: base, Score: base}

	for _, layer := range e.Layers {
		ev, ok := layer.Evaluate(f, ctx)
		if !ok {
			continue
		}
		res.Evidence = append(res.Evidence, ev)
		res.Score *= ev.Multiplier
	}

	// Evidence is sorted by layer order so the rendered explanation always
	// reads in the same sequence regardless of how the layers were stacked.
	sort.SliceStable(res.Evidence, func(i, j int) bool {
		return res.Evidence[i].Kind.Order() < res.Evidence[j].Kind.Order()
	})

	if res.Score > 100 {
		res.Score = 100
	}
	if res.Score < 0 {
		res.Score = 0
	}

	switch {
	case res.Score >= e.ActThreshold:
		res.Verdict = VerdictAct
	case res.Score >= e.WatchThreshold:
		res.Verdict = VerdictWatch
	default:
		res.Verdict = VerdictSuppress
	}

	return res
}

// rank sorts results most-urgent first, with tie-breakers chosen so the order
// is total: no two distinct findings can compare equal.
func (e *Engine) rank(results []Result) {
	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.Verdict.Rank() != b.Verdict.Rank() {
			return a.Verdict.Rank() > b.Verdict.Rank()
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Finding.Severity.Rank() != b.Finding.Severity.Rank() {
			return a.Finding.Severity.Rank() > b.Finding.Severity.Rank()
		}
		// Corroboration breaks remaining ties: three scanners agreeing beats
		// one scanner asserting.
		if len(a.Finding.Scanners) != len(b.Finding.Scanners) {
			return len(a.Finding.Scanners) > len(b.Finding.Scanners)
		}
		return a.Finding.Fingerprint < b.Finding.Fingerprint
	})
}
