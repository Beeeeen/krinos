package evidence

import (
	"fmt"

	"github.com/Beeeeen/krinos/internal/model"
)

// Reachability asks whether the vulnerable code can be executed at all.
//
// This is the layer that does most of the noise reduction, because the
// majority of dependency CVEs sit in transitive packages whose vulnerable
// functions the project never calls.
//
// v0 reasons from dependency manifests: depth, and whether the dependency
// ships to production. That is honest structural evidence, and it is
// deliberately NOT called proof — full call-graph analysis lands in v2 and
// will report MethodCallGraph. Until then every reason string says what we
// actually did.
type Reachability struct{}

func (Reachability) Kind() Kind { return KindReachability }

func (r Reachability) Evaluate(f model.Finding, _ *Context) (Evidence, bool) {
	// Reachability is a question about dependencies. For a secret already
	// committed to the repository, or a misconfiguration already deployed,
	// there is no call path to trace — the exposure has happened.
	if f.Class != model.ClassDependency || f.Package == nil {
		return Evidence{}, false
	}

	switch {
	case f.Package.DevOnly:
		return Evidence{
			Kind:       KindReachability,
			Method:     MethodManifest,
			Multiplier: clamp(0.15),
			Reason:     "dev-only dependency — not present in the production build",
		}, true

	case f.Package.Depth == 0:
		return Evidence{
			Kind:       KindReachability,
			Method:     MethodManifest,
			Multiplier: clamp(1.0),
			Reason:     "direct dependency — your code imports this package",
		}, true

	case f.Package.Depth > 0:
		return Evidence{
			Kind:   KindReachability,
			Method: MethodManifest,
			// Each level of indirection makes an actual call path less
			// likely, but never impossible, so this decays rather than
			// collapsing to zero.
			Multiplier: clamp(0.55 / float64(f.Package.Depth)),
			Reason: fmt.Sprintf(
				"transitive dependency at depth %d — no call path proven (v0 does not trace call graphs)",
				f.Package.Depth,
			),
		}, true

	default:
		// Depth < 0: the scanner did not tell us. Absence of information is
		// not evidence of safety, so this barely moves the score.
		return Evidence{
			Kind:       KindReachability,
			Method:     MethodHeuristic,
			Multiplier: clamp(0.85),
			Reason:     "dependency depth unknown — scanner did not report it",
		}, true
	}
}
