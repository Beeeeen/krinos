package evidence

import (
	"strings"
	"testing"

	"github.com/Beeeeen/krinos/internal/model"
)

func dep(depth int, devOnly bool) model.Finding {
	return model.Finding{
		Class:    model.ClassDependency,
		Severity: model.SeverityCritical,
		CVEs:     []string{"CVE-2029-00001"},
		Package:  &model.Package{Ecosystem: "npm", Name: "acme", Version: "1.0.0", Depth: depth, DevOnly: devOnly},
	}
}

func TestReachability_DevOnlyIsAlmostSilenced(t *testing.T) {
	ev, ok := Reachability{}.Evaluate(dep(0, true), &Context{})
	if !ok {
		t.Fatal("expected evidence for a dependency finding")
	}
	if ev.Multiplier > 0.2 {
		t.Errorf("a dev-only dependency should be heavily discounted, got %v", ev.Multiplier)
	}
}

func TestReachability_DirectIsNeutral(t *testing.T) {
	ev, _ := Reachability{}.Evaluate(dep(0, false), &Context{})
	if ev.Multiplier != 1.0 {
		t.Errorf("a direct dependency should neither amplify nor discount, got %v", ev.Multiplier)
	}
}

func TestReachability_DecaysWithDepth(t *testing.T) {
	shallow, _ := Reachability{}.Evaluate(dep(1, false), &Context{})
	deep, _ := Reachability{}.Evaluate(dep(4, false), &Context{})

	if !(deep.Multiplier < shallow.Multiplier) {
		t.Errorf("deeper transitive dependencies must score lower: depth1=%v depth4=%v",
			shallow.Multiplier, deep.Multiplier)
	}
	if deep.Multiplier <= 0 {
		t.Error("depth must never drive the multiplier to zero — distance is not proof of safety")
	}
}

// v0 has no call-graph analysis. Every reason string it produces must say so,
// because the fastest way to lose a security audience is to imply a proof we
// did not perform.
func TestReachability_NeverClaimsProof(t *testing.T) {
	for _, f := range []model.Finding{dep(0, false), dep(3, false), dep(-1, false)} {
		ev, ok := Reachability{}.Evaluate(f, &Context{})
		if !ok {
			continue
		}
		if ev.Method == MethodCallGraph {
			t.Errorf("v0 must not report call-graph evidence: %+v", ev)
		}
		if ev.Method.Proven() && !strings.Contains(ev.Reason, "import") {
			t.Errorf("evidence marked proven must justify itself: %q", ev.Reason)
		}
	}
}

func TestReachability_SilentOnNonDependencies(t *testing.T) {
	secret := model.Finding{Class: model.ClassSecret, Severity: model.SeverityHigh}
	if _, ok := (Reachability{}).Evaluate(secret, &Context{}); ok {
		t.Fatal("a committed secret is already disclosed — reachability must have no opinion")
	}
}

func TestReachability_UnknownDepthBarelyMoves(t *testing.T) {
	ev, ok := Reachability{}.Evaluate(dep(-1, false), &Context{})
	if !ok {
		t.Fatal("expected evidence")
	}
	if ev.Multiplier < 0.7 {
		t.Errorf("missing depth data must not be treated as safety, got %v", ev.Multiplier)
	}
	if ev.Method != MethodHeuristic {
		t.Errorf("a guess must be labelled a heuristic, got %s", ev.Method)
	}
}

func TestExploitability_KEVDominates(t *testing.T) {
	f := model.Finding{Class: model.ClassDependency, CVEs: []string{"CVE-2021-44228"}}
	ev, ok := Exploitability{}.Evaluate(f, &Context{})
	if !ok {
		t.Fatal("Log4Shell must be recognized from the bundled KEV snapshot")
	}
	if ev.Multiplier < 2.0 {
		t.Errorf("known-exploited must be the strongest single signal, got %v", ev.Multiplier)
	}
	if ev.Method != MethodDataset {
		t.Errorf("KEV membership is a dataset lookup, got %s", ev.Method)
	}
}

func TestExploitability_KEVBeatsLowEPSS(t *testing.T) {
	f := model.Finding{Class: model.ClassDependency, CVEs: []string{"CVE-2021-44228"}}
	ctx := &Context{EPSS: map[string]float64{"CVE-2021-44228": 0.0001}}

	ev, _ := Exploitability{}.Evaluate(f, ctx)
	if ev.Multiplier < 2.0 {
		t.Fatal("a low EPSS must never override observed exploitation in the wild")
	}
}

func TestExploitability_EPSSBands(t *testing.T) {
	cases := []struct {
		name    string
		prob    float64
		wantMin float64
		wantMax float64
	}{
		{"high", 0.42, 1.5, 2.5},
		{"moderate", 0.05, 0.9, 1.1},
		{"negligible", 0.0002, 0.0, 0.6},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := model.Finding{Class: model.ClassDependency, CVEs: []string{"CVE-2029-99999"}}
			ctx := &Context{EPSS: map[string]float64{"CVE-2029-99999": c.prob}}
			ev, ok := Exploitability{}.Evaluate(f, ctx)
			if !ok {
				t.Fatal("expected evidence when an EPSS dataset is loaded")
			}
			if ev.Multiplier < c.wantMin || ev.Multiplier > c.wantMax {
				t.Errorf("multiplier %v outside [%v,%v]", ev.Multiplier, c.wantMin, c.wantMax)
			}
		})
	}
}

func TestExploitability_SilentWithoutData(t *testing.T) {
	noCVE := model.Finding{Class: model.ClassCode, RuleID: "sql-injection"}
	if _, ok := (Exploitability{}).Evaluate(noCVE, &Context{}); ok {
		t.Error("a SAST finding has no CVE — the layer must decline rather than invent a number")
	}

	unknownCVE := model.Finding{Class: model.ClassDependency, CVEs: []string{"CVE-2029-99999"}}
	if _, ok := (Exploitability{}).Evaluate(unknownCVE, &Context{}); ok {
		t.Error("without KEV membership or an EPSS dataset the layer must stay silent")
	}
}

// Ordering inside BlastRadius is load-bearing: dampeners run before
// amplifiers so that a hardcoded key in an auth *test fixture* is treated as
// a fixture. Reversing these two loops is how tools end up screaming about
// their own test data, so the behaviour is pinned here.
func TestBlastRadius_DampenerBeatsAmplifier(t *testing.T) {
	f := model.Finding{
		Class:    model.ClassSecret,
		Location: model.Location{Path: "internal/auth/testdata/fake_token.json"},
	}
	ev, ok := NewBlastRadius().Evaluate(f, &Context{})
	if !ok {
		t.Fatal("expected a path rule to match")
	}
	if ev.Multiplier > 0.5 {
		t.Errorf("a fixture inside an auth package is still a fixture, got %v (%s)", ev.Multiplier, ev.Reason)
	}
}

func TestBlastRadius_AmplifiesSensitivePaths(t *testing.T) {
	f := model.Finding{Class: model.ClassCode, Location: model.Location{Path: "services/payment/charge.go"}}
	ev, ok := NewBlastRadius().Evaluate(f, &Context{})
	if !ok {
		t.Fatal("expected the payment path to match")
	}
	if ev.Multiplier <= 1.0 {
		t.Errorf("the payment path must amplify, got %v", ev.Multiplier)
	}
}

func TestBlastRadius_SilentOnOrdinaryPaths(t *testing.T) {
	f := model.Finding{Class: model.ClassCode, Location: model.Location{Path: "internal/render/terminal.go"}}
	if _, ok := NewBlastRadius().Evaluate(f, &Context{}); ok {
		t.Error("an ordinary path should produce no opinion, not a neutral one")
	}
}

// Regression: a substring matcher fires "auth" on "internal/blog/author.go",
// and a tool that flags a blog module as authentication code is a tool nobody
// trusts twice. Segment-anchored matching is what prevents it.
func TestBlastRadius_DoesNotMatchSubstringsMidSegment(t *testing.T) {
	falsePositives := []string{
		"internal/blog/author.go",
		"lib/authority/registry.go",
		"cmd/tokenizer/main.go",
		"pkg/admins_report/build.go", // "admins" continues with a letter
		"web/logins_page_helper.go",
	}
	for _, p := range falsePositives {
		f := model.Finding{Class: model.ClassCode, Location: model.Location{Path: p}}
		if ev, ok := NewBlastRadius().Evaluate(f, &Context{}); ok {
			t.Errorf("%s must not match a sensitive-path rule, got %q", p, ev.Reason)
		}
	}
}

// The flip side of the regression above: real sensitive paths, including the
// naming conventions teams actually use, must still be caught.
func TestBlastRadius_MatchesRealSensitiveSegments(t *testing.T) {
	truePositives := []string{
		"internal/auth/login.go",       // exact segment
		"services/auth-service/api.go", // hyphenated
		"internal/auth.go",             // file named for the segment
		"src/payments/charge.ts",       // plural
		"api/oauth/callback.go",
		"pkg/crypto/keys.go",
	}
	for _, p := range truePositives {
		f := model.Finding{Class: model.ClassCode, Location: model.Location{Path: p}}
		ev, ok := NewBlastRadius().Evaluate(f, &Context{})
		if !ok {
			t.Errorf("%s should have matched a sensitive-path rule", p)
			continue
		}
		if ev.Multiplier <= 1.0 {
			t.Errorf("%s should amplify, got %v", p, ev.Multiplier)
		}
	}
}

func TestBlastRadius_MatchesTestSuffixes(t *testing.T) {
	for _, p := range []string{
		"internal/auth/login_test.go",
		"src/payments/charge.spec.ts",
		"api/handlers.test.js",
	} {
		f := model.Finding{Class: model.ClassCode, Location: model.Location{Path: p}}
		ev, ok := NewBlastRadius().Evaluate(f, &Context{})
		if !ok {
			t.Errorf("%s should have matched a test-suffix rule", p)
			continue
		}
		if ev.Multiplier > 0.5 {
			t.Errorf("%s is test code and should be dampened, got %v", p, ev.Multiplier)
		}
	}
}

func TestClampBoundsMultipliers(t *testing.T) {
	if got := clamp(99); got > 2.5 {
		t.Errorf("clamp must cap runaway multipliers, got %v", got)
	}
	if got := clamp(-4); got < 0 {
		t.Errorf("clamp must never produce a negative multiplier, got %v", got)
	}
}

func TestKEVSnapshotLoaded(t *testing.T) {
	if KEVSize() == 0 {
		t.Fatal("the embedded KEV snapshot failed to parse — this is a build-time defect")
	}
}
