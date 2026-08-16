package evidence

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/krinos-dev/krinos/internal/model"
)

// PathRule raises or lowers a finding's weight based on where it sits.
//
// Rules match path *segments*, never raw substrings. That distinction was
// found by a test: a naive substring rule for "auth" also fires on
// "internal/blog/author.go", and a security tool that cries wolf over a blog
// module is a security tool nobody reads twice.
type PathRule struct {
	// Segment matches a complete path segment — a directory or file name.
	// It also matches a segment that begins with the value and continues
	// with a non-letter, so "auth" covers "auth-service" and "auth.go" but
	// never "author.go".
	Segment string

	// Suffix matches the end of the file name, for conventions like
	// "_test.go" that are not their own directory.
	Suffix string

	// Multiplier is applied when the rule matches.
	Multiplier float64

	// Label describes the zone in words a developer recognizes.
	Label string
}

// matches reports whether the rule applies to a normalized path.
func (r PathRule) matches(path string) bool {
	if r.Suffix != "" && strings.HasSuffix(path, r.Suffix) {
		return true
	}
	if r.Segment == "" {
		return false
	}

	for _, seg := range strings.Split(path, "/") {
		if seg == r.Segment {
			return true
		}
		// "auth-service" and "auth.go" are authentication code.
		// "author.go" is not: the character after the prefix decides.
		if len(seg) > len(r.Segment) && strings.HasPrefix(seg, r.Segment) {
			next := rune(seg[len(r.Segment)])
			if !unicode.IsLetter(next) {
				return true
			}
		}
	}
	return false
}

// DefaultDampeners lower the weight of findings in code that never runs in
// production. They are evaluated before amplifiers: a hardcoded key inside a
// test fixture is a test fixture, even when the path also says "auth".
//
// That ordering is the most consequential default in this file. Reversed, the
// tool spends its credibility screaming about its own test data.
var DefaultDampeners = []PathRule{
	{Segment: "testdata", Multiplier: 0.10, Label: "test fixture"},
	{Segment: "fixtures", Multiplier: 0.10, Label: "test fixture"},
	{Segment: "node_modules", Multiplier: 0.10, Label: "vendored dependency"},
	{Segment: "vendor", Multiplier: 0.10, Label: "vendored dependency"},
	{Segment: "site-packages", Multiplier: 0.10, Label: "vendored dependency"},
	{Segment: "third_party", Multiplier: 0.15, Label: "third-party source"},
	{Segment: "__tests__", Multiplier: 0.15, Label: "test code"},
	{Segment: "test", Multiplier: 0.15, Label: "test code"},
	{Segment: "tests", Multiplier: 0.15, Label: "test code"},
	{Segment: "mocks", Multiplier: 0.15, Label: "mock code"},
	{Segment: "examples", Multiplier: 0.20, Label: "example code"},
	{Segment: "example", Multiplier: 0.20, Label: "example code"},
	{Segment: "docs", Multiplier: 0.20, Label: "documentation"},
	{Suffix: "_test.go", Multiplier: 0.15, Label: "test code"},
	{Suffix: ".test.ts", Multiplier: 0.15, Label: "test code"},
	{Suffix: ".test.js", Multiplier: 0.15, Label: "test code"},
	{Suffix: ".spec.ts", Multiplier: 0.15, Label: "test code"},
	{Suffix: ".spec.js", Multiplier: 0.15, Label: "test code"},
	{Suffix: "_test.py", Multiplier: 0.15, Label: "test code"},
}

// DefaultAmplifiers raise the weight of findings sitting where a compromise
// converts directly into a breach.
//
// Plural and expanded forms are listed explicitly rather than inferred. A
// clever stemmer here would reintroduce exactly the false positives the
// segment matcher was written to remove.
var DefaultAmplifiers = []PathRule{
	{Segment: "auth", Multiplier: 1.6, Label: "authentication"},
	{Segment: "authn", Multiplier: 1.6, Label: "authentication"},
	{Segment: "authz", Multiplier: 1.6, Label: "authorization"},
	{Segment: "authentication", Multiplier: 1.6, Label: "authentication"},
	{Segment: "authorization", Multiplier: 1.6, Label: "authorization"},
	{Segment: "login", Multiplier: 1.6, Label: "authentication"},
	{Segment: "oauth", Multiplier: 1.6, Label: "authentication"},
	{Segment: "session", Multiplier: 1.6, Label: "session handling"},
	{Segment: "sessions", Multiplier: 1.6, Label: "session handling"},
	{Segment: "crypto", Multiplier: 1.6, Label: "cryptography"},
	{Segment: "secret", Multiplier: 1.6, Label: "secret handling"},
	{Segment: "secrets", Multiplier: 1.6, Label: "secret handling"},
	{Segment: "credential", Multiplier: 1.6, Label: "credential handling"},
	{Segment: "credentials", Multiplier: 1.6, Label: "credential handling"},
	{Segment: "token", Multiplier: 1.5, Label: "token handling"},
	{Segment: "tokens", Multiplier: 1.5, Label: "token handling"},
	{Segment: "payment", Multiplier: 1.6, Label: "payments"},
	{Segment: "payments", Multiplier: 1.6, Label: "payments"},
	{Segment: "billing", Multiplier: 1.5, Label: "billing"},
	{Segment: "checkout", Multiplier: 1.5, Label: "payments"},
	{Segment: "admin", Multiplier: 1.4, Label: "administrative"},
	{Segment: "pii", Multiplier: 1.5, Label: "personal data"},
	{Segment: "identity", Multiplier: 1.4, Label: "identity"},
}

// BlastRadius asks what a successful exploit would actually reach.
//
// The same CVE in an internal documentation generator and in the payment
// authorization path are not the same risk, and every tool that treats them
// identically is why nobody reads the backlog.
type BlastRadius struct {
	Dampeners  []PathRule
	Amplifiers []PathRule
}

// NewBlastRadius builds the layer with the default rule sets.
func NewBlastRadius() BlastRadius {
	return BlastRadius{Dampeners: DefaultDampeners, Amplifiers: DefaultAmplifiers}
}

func (BlastRadius) Kind() Kind { return KindBlastRadius }

func (b BlastRadius) Evaluate(f model.Finding, _ *Context) (Evidence, bool) {
	path := strings.ToLower(model.NormalizePath(f.Location.Path))
	if path == "" {
		return Evidence{}, false
	}

	for _, rule := range b.Dampeners {
		if rule.matches(path) {
			return Evidence{
				Kind:       KindBlastRadius,
				Method:     MethodPathRule,
				Multiplier: clamp(rule.Multiplier),
				Reason:     fmt.Sprintf("located in %s — not reachable from production traffic", rule.Label),
			}, true
		}
	}

	for _, rule := range b.Amplifiers {
		if rule.matches(path) {
			return Evidence{
				Kind:       KindBlastRadius,
				Method:     MethodPathRule,
				Multiplier: clamp(rule.Multiplier),
				Reason:     fmt.Sprintf("sits on the %s path — a compromise here reaches sensitive data", rule.Label),
			}, true
		}
	}

	return Evidence{}, false
}
