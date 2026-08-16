# Contributing to Krinos

Thanks for being here. This document is short on ceremony and specific about
the two or three things that are genuinely load-bearing.

## The fastest way to help

**Write an adapter.** Every scanner Krinos can read makes it useful to a new
audience without touching the engine, and the interface is about forty lines:

```go
type Adapter interface {
	Name() string
	Detect(data []byte) bool
	Parse(data []byte) ([]model.Finding, error)
}
```

Copy `internal/ingest/gitleaks.go` — it is the smallest complete example — and
register your adapter in the `adapters()` list. Then add a test with a real
report from the tool, trimmed to a handful of findings.

Wanted, roughly in order: **npm audit** (it reports dev-only dependencies,
which unlocks our strongest reachability discount), **Grype native JSON**,
**OSV-Scanner**, **Checkov**, **Snyk CLI**, **Dependency-Track**.

## Getting set up

```bash
git clone https://github.com/Beeeeen/krinos
cd krinos
make check    # lint + dependency assertion + tests
make demo     # triage the bundled corpus
```

You need Go 1.26 and nothing else. On Windows without `make`, every recipe in
the `Makefile` is a single command you can copy and run directly.

## Three rules that will get a PR sent back

These are the ones we care about. Everything else is negotiable in review.

### 1. No third-party dependencies

`go.mod` has an empty require block and CI enforces it.

We are a supply-chain security tool. A CLI that pulls in two hundred
transitive packages cannot credibly lecture anyone about transitive packages.
If you genuinely need a dependency, open an issue **before** writing the code
and make the case — the answer is not automatically no, but it needs to be
argued in `ARCHITECTURE.md`.

### 2. Never present a heuristic as a proof

Every `Evidence` value records the `Method` that produced it, and
`Method.Proven()` separates fact from inference. If your layer guesses, it
must say `MethodHeuristic`, and its `Reason` string must read like a guess.

There is a test asserting v0 never emits `MethodCallGraph`. It exists so that
when real call-graph analysis lands, `✔ call-graph` will actually mean
something.

### 3. Determinism

The same input must produce byte-identical output. Practically:

- don't iterate a map to build output — Go randomizes that on purpose
- keep sort comparators *total*, so no two distinct findings compare equal
- no timestamps, no random IDs, no wall-clock reads in the pipeline

`TestEngine_IsDeterministic` runs the engine thirty times and diffs the JSON.

## Tests

Name a test after the behaviour it protects, and put a comment above it saying
why it exists. This one is the house style:

```go
// This is the product thesis expressed as an assertion: a CRITICAL finding
// that cannot reach production must not break the build. If this test ever
// fails, Krinos has become just another scanner.
func TestEngine_SuppressesUnreachableCritical(t *testing.T) {
```

A test that only re-states the implementation is worse than no test — it
freezes a decision without recording it. Tell the next person what would
break.

Adapters additionally need a hostile-input case. Users point security tools at
the wrong file constantly; a stack trace is not an error message.

## Tuning path rules and thresholds

`DefaultDampeners`, `DefaultAmplifiers` and the score thresholds are the parts
most people will want to change, and they are the parts most likely to cause
false positives. Two things to know before you edit them:

- **Dampeners run before amplifiers.** A hardcoded key in
  `internal/auth/testdata/` is a test fixture, even though the path says
  `auth`. Do not reorder these loops.
- **Rules match path segments, not substrings.** A substring rule for `auth`
  also fires on `author.go`. List plurals and expansions explicitly rather
  than adding a stemmer — a stemmer reintroduces exactly this bug.

New rules need a test with both a true positive and a plausible false
positive.

## Commits and pull requests

Conventional-ish subject lines, imperative mood, one logical change per PR:

```
ingest: add npm audit adapter
evidence: match path rules on segments, not substrings
```

In the PR description, tell us **what would break if you were wrong**. That is
more useful to a reviewer than a summary of the diff, which we can read.

## Reporting a vulnerability

Please do not open a public issue. See [SECURITY.md](SECURITY.md).

## Conduct

Be straightforward and assume good faith. Disagree about the work, not about
the person. Maintainers will act on anything that makes this a worse place to
contribute.

## Licence

Contributions are accepted under Apache 2.0. By opening a pull request you
agree your work is licensed that way.
