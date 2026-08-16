# Architecture

This document explains why Krinos is shaped the way it is. It is written for
the person who has to change it — including future us.

## The shape

```
  scanner reports (vendor JSON)
            │
            ▼
    ┌───────────────┐   the narrow waist: nothing vendor-specific
    │    ingest     │   escapes this boundary
    └───────┬───────┘
            │  []model.Finding
            ▼
    ┌───────────────┐   collapse the same problem reported N times
    │    dedupe     │
    └───────┬───────┘
            │  []model.Finding  (unique)
            ▼
    ┌───────────────┐   reachability · exploitability · blast radius
    │   evidence    │   each layer independent, each records its method
    └───────┬───────┘
            │  []evidence.Evidence
            ▼
    ┌───────────────┐   compose multipliers → score → verdict → rank
    │    triage     │   THIS IS THE PRODUCT
    └───────┬───────┘
            │  triage.Report
            ├──────────────┐
            ▼              ▼
    ┌───────────────┐  ┌───────────────┐
    │    policy     │  │    render     │
    │  (gate/exit)  │  │ (terminal/json)│
    └───────────────┘  └───────────────┘
```

`cmd/krinos` wires these together and owns nothing else. If logic accumulates
in `main.go`, it belongs in a package.

## The rules

### 1. Zero third-party dependencies

`go.mod` has an empty require block, and that is a product decision, not
minimalism for its own sake.

We are a supply-chain security tool. Every dependency we take is a dependency
our users inherit, and an argument we lose the first time a customer runs
Krinos on Krinos. A CLI that pulls in two hundred transitive packages cannot
credibly lecture anyone about transitive packages.

Practically this costs us a CLI framework and a colour library. Both are a few
hundred lines of standard library. That is a good trade.

Adding a dependency requires justification in this file and approval in
review.

### 2. Ingest is a one-way valve

Nothing downstream of `internal/ingest` may know which scanner produced a
finding *in order to behave correctly*. Findings carry scanner names for
display and corroboration, never for control flow.

If a triage rule ever needs `if scanner == "trivy"`, the normalization is
incomplete and the fix belongs in the adapter.

### 3. Determinism is a product requirement

Same input, byte-identical output. Every time.

This constrains real code:

- `dedupe` tracks insertion order in a slice rather than iterating its map,
  because Go randomizes map iteration deliberately.
- `triage.rank` uses a *total* order — verdict, score, severity, corroboration
  count, then fingerprint — so no two distinct findings can compare equal.
- Evidence is sorted by layer order before rendering.

There is a test that runs the engine fifty times and diffs the JSON. Keep it.

A security gate whose verdicts drift between runs gets disabled by the first
engineer it inconveniences at 6pm on a Friday, and it never gets re-enabled.

### 4. Never present a heuristic as a proof

`evidence.Method` exists solely for this. Every piece of evidence records how
it was reached, `Method.Proven()` distinguishes fact from inference, and the
renderer marks them differently (`✔` versus `·`).

v0 has no call-graph analysis, so no v0 evidence may report
`MethodCallGraph` — there is a test asserting exactly that. When real
reachability lands in v1.0, that test is what makes the upgrade meaningful:
`✔ call-graph` will mean something because `· manifest` was honest.

### 5. Suppression is folding, never deleting

A suppressed finding keeps its evidence and stays in the report. `--show
suppressed` prints every one with the reason. A user must always be able to
ask "why did you dismiss that?" and get an answer.

The day we cannot answer that question is the day we become a tool that hides
vulnerabilities.

## Key decisions, and what they cost

### Fingerprints ignore the path for dependency findings

Trivy reports a Go CVE against `go.sum`. Grype reports it against the module
path. OSV-Scanner reports it against `go.mod`. Three paths, one problem.

`Finding.ComputeFingerprint` therefore keys dependency findings on
`ecosystem/name@version` plus the primary CVE, and ignores the location
entirely. It looks like a bug to anyone reading it cold, which is why there is
a test named after the behaviour.

**Cost:** two vulnerabilities in the same package version that share a CVE
alias collapse into one. Acceptable — they have the same fix.

### Dependency reconciliation for SARIF

SARIF has no field for package coordinates, so Grype-via-SARIF produces
dependency findings with no package at all. Those can never fingerprint-match
Trivy's.

`dedupe.reconcileDependencies` runs a second pass folding coordinate-less
dependency findings into the finding for the same CVE that *does* have
coordinates — but **only when exactly one candidate exists**. When a CVE
affects several packages, there is no honest way to choose, so they stay
separate.

**Cost:** ambiguous cases are counted twice. Deliberate. Over-reporting is a
nuisance; mis-attributing a vulnerability to the wrong package is a wrong
answer, and wrong answers are how a triage tool dies.

### Dampeners run before amplifiers

In `evidence.BlastRadius`, the test/vendor/fixture rules are evaluated before
the auth/payments/crypto rules. A hardcoded key inside
`internal/auth/testdata/` is a test fixture, even though the path also says
`auth`.

Reversed, the tool spends its credibility screaming about its own test data.

### Path rules match segments, not substrings

A substring rule for `auth` also fires on `internal/blog/author.go`. That
false positive was found by a test during Sprint 1 and is now pinned by
`TestBlastRadius_DoesNotMatchSubstringsMidSegment`.

`PathRule.matches` compares whole path segments, plus segments that begin with
the value and continue with a non-letter — so `auth` covers `auth-service` and
`auth.go` but never `author.go`. Plurals and expansions are listed explicitly
rather than stemmed, because a clever stemmer reintroduces exactly the class
of bug the segment matcher removed.

### The ACT threshold sits above a plain HIGH

`Engine.ActThreshold` is 80. `SeverityHigh.BaseScore()` is 70.

The gap is the whole product. Severity alone can never break a build;
something must argue the finding up. Set the threshold to 70 and Krinos
becomes a scanner that gates on vendor labels — the thing we exist to replace.

### KEV is bundled, EPSS is not

KEV membership is a binary fact that changes slowly, so a bundled snapshot is
useful offline on day one and `krinos update` refreshes it.

EPSS is a numeric probability that changes daily. Shipping a stale table would
make us *confidently wrong*, which is the one failure mode a triage tool
cannot survive. Users supply it with `--epss`, or the layer stays silent.

Absence of data is never treated as absence of risk: the reachability layer
scores unknown dependency depth at 0.85, not 0.

### Reduction is measured against Ingested, not Unique

`Funnel.Reduction()` divides by `Ingested` — the number the developer actually
saw in their scanner output, the number that made them give up.

Dividing by `Unique` would let us count our own dedup twice and flatter the
headline. We will not cheat our own metric.

## Where the gaps are

Known and deliberate, so nobody rediscovers them as bugs:

- **`Package.DevOnly` is rarely populated.** Trivy's JSON does not report
  dev-only dependencies, so the strongest reachability discount only fires for
  adapters that do (npm audit, planned for v0.3). The field and the logic are
  in place waiting for the data.
- **No call-graph reachability.** v0 reasons from manifests. Labelled as such
  everywhere.
- **Provenance layer is defined but unimplemented.** `KindProvenance` exists
  in the evidence taxonomy with no layer behind it, so the interface does not
  have to change in v2.
- **No config file.** Thresholds and path rules are exported struct fields but
  not yet loadable from `.krinos.yml`. That is v0.2.
- **Terminal width is fixed at 74 columns.** Detecting it needs either a
  dependency or per-platform syscalls; neither is worth it before someone
  complains.

## Testing philosophy

Tests are named after the behaviour they protect, and the comment above each
one says why it exists. `TestEngine_SuppressesUnreachableCritical` is not a
unit test — it is the product thesis expressed as an assertion. If it ever
fails, Krinos has become just another scanner.

Adapters are fuzzed against hostile input (`TestAdapters_DoNotPanicOnHostileInput`)
because users point security tools at the wrong file constantly, and a stack
trace is not an error message.
