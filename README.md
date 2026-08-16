# Krinos

**Your scanners find everything. Krinos tells you what to fix.**

[![CI](https://github.com/Beeeeen/krinos/actions/workflows/ci.yml/badge.svg)](https://github.com/Beeeeen/krinos/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/Beeeeen/krinos)](https://goreportcard.com/report/github.com/Beeeeen/krinos)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](go.mod)

You don't have a vulnerability problem. You have a
2,400-vulnerabilities-and-no-idea-which-one-matters problem.

Every security scanner your team runs is built never to miss a bug — which is
why your backlog has thousands of findings, your build gate is switched off,
and your developers stopped looking months ago.

Krinos is the open-source engine that sits on top of the scanners you already
use and proves which handful of findings are actually reachable, exploitable,
and worth breaking the build for.

```console
$ krinos scan ./security-reports/
```

```
  ── INTAKE ────────────────────────────────────────────────────────────────

    gitleaks             3
    grype                3
    semgrep              9
    trivy               16
                   ───────
                        31 reported

  ── TRIAGE ────────────────────────────────────────────────────────────────

    31 reported  → 28 unique  → 6 to act on

    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░█████████  80.6% needs no action today

  ── ACT ── 6 findings ─────────────────────────────────────────────────────

    1. CRITICAL 100  CVE-2023-4863
       libwebp@1.3.1  Heap buffer overflow in WebP decoding
       storefront/package-lock.json
       · manifest   direct dependency — your code imports this package
       ✔ dataset    CVE-2023-4863 is in the CISA KEV catalogue — actively exploited
       → fix: upgrade libwebp to 1.3.2
       confirmed by grype, trivy

    2. CRITICAL 100  stripe-access-token
       Stripe live secret key
       backend/internal/payments/config.go:7
       · path-rule  sits on the payments path — a compromise here reaches sensitive data

  ℹ 9 findings are worth tracking but do not gate the build. Show them with --show watch.
  ℹ 13 findings were suppressed with reasons. Audit them with --show suppressed.

  FAIL  6 finding(s) at or above "act" — build gated
```

---

## Why this exists

Scanners optimise for **recall** — never miss anything. Humans need
**precision** — tell me the one thing to fix. Nobody owns that gap.

Krinos does not scan. It reads the reports your scanners already produce,
collapses the duplicates, and weighs every remaining finding against evidence:

| Layer | Question | How it knows |
| --- | --- | --- |
| **Reachability** | Can the vulnerable code run at all? | Dependency manifests: direct vs transitive, production vs dev |
| **Exploitability** | Is anyone actually exploiting this? | CISA KEV membership; EPSS when you supply a dataset |
| **Blast radius** | What would a compromise reach? | Path rules — auth, payments, crypto up; tests, vendored code, fixtures down |
| **Provenance** | Who wrote this, and did anyone review it? | *v2 — see the roadmap* |

Every line of evidence Krinos prints carries the **method** that produced it.
`✔ dataset` is a fact we looked up. `· manifest` is structural evidence.
`· heuristic` is an informed guess. We will never dress a guess as a proof —
that is the fastest way to lose a security audience, and once lost it does not
come back.

## Install

```bash
go install github.com/Beeeeen/krinos/cmd/krinos@latest
```

Or grab a binary from [Releases](https://github.com/Beeeeen/krinos/releases).
Krinos is a single static binary with **zero third-party dependencies** — we
are a supply-chain security tool, so our own supply chain is the argument.

## Use it

Krinos reads whatever your pipeline already writes:

```bash
# point it at files
krinos scan trivy.json semgrep.sarif gitleaks.json

# or at the directory your CI collects reports into
krinos scan ./security-reports/

# report-only while you tune it, then turn the gate on
krinos scan --fail-on never ./reports/
krinos scan --fail-on act   ./reports/

# see everything, including what we dismissed and why
krinos scan --show all ./reports/

# machine-readable, with a versioned schema
krinos scan --format json ./reports/ > krinos.json
```

### Supported input

| Format | Produced by |
| --- | --- |
| Trivy JSON | Trivy — vulnerabilities, secrets and misconfigurations |
| Gitleaks JSON | Gitleaks |
| SARIF 2.1.0 | Semgrep, CodeQL, Checkov, Bandit, ESLint, Grype, OSV-Scanner, GitHub code scanning, … |

SARIF support is deliberate leverage: it is the closest thing this industry
has to a common tongue, so supporting it well means supporting dozens of tools
we never write an adapter for.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Gate passed |
| `1` | Gate failed — findings at or above the threshold |
| `2` | Usage or I/O error; the scan did not run |

## GitHub Action

Krinos speaks GitHub natively. One step gives you **inline annotations on the
diff**, a **job summary** on the run page, and **step outputs** the rest of
your workflow can branch on — no `jq`, no glue.

```yaml
- name: Triage security findings
  uses: Beeeeen/krinos@v0.2.0
  with:
    reports: ./security-reports
    fail-on: act
```

A complete pipeline:

```yaml
name: Security
on: [pull_request]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run the scanners you already trust
        run: |
          mkdir -p reports
          trivy fs --format json --output reports/trivy.json .
          semgrep --sarif --output reports/semgrep.sarif .
          gitleaks detect --report-format json --report-path reports/gitleaks.json

      - name: Decide what actually matters
        id: krinos
        uses: Beeeeen/krinos@v0.2.0
        with:
          reports: reports/
          fail-on: act

      - name: Tell the team
        if: always()
        run: |
          echo "${{ steps.krinos.outputs.act }} to fix, \
                ${{ steps.krinos.outputs.suppressed }} suppressed, \
                ${{ steps.krinos.outputs.reduction }}% needed no action"
```

### Adopting it without breaking anyone's Friday

Turn the gate off first. Watch the numbers for a week. Then turn it on.

```yaml
- uses: Beeeeen/krinos@v0.2.0
  with:
    reports: reports/
    soft-fail: true        # never fails the step
    show: all              # print watch and suppressed too
```

### Inputs

| Input | Default | What it does |
| --- | --- | --- |
| `reports` | `./security-reports` | Files or directories holding scanner output |
| `fail-on` | `act` | Gate threshold: `act`, `watch` or `never` |
| `soft-fail` | `false` | Never fail the step; branch on the outputs instead |
| `show` | `act` | `act`, `watch`, `suppressed` or `all` |
| `annotate` | `true` | Inline annotations on the changed lines |
| `annotate-watch` | `false` | Also annotate watch findings, as warnings |
| `ignore` | — | Fingerprints, CVEs or rule IDs to drop, one per line |
| `epss` | — | Path to an EPSS dataset |
| `json-out` | `krinos-report.json` | Where to write the machine-readable report |
| `version` | the action's ref | Pin the binary; pinning the action pins it for you |

### Outputs

`ingested` · `unique` · `duplicates` · `act` · `watch` · `suppressed` ·
`reduction` · `passed` · `report`

### Other CI

Krinos is a single binary and works anywhere:

```bash
krinos scan --format markdown reports/ > comment.md   # PR comments, chat
krinos scan --format json     reports/ > krinos.json  # dashboards
krinos scan --fail-on act     reports/                # any gate, any CI
```

Krinos runs offline. The KEV catalogue is bundled, so a scan in an air-gapped
runner behaves exactly like a scan on a laptop. The action verifies the
binary's SHA-256 against the published checksums before running it — a
security tool that installs itself over an unverified download has no business
gating anyone's build.

## Design commitments

These are not aspirations. They are tested, and the tests are named after them.

- **Deterministic.** The same inputs produce byte-identical output, always. A
  gate whose verdicts move on their own is a gate the first inconvenienced
  engineer switches off.
- **Severity alone never breaks a build.** Something must argue a finding up —
  known exploitation, a sensitive code path, a direct dependency. Otherwise we
  are just a scanner that gates on labels.
- **Nothing is deleted, only folded.** Every suppressed finding keeps the
  reason it was suppressed, and `--show suppressed` prints them all.
- **Secrets are never copied into output.** Krinos writes to CI logs and
  build artifacts. Echoing a live credential into them would make us the
  breach.
- **Ambiguity is reported, not guessed.** When a CVE could belong to several
  packages, Krinos reports it twice rather than attributing it wrongly.

## Roadmap

| Version | What lands |
| --- | --- |
| **v0.1** | Trivy / Gitleaks / SARIF ingest, dedup, three evidence layers, policy gate, JSON output |
| v0.2 | `krinos update` for the live KEV feed, `.krinos.yml` config, exceptions with expiry dates |
| v0.3 | More adapters: Grype native, OSV-Scanner native, npm audit (dev-dependency data), Checkov |
| v1.0 | Call-graph reachability for Go and JavaScript — the first evidence we will report as `call-graph` |
| v2.0 | Provenance: which lines were AI-generated, by what, and did a human review them |

## Contributing

Adapters are the highest-leverage contribution — every one makes Krinos useful
to a new audience without changing the engine. Start with
[CONTRIBUTING.md](CONTRIBUTING.md); the adapter interface is about forty lines.

## Licence

Apache 2.0. The patent grant is why: enterprise legal review reads that
clause, and MIT does not have one.

---

*Krinos — from κρίνω, to separate grain from chaff, and thereby to decide.*
