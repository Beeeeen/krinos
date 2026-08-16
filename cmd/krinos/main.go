// Command krinos proves which security findings actually matter.
//
// It reads the reports your existing scanners already produce, collapses the
// duplicates, weighs each finding against evidence, and prints the short list
// worth a developer's afternoon.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/krinos-dev/krinos/internal/evidence"
	"github.com/krinos-dev/krinos/internal/ingest"
	"github.com/krinos-dev/krinos/internal/policy"
	"github.com/krinos-dev/krinos/internal/render"
	"github.com/krinos-dev/krinos/internal/triage"
)

// version is overwritten at release time with -ldflags "-X main.version=...".
var version = "v0.1.0-dev"

// Exit codes are part of the CLI contract. CI configurations depend on them,
// so they are documented here and must not be reassigned casually.
const (
	exitOK      = 0 // gate passed
	exitGated   = 1 // gate failed: findings at or above the threshold
	exitInvalid = 2 // usage or I/O error; the scan did not run
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return exitInvalid
	}

	switch args[0] {
	case "scan":
		return cmdScan(args[1:])
	case "version", "--version", "-V":
		fmt.Printf("krinos %s\n", version)
		fmt.Printf("report schema %s\n", render.SchemaVersion)
		fmt.Printf("bundled KEV entries %d\n", evidence.KEVSize())
		return exitOK
	case "help", "--help", "-h":
		usage(os.Stdout)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "krinos: unknown command %q\n\n", args[0])
		usage(os.Stderr)
		return exitInvalid
	}
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("krinos scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		format   = fs.String("format", "text", "output format: text or json")
		failOn   = fs.String("fail-on", "act", "gate threshold: act, watch or never")
		show     = fs.String("show", "act", "which verdicts to print: act, watch, suppressed or all")
		epssPath = fs.String("epss", "", "path to an EPSS dataset (JSON object of CVE to probability)")
		limit    = fs.Int("limit", 20, "maximum findings printed per section; 0 for no limit")
		noColor  = fs.Bool("no-color", false, "disable ANSI colour")
		color    = fs.Bool("color", false, "force ANSI colour even when redirected")
		ascii    = fs.Bool("ascii", false, "use ASCII glyphs instead of Unicode")
		ignore   stringList
	)
	fs.Var(&ignore, "ignore", "fingerprint, CVE or rule ID to drop before triage (repeatable)")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: krinos scan [flags] <report.json|directory>...")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitInvalid
	}

	inputs, err := expandInputs(fs.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "krinos: %v\n", err)
		return exitInvalid
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "krinos: no scanner reports given")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "  Point krinos at the JSON your scanners already produce:")
		fmt.Fprintln(os.Stderr, "    krinos scan trivy.json semgrep.sarif gitleaks.json")
		fmt.Fprintln(os.Stderr, "    krinos scan ./security-reports/")
		return exitInvalid
	}

	gateThreshold, err := policy.ParseVerdict(*failOn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "krinos: %v\n", err)
		return exitInvalid
	}

	findings, intake, parseErrs := ingest.ParseAll(inputs)
	// Parse failures are reported but do not abort: triaging five of six
	// reports beats triaging none because one tool wrote malformed JSON.
	for _, e := range parseErrs {
		fmt.Fprintf(os.Stderr, "krinos: warning: %v\n", e)
	}
	if len(findings) == 0 && len(parseErrs) > 0 {
		return exitInvalid
	}

	pol := policy.Policy{FailOn: gateThreshold, Ignore: ignore}
	findings, dropped := pol.Filter(findings)
	if dropped > 0 {
		fmt.Fprintf(os.Stderr, "krinos: %d finding(s) dropped by --ignore\n", dropped)
	}

	ctx := &evidence.Context{}
	if *epssPath != "" {
		epss, err := loadEPSS(*epssPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "krinos: %v\n", err)
			return exitInvalid
		}
		ctx.EPSS = epss
	}

	report := triage.NewEngine().Run(findings, ctx)
	decision := pol.Gate(report)

	switch strings.ToLower(*format) {
	case "json":
		if err := render.JSON(os.Stdout, report, intake, decision, version); err != nil {
			fmt.Fprintf(os.Stderr, "krinos: writing report: %v\n", err)
			return exitInvalid
		}
	case "text":
		term := render.Terminal{
			Style:          render.DetectStyle(os.Stdout, *color, *noColor, *ascii),
			ShowWatch:      *show == "watch" || *show == "all",
			ShowSuppressed: *show == "suppressed" || *show == "all",
			Limit:          *limit,
		}
		term.Render(os.Stdout, report, intake, decision, version)
	default:
		fmt.Fprintf(os.Stderr, "krinos: invalid --format %q: expected text or json\n", *format)
		return exitInvalid
	}

	return decision.ExitCode
}

// expandInputs resolves each argument to concrete report files, walking one
// level into directories.
//
// CI pipelines collect scanner output into a folder far more often than they
// list every file, so accepting a directory removes a whole class of
// "krinos: no such file" support tickets.
func expandInputs(args []string) ([]string, error) {
	var out []string

	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", arg, err)
		}

		if !info.IsDir() {
			out = append(out, arg)
			continue
		}

		entries, err := os.ReadDir(arg)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", arg, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			switch strings.ToLower(filepath.Ext(e.Name())) {
			case ".json", ".sarif":
				out = append(out, filepath.Join(arg, e.Name()))
			}
		}
	}

	return out, nil
}

// loadEPSS reads an EPSS dataset.
//
// EPSS is not bundled with Krinos. Its scores change daily, and shipping a
// stale probability table would make us confidently wrong — the one failure
// mode a triage tool cannot afford.
func loadEPSS(path string) (map[string]float64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading EPSS dataset: %w", err)
	}

	var raw map[string]float64
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing EPSS dataset %s: expected a JSON object mapping CVE IDs to probabilities: %w", path, err)
	}

	out := make(map[string]float64, len(raw))
	for k, v := range raw {
		out[strings.ToUpper(strings.TrimSpace(k))] = v
	}
	return out, nil
}

// stringList collects a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func usage(w *os.File) {
	fmt.Fprint(w, `krinos — prove which security findings actually matter

Your scanners find everything. Krinos tells you what to fix.

USAGE
  krinos scan [flags] <report.json|directory>...
  krinos version

EXAMPLES
  krinos scan trivy.json semgrep.sarif gitleaks.json
  krinos scan ./security-reports/
  krinos scan --fail-on watch --show all reports/
  krinos scan --format json reports/ > krinos.json

SUPPORTED INPUT
  trivy      Trivy JSON (vulnerabilities, secrets, misconfigurations)
  gitleaks   Gitleaks JSON
  sarif      SARIF 2.1.0 — Semgrep, CodeQL, Checkov, Bandit, ESLint, ...

EXIT CODES
  0  gate passed
  1  gate failed: findings at or above the threshold
  2  usage or I/O error; the scan did not run

Run "krinos scan -h" for the full flag list.
`)
}
