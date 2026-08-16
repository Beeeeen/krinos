package ingest

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/Beeeeen/krinos/internal/model"
)

// SARIF reads the OASIS Static Analysis Results Interchange Format 2.1.0.
//
// SARIF is the closest thing this industry has to a common tongue: Semgrep,
// CodeQL, Checkov, Bandit, ESLint and GitHub's own code scanning all speak
// it. Supporting it well means supporting dozens of tools we never write an
// adapter for, which is the whole leverage of sitting above the scanners.
type SARIF struct{}

func (SARIF) Name() string { return "sarif" }

type sarifDoc struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription text            `json:"shortDescription"`
	FullDescription  text            `json:"fullDescription"`
	Properties       sarifProperties `json:"properties"`
	DefaultConfig    struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
}

type sarifProperties struct {
	// SecuritySeverity is a stringified CVSS-like number. GitHub, Semgrep
	// and CodeQL all use it, and it is far more precise than SARIF's own
	// three-value level enum.
	SecuritySeverity string   `json:"security-severity"`
	Tags             []string `json:"tags"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   text            `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
			EndLine   int `json:"endLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

func (SARIF) Detect(data []byte) bool {
	var probe struct {
		Version *string          `json:"version"`
		Runs    *json.RawMessage `json:"runs"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.Version != nil && probe.Runs != nil && strings.HasPrefix(*probe.Version, "2.")
}

func (s SARIF) Parse(data []byte) ([]model.Finding, error) {
	var doc sarifDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	var out []model.Finding
	for _, run := range doc.Runs {
		scanner := strings.ToLower(strings.TrimSpace(run.Tool.Driver.Name))
		if scanner == "" {
			scanner = "sarif"
		}

		rules := make(map[string]sarifRule, len(run.Tool.Driver.Rules))
		for _, r := range run.Tool.Driver.Rules {
			rules[r.ID] = r
		}

		for _, res := range run.Results {
			out = append(out, s.finding(scanner, rules, res))
		}
	}
	return out, nil
}

func (SARIF) finding(scanner string, rules map[string]sarifRule, res sarifResult) model.Finding {
	rule := rules[res.RuleID]

	f := model.Finding{
		RuleID:      res.RuleID,
		Title:       firstNonEmpty(rule.ShortDescription.Text, rule.Name, res.Message.Text, res.RuleID),
		Description: firstNonEmpty(res.Message.Text, rule.FullDescription.Text),
		Class:       classFromTags(rule.Properties.Tags),
		Scanners:    []string{scanner},
	}

	// Prefer the numeric security-severity over the coarse level enum. A
	// tool that says 9.1 is telling us more than one that says "error".
	if raw := strings.TrimSpace(rule.Properties.SecuritySeverity); raw != "" {
		if score, err := strconv.ParseFloat(raw, 64); err == nil && score > 0 {
			f.CVSS = score
			f.Severity = model.SeverityFromCVSS(score)
		}
	}
	if f.Severity == "" || f.Severity == model.SeverityUnknown {
		f.Severity = model.ParseSeverity(firstNonEmpty(res.Level, rule.DefaultConfig.Level))
	}

	if len(res.Locations) > 0 {
		phys := res.Locations[0].PhysicalLocation
		f.Location = model.Location{
			Path:      phys.ArtifactLocation.URI,
			StartLine: phys.Region.StartLine,
			EndLine:   phys.Region.EndLine,
		}
	}

	f.CVEs = extractCVEs(res.RuleID, rule.Properties.Tags)
	return f
}

// classFromTags reads the SARIF tag vocabulary that tools use to say what
// kind of problem this is. Unknown tags fall back to code, because SARIF is
// overwhelmingly a static-analysis format.
func classFromTags(tags []string) model.Class {
	for _, t := range tags {
		switch {
		case strings.Contains(strings.ToLower(t), "secret"),
			strings.Contains(strings.ToLower(t), "credential"):
			return model.ClassSecret
		case strings.Contains(strings.ToLower(t), "supply-chain"),
			strings.Contains(strings.ToLower(t), "dependency"):
			return model.ClassDependency
		case strings.Contains(strings.ToLower(t), "iac"),
			strings.Contains(strings.ToLower(t), "terraform"),
			strings.Contains(strings.ToLower(t), "kubernetes"):
			return model.ClassConfig
		case strings.Contains(strings.ToLower(t), "license"):
			return model.ClassLicense
		}
	}
	return model.ClassCode
}

// extractCVEs pulls CVE identifiers out of the rule ID and tags, which is
// where SARIF producers conventionally put them.
func extractCVEs(ruleID string, tags []string) []string {
	var out []string
	seen := map[string]struct{}{}

	for _, candidate := range append([]string{ruleID}, tags...) {
		for _, token := range strings.FieldsFunc(candidate, func(r rune) bool {
			return r == ' ' || r == ',' || r == ';' || r == '/' || r == ':'
		}) {
			up := strings.ToUpper(strings.Trim(token, ".()[]"))
			if !strings.HasPrefix(up, "CVE-") || len(up) < 9 {
				continue
			}
			if _, dup := seen[up]; dup {
				continue
			}
			seen[up] = struct{}{}
			out = append(out, up)
		}
	}
	return out
}
