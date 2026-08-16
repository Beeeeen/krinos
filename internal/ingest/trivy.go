package ingest

import (
	"encoding/json"
	"strings"

	"github.com/Beeeeen/krinos/internal/model"
)

// Trivy reads Aqua Security's Trivy JSON report.
//
// Trivy is the most widely installed scanner in our target segment, so this
// adapter is the one that has to be right. It emits three different kinds of
// finding in one file — vulnerabilities, secrets and misconfigurations — and
// they map onto three different classes with different evidence semantics.
type Trivy struct{}

func (Trivy) Name() string { return "trivy" }

type trivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	Results       []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target            string           `json:"Target"`
	Class             string           `json:"Class"`
	Type              string           `json:"Type"`
	Vulnerabilities   []trivyVuln      `json:"Vulnerabilities"`
	Secrets           []trivySecret    `json:"Secrets"`
	Misconfigurations []trivyMisconfig `json:"Misconfigurations"`
}

type trivyVuln struct {
	VulnerabilityID  string                `json:"VulnerabilityID"`
	PkgName          string                `json:"PkgName"`
	InstalledVersion string                `json:"InstalledVersion"`
	FixedVersion     string                `json:"FixedVersion"`
	Severity         string                `json:"Severity"`
	Title            string                `json:"Title"`
	Description      string                `json:"Description"`
	Relationship     string                `json:"Relationship"`
	CVSS             map[string]trivyScore `json:"CVSS"`
}

type trivyScore struct {
	V3Score float64 `json:"V3Score"`
	V2Score float64 `json:"V2Score"`
}

type trivySecret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
}

type trivyMisconfig struct {
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Severity    string `json:"Severity"`
	Resolution  string `json:"Resolution"`
}

func (Trivy) Detect(data []byte) bool {
	var probe struct {
		SchemaVersion *int             `json:"SchemaVersion"`
		Results       *json.RawMessage `json:"Results"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.SchemaVersion != nil && probe.Results != nil
}

func (t Trivy) Parse(data []byte) ([]model.Finding, error) {
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}

	var out []model.Finding
	for _, res := range report.Results {
		for _, v := range res.Vulnerabilities {
			out = append(out, t.vulnerability(res, v))
		}
		for _, s := range res.Secrets {
			out = append(out, t.secret(res, s))
		}
		for _, m := range res.Misconfigurations {
			out = append(out, t.misconfig(res, m))
		}
	}
	return out, nil
}

func (Trivy) vulnerability(res trivyResult, v trivyVuln) model.Finding {
	f := model.Finding{
		RuleID:      v.VulnerabilityID,
		Title:       firstNonEmpty(v.Title, v.VulnerabilityID),
		Description: v.Description,
		Class:       model.ClassDependency,
		Severity:    model.ParseSeverity(v.Severity),
		Location:    model.Location{Path: res.Target},
		Scanners:    []string{"trivy"},
		Package: &model.Package{
			Ecosystem: strings.ToLower(res.Type),
			Name:      v.PkgName,
			Version:   v.InstalledVersion,
			FixedIn:   v.FixedVersion,
			Depth:     relationshipDepth(v.Relationship),
		},
	}

	if strings.HasPrefix(strings.ToUpper(v.VulnerabilityID), "CVE-") {
		f.CVEs = []string{strings.ToUpper(v.VulnerabilityID)}
	}

	// Trivy reports CVSS from several providers. Take the highest V3 score:
	// when NVD and a vendor disagree we would rather over- than under-state,
	// and let the evidence layers argue the finding back down.
	for _, score := range v.CVSS {
		if score.V3Score > f.CVSS {
			f.CVSS = score.V3Score
		}
	}

	return f
}

func (Trivy) secret(res trivyResult, s trivySecret) model.Finding {
	return model.Finding{
		RuleID: s.RuleID,
		Title:  firstNonEmpty(s.Title, s.RuleID),
		// The secret value itself is deliberately not carried into the
		// finding. Krinos writes reports to CI logs and artifacts; copying a
		// live credential into them would make us the breach.
		Description: "A credential matching " + s.Category + " was committed to the repository.",
		Class:       model.ClassSecret,
		Severity:    model.ParseSeverity(s.Severity),
		Location:    model.Location{Path: res.Target, StartLine: s.StartLine, EndLine: s.EndLine},
		Scanners:    []string{"trivy"},
	}
}

func (Trivy) misconfig(res trivyResult, m trivyMisconfig) model.Finding {
	return model.Finding{
		RuleID:      m.ID,
		Title:       firstNonEmpty(m.Title, m.ID),
		Description: firstNonEmpty(m.Resolution, m.Description),
		Class:       model.ClassConfig,
		Severity:    model.ParseSeverity(m.Severity),
		Location:    model.Location{Path: res.Target},
		Scanners:    []string{"trivy"},
	}
}

// relationshipDepth maps Trivy's dependency relationship onto our depth
// model. Trivy distinguishes direct from indirect but not how deep indirect
// goes, so every indirect dependency lands at depth 1 — which understates
// distance and therefore overstates risk. That is the safe direction to err.
func relationshipDepth(rel string) int {
	switch strings.ToLower(rel) {
	case "direct", "root", "workspace":
		return 0
	case "indirect":
		return 1
	default:
		return -1
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
