package scanner

import "time"

// Severity represents a finding's severity level.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding represents a single security issue detected by a scanner.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Resource    string   `json:"resource"`
	File        string   `json:"file"`
	Line        int      `json:"line,omitempty"`
	Remediation string   `json:"remediation"`
	Tags        []string `json:"tags,omitempty"`
}

// Summary holds counts per severity level.
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
	Passed   int `json:"passed"`
}

// ScanResult is the top-level output of a scan run.
type ScanResult struct {
	Target    string    `json:"target"`
	ScanType  string    `json:"scan_type"`
	StartedAt time.Time `json:"started_at"`
	Duration  string    `json:"duration"`
	Findings  []Finding `json:"findings"`
	Summary   Summary   `json:"summary"`
}

// BuildSummary tallies findings by severity.
func BuildSummary(findings []Finding, passed int) Summary {
	s := Summary{Total: len(findings), Passed: passed}
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		case SeverityInfo:
			s.Info++
		}
	}
	return s
}

// FilterBySeverity returns only findings at or above the minimum severity.
func FilterBySeverity(findings []Finding, min Severity) []Finding {
	if min == "" || min == SeverityInfo {
		return findings
	}
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if SevWeight(f.Severity) >= SevWeight(min) {
			out = append(out, f)
		}
	}
	return out
}

// FilterByTags returns only findings matching at least one tag.
func FilterByTags(findings []Finding, tags []string) []Finding {
	if len(tags) == 0 {
		return findings
	}
	tagSet := make(map[string]bool, len(tags))
	for _, t := range tags {
		tagSet[t] = true
	}
	out := make([]Finding, 0)
	for _, f := range findings {
		for _, ft := range f.Tags {
			if tagSet[ft] {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// ExcludeRules removes findings whose rule ID appears in the exclude list.
func ExcludeRules(findings []Finding, exclude []string) []Finding {
	if len(exclude) == 0 {
		return findings
	}
	excludeSet := make(map[string]bool, len(exclude))
	for _, r := range exclude {
		excludeSet[r] = true
	}
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if !excludeSet[f.RuleID] {
			out = append(out, f)
		}
	}
	return out
}

// SevWeight maps a severity string to a numeric weight for comparison.
func SevWeight(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}
