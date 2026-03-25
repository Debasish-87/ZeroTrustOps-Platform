package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"

	"github.com/Debasish-87/ZeroTrustOps-Platform/sectl/internal/scanner"
)

// Render dispatches to the correct output format.
func Render(format string, result scanner.ScanResult) error {
	switch format {
	case "json":
		return renderJSON(result)
	case "sarif":
		return renderSARIF(result)
	default:
		return renderTable(result)
	}
}

// ─── Table ────────────────────────────────────────────────────────────────────

func renderTable(result scanner.ScanResult) error {
	printHeader(result)

	if len(result.Findings) == 0 {
		fmt.Printf("%s  No findings above threshold. %d checks passed.\n\n",
			color.GreenString("✔"), result.Summary.Passed)
		return nil
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"RULE ID", "SEVERITY", "CATEGORY", "TITLE", "RESOURCE", "FILE"})
	table.SetBorder(false)
	table.SetColumnSeparator("  ")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoWrapText(true)
	table.SetColWidth(40)

	sevColor := map[scanner.Severity]*color.Color{
		scanner.SeverityCritical: color.New(color.FgRed, color.Bold),
		scanner.SeverityHigh:     color.New(color.FgRed),
		scanner.SeverityMedium:   color.New(color.FgYellow),
		scanner.SeverityLow:      color.New(color.FgCyan),
		scanner.SeverityInfo:     color.New(color.FgWhite),
	}

	for _, f := range result.Findings {
		sev := string(f.Severity)
		if c, ok := sevColor[f.Severity]; ok {
			sev = c.Sprint(sev)
		}
		table.Append([]string{
			f.RuleID,
			sev,
			f.Category,
			truncate(f.Title, 50),
			truncate(f.Resource, 30),
			truncate(f.File, 40),
		})
	}

	table.Render()
	printSummary(result.Summary)
	return nil
}

func printHeader(result scanner.ScanResult) {
	fmt.Printf("\n%s  Target   : %s\n", color.CyanString("▶"), color.WhiteString(result.Target))
	fmt.Printf("%s  Type     : %s\n", color.CyanString("▶"), color.WhiteString(result.ScanType))
	fmt.Printf("%s  Duration : %s\n\n", color.CyanString("▶"), color.WhiteString(result.Duration))
}

func printSummary(s scanner.Summary) {
	fmt.Printf("\n%s\n", color.New(color.Bold).Sprint("─── Summary ────────────────────────────────"))

	crit := color.New(color.FgRed, color.Bold)
	high := color.New(color.FgRed)
	med := color.New(color.FgYellow)
	low := color.New(color.FgCyan)
	info := color.New(color.FgWhite)

	fmt.Printf("  CRITICAL  %s\n", crit.Sprintf("%d", s.Critical))
	fmt.Printf("  HIGH      %s\n", high.Sprintf("%d", s.High))
	fmt.Printf("  MEDIUM    %s\n", med.Sprintf("%d", s.Medium))
	fmt.Printf("  LOW       %s\n", low.Sprintf("%d", s.Low))
	fmt.Printf("  INFO      %s\n", info.Sprintf("%d", s.Info))
	fmt.Printf("  ─────────────────\n")
	fmt.Printf("  TOTAL     %d    PASSED  %d\n\n", s.Total, s.Passed)

	if s.Critical > 0 || s.High > 0 {
		fmt.Printf("  %s  Pipeline gate: FAIL\n\n", color.RedString("✗"))
	} else {
		fmt.Printf("  %s  Pipeline gate: PASS\n\n", color.GreenString("✔"))
	}
}

// ─── JSON ─────────────────────────────────────────────────────────────────────

func renderJSON(result scanner.ScanResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// ─── SARIF ────────────────────────────────────────────────────────────────────

// sarifReport represents a minimal SARIF 2.1.0 document.
type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Help sarifMarkdown   `json:"help"`
}

type sarifMarkdown struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type sarifResult struct {
	RuleID  string          `json:"ruleId"`
	Level   string          `json:"level"`
	Message sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func renderSARIF(result scanner.ScanResult) error {
	rules := make([]sarifRule, 0)
	rulesSeen := map[string]bool{}

	sarifResults := make([]sarifResult, 0, len(result.Findings))
	for _, f := range result.Findings {
		if !rulesSeen[f.RuleID] {
			rules = append(rules, sarifRule{
				ID:   f.RuleID,
				Name: f.Title,
				Help: sarifMarkdown{
					Text:     f.Remediation,
					Markdown: "**Remediation:** " + f.Remediation,
				},
			})
			rulesSeen[f.RuleID] = true
		}

		level := "warning"
		switch f.Severity {
		case scanner.SeverityCritical, scanner.SeverityHigh:
			level = "error"
		case scanner.SeverityLow, scanner.SeverityInfo:
			level = "note"
		}

		line := f.Line
		if line == 0 {
			line = 1
		}

		sarifResults = append(sarifResults, sarifResult{
			RuleID: f.RuleID,
			Level:  level,
			Message: sarifMessage{Text: fmt.Sprintf("%s — %s", f.Title, f.Remediation)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.File},
					Region:           sarifRegion{StartLine: line},
				},
			}},
		})
	}

	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "sectl",
					Version:        "0.1.0",
					InformationURI: "https://github.com/Debasish-87/ZeroTrustOps-Platform/sectl",
					Rules:          rules,
				},
			},
			Results: sarifResults,
		}},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// ─── Utilities ────────────────────────────────────────────────────────────────

// PrintDuration returns a human-readable duration string.
func PrintDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
