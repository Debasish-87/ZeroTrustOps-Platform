package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Debasish-87/ZeroTrustOps-Platform/sectl/internal/report"
	"github.com/Debasish-87/ZeroTrustOps-Platform/sectl/internal/scanner"
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan IaC files for security misconfigurations",
	Long: `Scan Kubernetes manifests, Terraform files, or Helm charts for security
misconfigurations before they reach production.

The scanner returns a binary PASS/FAIL signal via exit code:
  0 = PASS (no findings at or above severity threshold)
  1 = FAIL (findings found — use as a pipeline gate)

Examples:
  sectl scan ./manifests --type k8s
  sectl scan ./manifests --type k8s --severity high --fail-on-findings
  sectl scan ./infra/ --type terraform
  sectl scan ./infra/ --type terraform --output json > reports/sectl/tf.json
  sectl scan ./charts/myapp --type helm
  sectl scan ./deploy.yaml --type k8s --exclude-rules K8S-011,K8S-009-DIGEST
  sectl scan . --type auto --output sarif > results.sarif`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringP("type", "t", "auto", "IaC type: k8s | terraform | helm | auto")
	scanCmd.Flags().StringSlice("exclude-rules", []string{}, "Comma-separated rule IDs to skip (e.g. K8S-011,K8S-009-DIGEST)")
}

func runScan(cmd *cobra.Command, args []string) error {
	path := args[0]
	iacType, _ := cmd.Flags().GetString("type")
	outputFmt := viper.GetString("output")
	minSeverity := scanner.Severity(strings.ToUpper(viper.GetString("severity")))
	failOnFindings, _ := rootCmd.PersistentFlags().GetBool("fail-on-findings")
	tags, _ := rootCmd.PersistentFlags().GetStringSlice("tags")
	excludeRules, _ := cmd.Flags().GetStringSlice("exclude-rules")

	if iacType == "auto" {
		iacType = detectIaCType(path)
		if !viper.GetBool("quiet") {
			fmt.Printf("%s  Auto-detected type: %s\n", color.CyanString("▶"), color.WhiteString(iacType))
		}
	}

	if !viper.GetBool("quiet") {
		fmt.Printf("%s  Scanning : %s\n", color.CyanString("▶"), color.WhiteString(path))
		fmt.Printf("%s  Type     : %s\n", color.CyanString("▶"), color.WhiteString(iacType))
		fmt.Printf("%s  Min sev  : %s\n\n", color.CyanString("▶"), color.WhiteString(string(minSeverity)))
	}

	start := time.Now()
	var findings []scanner.Finding
	var passed int
	var err error

	switch iacType {
	case "k8s", "kubernetes":
		findings, passed, err = scanner.ScanK8s(path, excludeRules)
	case "terraform", "tf":
		findings, passed, err = scanner.ScanTerraform(path, excludeRules)
	case "helm":
		findings, passed, err = scanner.ScanHelm(path, excludeRules)
	default:
		return fmt.Errorf("unknown IaC type: %s (supported: k8s, terraform, helm, auto)", iacType)
	}

	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	elapsed := time.Since(start)

	// Apply filters
	findings = scanner.FilterBySeverity(findings, minSeverity)
	if len(tags) > 0 {
		findings = scanner.FilterByTags(findings, tags)
	}

	result := scanner.ScanResult{
		Target:    path,
		ScanType:  iacType,
		StartedAt: start,
		Duration:  report.PrintDuration(elapsed),
		Findings:  findings,
		Summary:   scanner.BuildSummary(findings, passed),
	}

	if err := report.Render(outputFmt, result); err != nil {
		return fmt.Errorf("render failed: %w", err)
	}

	// CI gate: exit 1 if findings above threshold
	if failOnFindings && len(findings) > 0 {
		if !viper.GetBool("quiet") {
			fmt.Fprintf(os.Stderr, "\n%s  CI gate triggered: %d finding(s) at or above %s severity.\n",
				color.RedString("✗"), len(findings), minSeverity)
		}
		os.Exit(1)
	}

	return nil
}

// detectIaCType infers the IaC type from file extensions in the path.
func detectIaCType(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "k8s"
	}

	if !info.IsDir() {
		switch {
		case strings.HasSuffix(path, ".tf"):
			return "terraform"
		case strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml"):
			return "k8s"
		}
		return "k8s"
	}

	// Walk directory and score file types
	tfCount, yamlCount := 0, 0
	hasChartYAML := false

	_ = walkDir(path, func(p string) {
		switch {
		case strings.HasSuffix(p, ".tf"):
			tfCount++
		case strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml"):
			yamlCount++
			if strings.HasSuffix(p, "Chart.yaml") || strings.HasSuffix(p, "Chart.yml") {
				hasChartYAML = true
			}
		}
	})

	if hasChartYAML {
		return "helm"
	}
	if tfCount > yamlCount {
		return "terraform"
	}
	return "k8s"
}

func walkDir(path string, fn func(string)) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		fn(path)
		return nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, e := range entries {
		child := path + "/" + e.Name()
		if e.IsDir() {
			walkDir(child, fn) //nolint:errcheck
		} else {
			fn(child)
		}
	}
	return nil
}
