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
	"github.com/Debasish-87/ZeroTrustOps-Platform/sectl/internal/supply"
)

var verifyCmd = &cobra.Command{
	Use:   "verify [image...]",
	Short: "Verify container image supply chain (digest, tag, EOL detection)",
	Long: `Check container images for supply chain risks:
  • Not pinned by digest (SC-001)
  • Using :latest tag (SC-002)
  • EOL base image detected (SC-020)

Examples:
  sectl verify nginx:latest
  sectl verify myapp:1.2.3 postgres:15-alpine
  sectl verify myregistry.io/app@sha256:abc123... --fail-on-findings`,
	Args: cobra.MinimumNArgs(1),
	RunE: runVerify,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	outputFmt := viper.GetString("output")
	minSeverity := scanner.Severity(strings.ToUpper(viper.GetString("severity")))
	failOnFindings, _ := rootCmd.PersistentFlags().GetBool("fail-on-findings")

	if !viper.GetBool("quiet") {
		fmt.Printf("%s  Verifying %d image(s)...\n\n", color.CyanString("▶"), len(args))
	}

	start := time.Now()
	findings, passed := supply.CheckImages(args)
	elapsed := time.Since(start)

	findings = scanner.FilterBySeverity(findings, minSeverity)

	result := scanner.ScanResult{
		Target:    strings.Join(args, ", "),
		ScanType:  "supply-chain",
		StartedAt: start,
		Duration:  report.PrintDuration(elapsed),
		Findings:  findings,
		Summary:   scanner.BuildSummary(findings, passed),
	}

	if err := report.Render(outputFmt, result); err != nil {
		return err
	}

	if failOnFindings && len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "\n%s  CI gate triggered: %d supply chain finding(s).\n",
			color.RedString("✗"), len(findings))
		os.Exit(1)
	}
	return nil
}
