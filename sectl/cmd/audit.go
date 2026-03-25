package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Debasish-87/ZeroTrustOps-Platform/sectl/internal/posture"
	"github.com/Debasish-87/ZeroTrustOps-Platform/sectl/internal/report"
	"github.com/Debasish-87/ZeroTrustOps-Platform/sectl/internal/scanner"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit live cloud account posture (AWS)",
	Long: `Connect to a live cloud account and audit its current security posture.

Checks performed (AWS):
  • IAM: root access keys, MFA, password policy, stale access keys
  • IAM: console users without MFA devices
  • S3:  public access blocks, encryption, versioning, bucket policies

Pre-requisites:
  AWS credentials must be configured via:
    aws configure             (default profile)
    export AWS_PROFILE=<name> (named profile)
    export AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (env vars)

Examples:
  sectl audit --provider aws --region us-east-1
  sectl audit --provider aws --profile staging --region eu-west-1
  sectl audit --provider aws --output json --fail-on-findings
  sectl audit --provider aws --severity critical --output sarif`,
	RunE: runAudit,
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.Flags().String("provider", "aws", "Cloud provider: aws | gcp | azure")
	auditCmd.Flags().String("region", "us-east-1", "AWS region")
	auditCmd.Flags().String("profile", "", "AWS CLI profile name")
}

func runAudit(cmd *cobra.Command, args []string) error {
	provider, _ := cmd.Flags().GetString("provider")
	region, _ := cmd.Flags().GetString("region")
	profile, _ := cmd.Flags().GetString("profile")
	outputFmt := viper.GetString("output")
	minSeverity := scanner.Severity(strings.ToUpper(viper.GetString("severity")))
	failOnFindings, _ := rootCmd.PersistentFlags().GetBool("fail-on-findings")

	if !viper.GetBool("quiet") {
		fmt.Printf("%s  Provider : %s\n", color.CyanString("▶"), color.WhiteString(provider))
		fmt.Printf("%s  Region   : %s\n", color.CyanString("▶"), color.WhiteString(region))
		if profile != "" {
			fmt.Printf("%s  Profile  : %s\n", color.CyanString("▶"), color.WhiteString(profile))
		}
		fmt.Println()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	start := time.Now()

	var findings []scanner.Finding
	var sum scanner.Summary

	switch strings.ToLower(provider) {
	case "aws":
		r, err := posture.AuditAWS(ctx, profile, region)
		if err != nil {
			return fmt.Errorf("AWS audit failed: %v\n\nEnsure credentials are configured:\n  aws configure\n  export AWS_PROFILE=<profile>", err)
		}
		findings = r.Findings
		sum = r.Summary
	case "gcp", "azure":
		return fmt.Errorf("%s support coming in sectl v0.2.0", provider)
	default:
		return fmt.Errorf("unknown provider: %s (supported: aws)", provider)
	}

	elapsed := time.Since(start)
	findings = scanner.FilterBySeverity(findings, minSeverity)

	result := scanner.ScanResult{
		Target:    fmt.Sprintf("%s/%s", provider, region),
		ScanType:  "posture",
		StartedAt: start,
		Duration:  report.PrintDuration(elapsed),
		Findings:  findings,
		Summary:   sum,
	}

	if !viper.GetBool("quiet") {
		fmt.Printf("%s  Audit completed in %s\n\n", color.GreenString("✔"), report.PrintDuration(elapsed))
	}

	if err := report.Render(outputFmt, result); err != nil {
		return err
	}

	if failOnFindings && len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "\n%s  CI gate triggered: %d finding(s) above threshold.\n",
			color.RedString("✗"), len(findings))
		os.Exit(1)
	}
	return nil
}
