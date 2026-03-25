package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const banner = `
  ╔═╗╔═╗╔═╗╔╦╗╦
  ╚═╗║╣ ║   ║ ║
  ╚═╝╚═╝╚═╝ ╩ ╩  Cloud-Native Security Enforcement Engine
  v0.1.0  │  github.com/Debasish-87/ZeroTrustOps-Platform/sectl
`

var rootCmd = &cobra.Command{
	Use:     "sectl",
	Short:   "SecTL — Cloud-Native Security Enforcement Engine",
	Version: "0.1.0",
	Long: `SecTL is a security scanning engine for Kubernetes, Terraform, Helm,
and live cloud accounts. It integrates into CI/CD pipelines as a
pre-deployment enforcement gate.

Commands:
  scan    Scan IaC files (k8s | terraform | helm | auto)
  audit   Audit live cloud account posture (AWS)
  verify  Verify container image supply chain
  rules   List all built-in detection rules`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if q, _ := cmd.Flags().GetBool("quiet"); !q {
			if cmd.Name() != "rules" && cmd.Name() != "version" && cmd.Name() != "help" {
				fmt.Println(color.CyanString(banner))
			}
		}
	},
}

// Execute is the package entry point.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, color.RedString("✗ %v", err))
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringP("output", "o", "table", "Output format: table | json | sarif")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Suppress banner and extra output")
	rootCmd.PersistentFlags().StringP("severity", "s", "low", "Minimum severity to report: critical | high | medium | low | info")
	rootCmd.PersistentFlags().Bool("fail-on-findings", false, "Exit 1 when findings are found at or above the severity threshold (use in CI)")
	rootCmd.PersistentFlags().StringSlice("tags", []string{}, "Filter findings by tag (e.g., rbac,encryption)")

	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))           //nolint:errcheck
	viper.BindPFlag("quiet", rootCmd.PersistentFlags().Lookup("quiet"))             //nolint:errcheck
	viper.BindPFlag("severity", rootCmd.PersistentFlags().Lookup("severity"))       //nolint:errcheck
	viper.BindPFlag("fail-on-findings", rootCmd.PersistentFlags().Lookup("fail-on-findings")) //nolint:errcheck
}

func initConfig() {
	home, _ := os.UserHomeDir()
	viper.AddConfigPath(home)
	viper.AddConfigPath(".")
	viper.SetConfigType("yaml")
	viper.SetConfigName(".sectl")
	viper.SetEnvPrefix("SECTL")
	viper.AutomaticEnv()
	viper.ReadInConfig() //nolint:errcheck
}
