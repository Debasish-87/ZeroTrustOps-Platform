package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type ruleEntry struct {
	ID       string
	Severity string
	Category string
	Title    string
	Source   string
}

var builtinRules = []ruleEntry{
	// ── Kubernetes ─────────────────────────────────────────────────────────────
	{"K8S-001", "CRITICAL", "PRIVILEGE", "hostPID enabled — container sees all host processes", "k8s"},
	{"K8S-002", "HIGH", "NETWORK_POLICY", "hostNetwork enabled — shares host network stack", "k8s"},
	{"K8S-003", "HIGH", "PRIVILEGE", "hostIPC enabled — shares host IPC namespace", "k8s"},
	{"K8S-004", "CRITICAL", "PRIVILEGE", "Privileged container — full host device access", "k8s"},
	{"K8S-005", "HIGH", "PRIVILEGE", "allowPrivilegeEscalation not set to false", "k8s"},
	{"K8S-006", "HIGH", "PRIVILEGE", "Container may run as root (runAsNonRoot missing/false)", "k8s"},
	{"K8S-007", "MEDIUM", "PRIVILEGE", "readOnlyRootFilesystem not enabled", "k8s"},
	{"K8S-008", "HIGH", "PRIVILEGE", "No securityContext defined on container", "k8s"},
	{"K8S-008-CAP", "MEDIUM", "PRIVILEGE", "Container does not drop all capabilities", "k8s"},
	{"K8S-009", "MEDIUM", "IMAGE", "Mutable :latest image tag", "k8s"},
	{"K8S-009-DIGEST", "LOW", "IMAGE", "Image not pinned by digest", "k8s"},
	{"K8S-010", "MEDIUM", "RESOURCE", "No resource requests/limits defined", "k8s"},
	{"K8S-011", "LOW", "MISCONFIGURATION", "No livenessProbe defined", "k8s"},
	{"K8S-012", "MEDIUM", "RBAC", "Service account token auto-mounted", "k8s"},
	{"K8S-020", "CRITICAL", "RBAC", "RBAC wildcard apiGroups (*)", "k8s"},
	{"K8S-021", "CRITICAL", "RBAC", "RBAC wildcard verbs (*)", "k8s"},
	{"K8S-022", "CRITICAL", "RBAC", "RBAC wildcard resources (*)", "k8s"},
	{"K8S-023", "HIGH", "RBAC", "Dangerous RBAC verb on sensitive resource", "k8s"},
	{"K8S-024", "CRITICAL", "RBAC", "Binding to cluster-admin role", "k8s"},
	{"K8S-025", "CRITICAL", "RBAC", "Binding to unauthenticated/anonymous subject", "k8s"},
	{"K8S-030", "HIGH", "SECRETS", "Potential secret stored in ConfigMap", "k8s"},
	{"K8S-031", "HIGH", "SECRETS", "Hardcoded secret in env var", "k8s"},
	{"K8S-040", "HIGH", "ENCRYPTION", "Ingress has no TLS configured", "k8s"},
	{"K8S-041", "MEDIUM", "ENCRYPTION", "TLS redirect disabled on Ingress", "k8s"},
	{"K8S-050", "INFO", "IAM", "ServiceAccount IRSA annotation — verify IAM role scope", "k8s"},
	// ── Terraform / AWS ────────────────────────────────────────────────────────
	{"TF-S3-001", "HIGH", "ENCRYPTION", "S3 bucket missing server-side encryption", "terraform"},
	{"TF-S3-002", "MEDIUM", "MISCONFIGURATION", "S3 bucket versioning not enabled", "terraform"},
	{"TF-S3-003", "LOW", "MISCONFIGURATION", "S3 access logging not enabled", "terraform"},
	{"TF-S3-010", "CRITICAL", "EXPOSURE", "S3 bucket ACL set to public", "terraform"},
	{"TF-S3-011", "HIGH", "EXPOSURE", "S3 public access block disabled", "terraform"},
	{"TF-IAM-001", "CRITICAL", "IAM", "IAM policy allows Action: * (all actions)", "terraform"},
	{"TF-IAM-002", "HIGH", "IAM", "IAM policy targets Resource: * (all resources)", "terraform"},
	{"TF-IAM-003", "HIGH", "IAM", "IAM policy uses NotAction — privilege escalation risk", "terraform"},
	{"TF-IAM-010", "MEDIUM", "IAM", "IAM user resource defined — prefer roles", "terraform"},
	{"TF-SG-001", "CRITICAL", "EXPOSURE", "Security group: sensitive port open to internet", "terraform"},
	{"TF-SG-002", "HIGH", "EXPOSURE", "Security group: ingress open to 0.0.0.0/0", "terraform"},
	{"TF-RDS-001", "HIGH", "ENCRYPTION", "RDS instance storage not encrypted", "terraform"},
	{"TF-RDS-002", "CRITICAL", "EXPOSURE", "RDS instance publicly accessible", "terraform"},
	{"TF-RDS-003", "MEDIUM", "MISCONFIGURATION", "RDS deletion protection not enabled", "terraform"},
	{"TF-RDS-004", "MEDIUM", "MISCONFIGURATION", "RDS backup retention period not configured", "terraform"},
	{"TF-EKS-001", "HIGH", "ENCRYPTION", "EKS cluster secrets not encrypted with KMS", "terraform"},
	{"TF-EKS-002", "HIGH", "EXPOSURE", "EKS API server publicly accessible", "terraform"},
	{"TF-EKS-003", "MEDIUM", "MISCONFIGURATION", "EKS control plane logging not enabled", "terraform"},
	{"TF-EC2-001", "MEDIUM", "EXPOSURE", "EC2 instance has a public IP address", "terraform"},
	{"TF-EC2-002", "HIGH", "MISCONFIGURATION", "IMDSv2 not enforced on EC2 instance", "terraform"},
	{"TF-CT-001", "MEDIUM", "MISCONFIGURATION", "CloudTrail not configured as multi-region trail", "terraform"},
	{"TF-CT-002", "MEDIUM", "MISCONFIGURATION", "CloudTrail log file validation not enabled", "terraform"},
	{"TF-CT-003", "MEDIUM", "ENCRYPTION", "CloudTrail logs not encrypted with KMS", "terraform"},
	{"TF-GCP-001", "CRITICAL", "EXPOSURE", "GCS bucket publicly accessible (allUsers)", "terraform"},
	{"TF-GCP-002", "MEDIUM", "MISCONFIGURATION", "GCS bucket versioning not enabled", "terraform"},
	{"TF-GKE-001", "CRITICAL", "RBAC", "GKE legacy ABAC enabled — bypasses RBAC", "terraform"},
	{"TF-GKE-002", "HIGH", "EXPOSURE", "GKE master not restricted by authorized networks", "terraform"},
	{"TF-AZ-001", "CRITICAL", "EXPOSURE", "Azure Storage Account allows public blob access", "terraform"},
	{"TF-AZ-002", "HIGH", "ENCRYPTION", "Azure Storage Account does not enforce TLS 1.2+", "terraform"},
	// ── Helm ───────────────────────────────────────────────────────────────────
	{"HELM-001", "LOW", "MISCONFIGURATION", "Helm chart uses deprecated apiVersion v1", "helm"},
	{"HELM-002", "LOW", "MISCONFIGURATION", "Helm chart missing version field", "helm"},
	{"HELM-010", "HIGH", "SECRETS", "Potential secret in values.yaml", "helm"},
	{"HELM-011", "MEDIUM", "IMAGE", "Mutable :latest tag in values.yaml", "helm"},
	{"HELM-012", "LOW", "MISCONFIGURATION", "Debug mode enabled in values.yaml", "helm"},
	// ── Supply Chain ───────────────────────────────────────────────────────────
	{"SC-001", "HIGH", "SUPPLY_CHAIN", "Image not pinned by digest", "supply-chain"},
	{"SC-002", "HIGH", "SUPPLY_CHAIN", "Image uses :latest tag", "supply-chain"},
	{"SC-020", "HIGH", "SUPPLY_CHAIN", "EOL base image detected", "supply-chain"},
	// ── Live AWS Posture ───────────────────────────────────────────────────────
	{"AWS-IAM-001", "CRITICAL", "IAM", "Root account has active access keys", "posture"},
	{"AWS-IAM-002", "CRITICAL", "IAM", "Root account MFA not enabled", "posture"},
	{"AWS-IAM-003", "HIGH", "IAM", "No IAM password policy configured", "posture"},
	{"AWS-IAM-004", "MEDIUM", "IAM", "Password policy minimum length < 14", "posture"},
	{"AWS-IAM-005", "MEDIUM", "IAM", "Password expiry not set or exceeds 90 days", "posture"},
	{"AWS-IAM-006", "HIGH", "IAM", "Console user without MFA", "posture"},
	{"AWS-IAM-007", "HIGH", "IAM", "Stale access key (> 90 days old)", "posture"},
	{"AWS-S3-001", "HIGH", "EXPOSURE", "S3 bucket has no public access block", "posture"},
	{"AWS-S3-002", "HIGH", "EXPOSURE", "S3 public access not fully blocked", "posture"},
	{"AWS-S3-003", "HIGH", "ENCRYPTION", "S3 bucket not encrypted at rest", "posture"},
	{"AWS-S3-004", "MEDIUM", "MISCONFIGURATION", "S3 versioning not enabled", "posture"},
	{"AWS-S3-005", "CRITICAL", "EXPOSURE", "S3 bucket policy allows public access (Principal: *)", "posture"},
}

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List all built-in detection rules",
	Long: `Display all built-in security rules in sectl.

Filter examples:
  sectl rules --source k8s
  sectl rules --source terraform
  sectl rules --source supply-chain
  sectl rules --source posture
  sectl rules --source helm
  sectl rules --severity critical`,
	RunE: runRules,
}

func init() {
	rootCmd.AddCommand(rulesCmd)
	rulesCmd.Flags().String("source", "", "Filter by source: k8s | terraform | helm | supply-chain | posture")
}

func runRules(cmd *cobra.Command, _ []string) error {
	source, _ := cmd.Flags().GetString("source")
	minSev := strings.ToUpper(viper.GetString("severity"))

	filtered := make([]ruleEntry, 0, len(builtinRules))
	for _, r := range builtinRules {
		if source != "" && r.Source != source {
			continue
		}
		if minSev != "" && minSev != "LOW" && minSev != "INFO" {
			if sevWeightStr(r.Severity) < sevWeightStr(minSev) {
				continue
			}
		}
		filtered = append(filtered, r)
	}

	sort.Slice(filtered, func(i, j int) bool {
		wi, wj := sevWeightStr(filtered[i].Severity), sevWeightStr(filtered[j].Severity)
		if wi != wj {
			return wi > wj
		}
		return filtered[i].ID < filtered[j].ID
	})

	sevColor := map[string]*color.Color{
		"CRITICAL": color.New(color.FgRed, color.Bold),
		"HIGH":     color.New(color.FgRed),
		"MEDIUM":   color.New(color.FgYellow),
		"LOW":      color.New(color.FgCyan),
		"INFO":     color.New(color.FgWhite),
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"RULE ID", "SEV", "CATEGORY", "TITLE", "SOURCE"})
	table.SetBorder(false)
	table.SetColumnSeparator("  ")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoWrapText(false)

	for _, r := range filtered {
		sev := r.Severity
		if c, ok := sevColor[sev]; ok {
			sev = c.Sprint(sev)
		}
		table.Append([]string{r.ID, sev, r.Category, r.Title, r.Source})
	}

	fmt.Printf("\n%s\n\n", color.New(color.Bold).Sprintf(
		"sectl built-in rules  (%d shown / %d total)", len(filtered), len(builtinRules)))
	table.Render()
	fmt.Println()
	return nil
}

func sevWeightStr(s string) int {
	switch s {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}
