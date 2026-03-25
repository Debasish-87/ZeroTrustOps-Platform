package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ScanTerraform scans a path (file or directory) for Terraform misconfigurations.
func ScanTerraform(path string, excludeRules []string) ([]Finding, int, error) {
	var findings []Finding
	passed := 0

	files, err := collectTFFiles(path)
	if err != nil {
		return nil, 0, err
	}
	if len(files) == 0 {
		return nil, 0, fmt.Errorf("no .tf files found at %s", path)
	}

	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		founds, p := checkTFFile(string(content), f)
		findings = append(findings, founds...)
		passed += p
	}

	findings = ExcludeRules(findings, excludeRules)
	return findings, passed, nil
}

func collectTFFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("path not found: %s", path)
	}
	if !info.IsDir() && strings.HasSuffix(path, ".tf") {
		return []string{path}, nil
	}
	var files []string
	err = filepath.Walk(path, func(p string, i os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if !i.IsDir() && strings.HasSuffix(p, ".tf") {
			files = append(files, p)
		}
		return nil
	})
	return files, err
}

// ─── Resource block parser ────────────────────────────────────────────────────

type tfResource struct {
	Type   string
	Name   string
	Body   string
	File   string
	lineNo int
}

var resourceRegex = regexp.MustCompile(`resource\s+"([^"]+)"\s+"([^"]+)"\s+\{`)

func parseTFResources(content, file string) []tfResource {
	var resources []tfResource
	scanner := bufio.NewScanner(strings.NewReader(content))
	lines := []string{}
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	i := 0
	for i < len(lines) {
		m := resourceRegex.FindStringSubmatch(lines[i])
		if m != nil {
			rtype := m[1]
			rname := m[2]
			// collect body until matching closing brace
			depth := 0
			var body strings.Builder
			startLine := i
			for j := i; j < len(lines); j++ {
				line := lines[j]
				depth += strings.Count(line, "{") - strings.Count(line, "}")
				body.WriteString(line + "\n")
				if depth <= 0 {
					i = j
					break
				}
			}
			resources = append(resources, tfResource{
				Type:   rtype,
				Name:   rname,
				Body:   body.String(),
				File:   file,
				lineNo: startLine + 1,
			})
		}
		i++
	}
	return resources
}

// ─── Main check dispatcher ────────────────────────────────────────────────────

func checkTFFile(content, file string) ([]Finding, int) {
	resources := parseTFResources(content, file)
	var findings []Finding
	passed := 0

	for _, r := range resources {
		var f []Finding
		var p int
		switch r.Type {
		case "aws_s3_bucket":
			f, p = checkS3Bucket(r, resources, content)
		case "aws_s3_bucket_acl":
			f, p = checkS3ACL(r)
		case "aws_s3_bucket_public_access_block":
			f, p = checkS3PublicBlock(r)
		case "aws_iam_policy", "aws_iam_role_policy":
			f, p = checkIAMPolicy(r, content)
		case "aws_iam_user":
			f, p = checkIAMUser(r)
		case "aws_security_group":
			f, p = checkSecurityGroup(r)
		case "aws_db_instance":
			f, p = checkRDS(r)
		case "aws_instance":
			f, p = checkEC2(r)
		case "aws_eks_cluster":
			f, p = checkEKS(r)
		case "aws_cloudtrail":
			f, p = checkCloudTrail(r)
		case "google_storage_bucket":
			f, p = checkGCSBucket(r)
		case "google_container_cluster":
			f, p = checkGKE(r)
		case "azurerm_storage_account":
			f, p = checkAzureStorage(r)
		}
		findings = append(findings, f...)
		passed += p
	}
	return findings, passed
}

// ─── AWS S3 ───────────────────────────────────────────────────────────────────

func checkS3Bucket(r tfResource, allResources []tfResource, content string) ([]Finding, int) {
	var findings []Finding
	passed := 0

	// TF-S3-001: Check for server-side encryption
	hasEncryption := false
	bucketID := fmt.Sprintf("aws_s3_bucket.%s.id", r.Name)
	for _, res := range allResources {
		if res.Type == "aws_s3_bucket_server_side_encryption_configuration" &&
			strings.Contains(res.Body, bucketID) {
			hasEncryption = true
			break
		}
	}
	if !hasEncryption {
		findings = append(findings, tfFinding("TF-S3-001", SeverityHigh, "ENCRYPTION",
			"S3 bucket missing server-side encryption",
			"Add an aws_s3_bucket_server_side_encryption_configuration resource targeting this bucket.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	// TF-S3-002: Versioning
	hasVersioning := false
	for _, res := range allResources {
		if res.Type == "aws_s3_bucket_versioning" && strings.Contains(res.Body, bucketID) {
			if strings.Contains(res.Body, `"Enabled"`) || strings.Contains(res.Body, "Enabled") {
				hasVersioning = true
			}
		}
	}
	if !hasVersioning {
		findings = append(findings, tfFinding("TF-S3-002", SeverityMedium, "MISCONFIGURATION",
			"S3 bucket versioning not enabled",
			"Add an aws_s3_bucket_versioning resource with status = Enabled.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	// TF-S3-003: Access logging
	hasLogging := false
	for _, res := range allResources {
		if res.Type == "aws_s3_bucket_logging" && strings.Contains(res.Body, bucketID) {
			hasLogging = true
		}
	}
	if !hasLogging {
		findings = append(findings, tfFinding("TF-S3-003", SeverityLow, "MISCONFIGURATION",
			"S3 access logging not enabled",
			"Add an aws_s3_bucket_logging resource to track bucket access.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	return findings, passed
}

func checkS3ACL(r tfResource) ([]Finding, int) {
	// TF-S3-010: Public ACL
	publicACLs := []string{`"public-read"`, `"public-read-write"`, `"authenticated-read"`}
	for _, acl := range publicACLs {
		if strings.Contains(r.Body, acl) {
			return []Finding{tfFinding("TF-S3-010", SeverityCritical, "EXPOSURE",
				fmt.Sprintf("S3 bucket ACL set to %s", strings.Trim(acl, `"`)),
				"Change the ACL to private and use bucket policies for access control.",
				r.Type+"."+r.Name, r.File)}, 0
		}
	}
	return nil, 1
}

func checkS3PublicBlock(r tfResource) ([]Finding, int) {
	// TF-S3-011: Public access block disabled
	if containsTFBool(r.Body, "block_public_acls", false) ||
		containsTFBool(r.Body, "block_public_policy", false) ||
		containsTFBool(r.Body, "restrict_public_buckets", false) {
		return []Finding{tfFinding("TF-S3-011", SeverityHigh, "EXPOSURE",
			"S3 public access block settings are disabled",
			"Set all public access block attributes to true.",
			r.Type+"."+r.Name, r.File)}, 0
	}
	return nil, 1
}

// ─── AWS IAM ──────────────────────────────────────────────────────────────────

func checkIAMPolicy(r tfResource, _ string) ([]Finding, int) {
	var findings []Finding
	passed := 0

	// TF-IAM-001: Action: *
	if strings.Contains(r.Body, `"Action"`) && strings.Contains(r.Body, `"*"`) {
		findings = append(findings, tfFinding("TF-IAM-001", SeverityCritical, "IAM",
			"IAM policy allows Action: * (all actions)",
			"Restrict Actions to the specific operations required by the workload.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	// TF-IAM-002: Resource: *
	if strings.Contains(r.Body, `"Resource"`) && strings.Contains(r.Body, `"*"`) {
		findings = append(findings, tfFinding("TF-IAM-002", SeverityHigh, "IAM",
			"IAM policy targets Resource: * (all resources)",
			"Restrict the Resource ARN to specific resources.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	// TF-IAM-003: NotAction
	if strings.Contains(r.Body, "NotAction") {
		findings = append(findings, tfFinding("TF-IAM-003", SeverityHigh, "IAM",
			"IAM policy uses NotAction — privilege escalation risk",
			"Replace NotAction with explicit Allow Actions to avoid unintended access.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	return findings, passed
}

func checkIAMUser(r tfResource) ([]Finding, int) {
	// TF-IAM-010: IAM user resource — prefer roles
	return []Finding{tfFinding("TF-IAM-010", SeverityMedium, "IAM",
		"IAM user resource defined — prefer roles",
		"Use IAM roles instead of long-lived IAM users with access keys.",
		r.Type+"."+r.Name, r.File)}, 0
}

// ─── AWS Security Groups ──────────────────────────────────────────────────────

func checkSecurityGroup(r tfResource) ([]Finding, int) {
	var findings []Finding
	passed := 0

	sensitivePortPatterns := []struct {
		port int
		name string
	}{
		{22, "SSH"},
		{3389, "RDP"},
		{3306, "MySQL"},
		{5432, "PostgreSQL"},
		{6379, "Redis"},
		{27017, "MongoDB"},
	}

	// Check ingress rules
	ingressBlocks := extractBlocks(r.Body, "ingress")
	for _, block := range ingressBlocks {
		fromPort := extractIntValue(block, "from_port")
		toPort := extractIntValue(block, "to_port")
		cidrBlocks := block

		isPublic := strings.Contains(cidrBlocks, `"0.0.0.0/0"`) || strings.Contains(cidrBlocks, `"::/0"`)

		if isPublic {
			for _, sp := range sensitivePortPatterns {
				if fromPort <= sp.port && sp.port <= toPort {
					findings = append(findings, tfFinding("TF-SG-001", SeverityCritical, "EXPOSURE",
						fmt.Sprintf("Security group: %s port (%d) open to internet", sp.name, sp.port),
						fmt.Sprintf("Restrict %s (port %d) access to specific CIDR blocks, not 0.0.0.0/0.", sp.name, sp.port),
						r.Type+"."+r.Name, r.File))
				}
			}

			// Any port open to the world
			if fromPort == 0 && toPort == 65535 {
				findings = append(findings, tfFinding("TF-SG-002", SeverityHigh, "EXPOSURE",
					"Security group: all ports open to internet",
					"Restrict ingress to specific ports and CIDR ranges.",
					r.Type+"."+r.Name, r.File))
			} else if fromPort > 0 {
				findings = append(findings, tfFinding("TF-SG-002", SeverityHigh, "EXPOSURE",
					fmt.Sprintf("Security group: port %d open to 0.0.0.0/0", fromPort),
					"Restrict ingress rules to known IP ranges.",
					r.Type+"."+r.Name, r.File))
			}
		} else {
			passed++
		}
	}

	return findings, passed
}

// ─── AWS RDS ──────────────────────────────────────────────────────────────────

func checkRDS(r tfResource) ([]Finding, int) {
	var findings []Finding
	passed := 0

	// TF-RDS-001: Storage not encrypted
	if containsTFBool(r.Body, "storage_encrypted", false) || !strings.Contains(r.Body, "storage_encrypted") {
		findings = append(findings, tfFinding("TF-RDS-001", SeverityHigh, "ENCRYPTION",
			"RDS instance storage not encrypted",
			"Set storage_encrypted = true and specify a kms_key_id.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	// TF-RDS-002: Publicly accessible
	if containsTFBool(r.Body, "publicly_accessible", true) {
		findings = append(findings, tfFinding("TF-RDS-002", SeverityCritical, "EXPOSURE",
			"RDS instance publicly accessible",
			"Set publicly_accessible = false and access the database via private subnets.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	// TF-RDS-003: Deletion protection
	if !strings.Contains(r.Body, "deletion_protection") || containsTFBool(r.Body, "deletion_protection", false) {
		findings = append(findings, tfFinding("TF-RDS-003", SeverityMedium, "MISCONFIGURATION",
			"RDS deletion protection not enabled",
			"Set deletion_protection = true to prevent accidental deletion.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	// TF-RDS-004: Backup retention
	if !strings.Contains(r.Body, "backup_retention_period") {
		findings = append(findings, tfFinding("TF-RDS-004", SeverityMedium, "MISCONFIGURATION",
			"RDS backup retention period not configured",
			"Set backup_retention_period to at least 7 days.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	return findings, passed
}

// ─── AWS EC2 ──────────────────────────────────────────────────────────────────

func checkEC2(r tfResource) ([]Finding, int) {
	var findings []Finding
	passed := 0

	// TF-EC2-001: Public IP
	if containsTFBool(r.Body, "associate_public_ip_address", true) {
		findings = append(findings, tfFinding("TF-EC2-001", SeverityMedium, "EXPOSURE",
			"EC2 instance has a public IP address",
			"Place EC2 instances in private subnets and use NAT Gateway for outbound traffic.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	// TF-EC2-002: IMDSv2 not enforced
	if !strings.Contains(r.Body, "metadata_options") ||
		(!strings.Contains(r.Body, `"required"`) && !strings.Contains(r.Body, "required")) {
		findings = append(findings, tfFinding("TF-EC2-002", SeverityHigh, "MISCONFIGURATION",
			"IMDSv2 not enforced on EC2 instance",
			"Add metadata_options { http_tokens = \"required\" } to enforce IMDSv2.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	return findings, passed
}

// ─── AWS EKS ──────────────────────────────────────────────────────────────────

func checkEKS(r tfResource) ([]Finding, int) {
	var findings []Finding
	passed := 0

	// TF-EKS-001: Secrets not encrypted with KMS
	if !strings.Contains(r.Body, "encryption_config") {
		findings = append(findings, tfFinding("TF-EKS-001", SeverityHigh, "ENCRYPTION",
			"EKS cluster secrets not encrypted with KMS",
			"Add an encryption_config block targeting the secrets resource with a KMS key.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	// TF-EKS-002: Public API server
	if containsTFBool(r.Body, "endpoint_public_access", true) {
		findings = append(findings, tfFinding("TF-EKS-002", SeverityHigh, "EXPOSURE",
			"EKS API server publicly accessible without CIDR restriction",
			"Set endpoint_public_access = false or restrict public_access_cidrs.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	// TF-EKS-003: Control plane logging
	if !strings.Contains(r.Body, "enabled_cluster_log_types") {
		findings = append(findings, tfFinding("TF-EKS-003", SeverityMedium, "MISCONFIGURATION",
			"EKS control plane logging not enabled",
			"Set enabled_cluster_log_types = [\"api\", \"audit\", \"authenticator\", \"controllerManager\", \"scheduler\"].",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	return findings, passed
}

// ─── AWS CloudTrail ───────────────────────────────────────────────────────────

func checkCloudTrail(r tfResource) ([]Finding, int) {
	var findings []Finding
	passed := 0

	// TF-CT-001: Multi-region
	if !strings.Contains(r.Body, "is_multi_region_trail") || containsTFBool(r.Body, "is_multi_region_trail", false) {
		findings = append(findings, tfFinding("TF-CT-001", SeverityMedium, "MISCONFIGURATION",
			"CloudTrail not configured as multi-region trail",
			"Set is_multi_region_trail = true to capture events in all regions.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	// TF-CT-002: Log file validation
	if !strings.Contains(r.Body, "log_file_validation_enabled") || containsTFBool(r.Body, "log_file_validation_enabled", false) {
		findings = append(findings, tfFinding("TF-CT-002", SeverityMedium, "MISCONFIGURATION",
			"CloudTrail log file validation not enabled",
			"Set log_file_validation_enabled = true to detect log tampering.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	// TF-CT-003: KMS encryption
	if !strings.Contains(r.Body, "kms_key_id") {
		findings = append(findings, tfFinding("TF-CT-003", SeverityMedium, "ENCRYPTION",
			"CloudTrail logs not encrypted with KMS",
			"Add kms_key_id to encrypt CloudTrail logs at rest.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	return findings, passed
}

// ─── GCP ─────────────────────────────────────────────────────────────────────

func checkGCSBucket(r tfResource) ([]Finding, int) {
	if strings.Contains(r.Body, "allUsers") || strings.Contains(r.Body, "allAuthenticatedUsers") {
		return []Finding{tfFinding("TF-GCP-001", SeverityCritical, "EXPOSURE",
			"GCS bucket publicly accessible (allUsers / allAuthenticatedUsers)",
			"Remove public IAM bindings and use Uniform Bucket-Level Access.",
			r.Type+"."+r.Name, r.File)}, 0
	}
	return nil, 1
}

func checkGKE(r tfResource) ([]Finding, int) {
	var findings []Finding
	passed := 0

	if containsTFBool(r.Body, "enable_legacy_abac", true) {
		findings = append(findings, tfFinding("TF-GKE-001", SeverityCritical, "RBAC",
			"GKE legacy ABAC enabled — bypasses RBAC",
			"Set enable_legacy_abac = false.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	if !strings.Contains(r.Body, "master_authorized_networks_config") {
		findings = append(findings, tfFinding("TF-GKE-002", SeverityHigh, "EXPOSURE",
			"GKE master not restricted by authorized networks",
			"Add master_authorized_networks_config to restrict API server access.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	return findings, passed
}

// ─── Azure ────────────────────────────────────────────────────────────────────

func checkAzureStorage(r tfResource) ([]Finding, int) {
	var findings []Finding
	passed := 0

	if containsTFBool(r.Body, "allow_blob_public_access", true) || strings.Contains(r.Body, "allow_nested_items_to_be_public = true") {
		findings = append(findings, tfFinding("TF-AZ-001", SeverityCritical, "EXPOSURE",
			"Azure Storage Account allows public blob access",
			"Set allow_blob_public_access = false.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	if !strings.Contains(r.Body, "min_tls_version") || strings.Contains(r.Body, `"TLS1_0"`) || strings.Contains(r.Body, `"TLS1_1"`) {
		findings = append(findings, tfFinding("TF-AZ-002", SeverityHigh, "ENCRYPTION",
			"Azure Storage Account does not enforce TLS 1.2+",
			"Set min_tls_version = \"TLS1_2\" and enable_https_traffic_only = true.",
			r.Type+"."+r.Name, r.File))
	} else {
		passed++
	}

	return findings, passed
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func tfFinding(id string, sev Severity, category, title, remediation, resource, file string) Finding {
	return Finding{
		RuleID:      id,
		Severity:    sev,
		Category:    category,
		Title:       title,
		Description: title,
		Resource:    resource,
		File:        file,
		Remediation: remediation,
		Tags:        []string{"terraform", strings.ToLower(category)},
	}
}

// containsTFBool checks if a Terraform body sets a given key to a specific bool value.
func containsTFBool(body, key string, val bool) bool {
	re := regexp.MustCompile(key + `\s*=\s*(true|false)`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		return false
	}
	return (m[1] == "true") == val
}

// extractBlocks extracts named blocks (e.g., ingress) from a resource body.
func extractBlocks(body, blockName string) []string {
	re := regexp.MustCompile(blockName + `\s*\{([^}]+)\}`)
	matches := re.FindAllString(body, -1)
	return matches
}

// extractIntValue extracts an integer value for a key from a block string.
func extractIntValue(block, key string) int {
	re := regexp.MustCompile(key + `\s*=\s*(\d+)`)
	m := re.FindStringSubmatch(block)
	if m == nil {
		return 0
	}
	v, _ := strconv.Atoi(m[1])
	return v
}
