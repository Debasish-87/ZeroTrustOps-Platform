package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func tmpTF(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "main.tf")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanTerraform_PublicS3ACL(t *testing.T) {
	tf := `
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}
resource "aws_s3_bucket_acl" "data_acl" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}
`
	path := tmpTF(t, tf)
	findings, _, err := ScanTerraform(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(findings, "TF-S3-010") {
		t.Errorf("expected TF-S3-010 (public S3 ACL), got: %v", findingIDs(findings))
	}
}

func TestScanTerraform_WildcardIAM(t *testing.T) {
	tf := `
resource "aws_iam_policy" "admin" {
  name = "AdminPolicy"
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      "Action"   = "*"
      "Resource" = "*"
    }]
  })
}
`
	path := tmpTF(t, tf)
	findings, _, err := ScanTerraform(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(findings, "TF-IAM-001") {
		t.Errorf("expected TF-IAM-001 (Action:*), got: %v", findingIDs(findings))
	}
	if !hasRule(findings, "TF-IAM-002") {
		t.Errorf("expected TF-IAM-002 (Resource:*), got: %v", findingIDs(findings))
	}
}

func TestScanTerraform_SSHOpenToInternet(t *testing.T) {
	tf := `
resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`
	path := tmpTF(t, tf)
	findings, _, err := ScanTerraform(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(findings, "TF-SG-001") {
		t.Errorf("expected TF-SG-001 (SSH open to internet), got: %v", findingIDs(findings))
	}
}

func TestScanTerraform_PublicRDS(t *testing.T) {
	tf := `
resource "aws_db_instance" "main" {
  identifier          = "main-db"
  engine              = "mysql"
  storage_encrypted   = false
  publicly_accessible = true
}
`
	path := tmpTF(t, tf)
	findings, _, err := ScanTerraform(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(findings, "TF-RDS-002") {
		t.Errorf("expected TF-RDS-002 (public RDS), got: %v", findingIDs(findings))
	}
}

func TestScanTerraform_PublicEKS(t *testing.T) {
	tf := `
resource "aws_eks_cluster" "main" {
  name     = "prod"
  role_arn = "arn:aws:iam::123:role/eks"
  vpc_config {
    endpoint_public_access = true
  }
}
`
	path := tmpTF(t, tf)
	findings, _, err := ScanTerraform(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(findings, "TF-EKS-002") {
		t.Errorf("expected TF-EKS-002 (public EKS API), got: %v", findingIDs(findings))
	}
}

func TestScanTerraform_GoodInfra_NoHighCritical(t *testing.T) {
	tf := `
resource "aws_s3_bucket" "secure" {
  bucket = "my-secure-bucket"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.secure.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_logging" "secure" {
  bucket        = aws_s3_bucket.secure.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3/"
}
resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_db_instance" "secure" {
  identifier              = "secure-db"
  storage_encrypted       = true
  publicly_accessible     = false
  deletion_protection     = true
  backup_retention_period = 14
}
resource "aws_cloudtrail" "secure" {
  name                        = "trail"
  s3_bucket_name              = "trail-bucket"
  is_multi_region_trail       = true
  log_file_validation_enabled = true
  kms_key_id                  = "arn:aws:kms:us-east-1:123:key/abc"
}
`
	path := tmpTF(t, tf)
	findings, _, err := ScanTerraform(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh {
			t.Errorf("hardened infra should have no CRITICAL/HIGH, got %s: %s", f.RuleID, f.Title)
		}
	}
}

func TestScanTerraform_CloudTrailMisconfigured(t *testing.T) {
	tf := `
resource "aws_cloudtrail" "main" {
  name                        = "trail"
  s3_bucket_name              = "bucket"
  is_multi_region_trail       = false
  log_file_validation_enabled = false
}
`
	path := tmpTF(t, tf)
	findings, _, err := ScanTerraform(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(findings, "TF-CT-001") {
		t.Errorf("expected TF-CT-001 (multi-region trail), got: %v", findingIDs(findings))
	}
	if !hasRule(findings, "TF-CT-002") {
		t.Errorf("expected TF-CT-002 (log validation), got: %v", findingIDs(findings))
	}
}

func TestScanTerraform_NoFiles_Error(t *testing.T) {
	_, _, err := ScanTerraform("/tmp/nonexistent-xyz", nil)
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}
