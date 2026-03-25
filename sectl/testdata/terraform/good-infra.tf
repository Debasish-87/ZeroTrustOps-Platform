# good-infra.tf — fully hardened Terraform for sectl testing
# Expected findings: none

resource "aws_s3_bucket" "secure" {
  bucket = "my-company-secure"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
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
  target_prefix = "s3-access/"
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
  engine                  = "postgres"
  instance_class          = "db.t3.medium"
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.rds.arn
  publicly_accessible     = false
  deletion_protection     = true
  backup_retention_period = 14
  username                = "admin"
  password                = var.db_password
}

resource "aws_instance" "secure" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.micro"
  associate_public_ip_address = false
  ebs_optimized               = true
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
}

resource "aws_eks_cluster" "secure" {
  name     = "secure-cluster"
  role_arn = aws_iam_role.eks.arn
  encryption_config {
    resources = ["secrets"]
    provider { key_arn = aws_kms_key.eks.arn }
  }
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
  }
}

resource "aws_cloudtrail" "secure" {
  name                        = "secure-trail"
  s3_bucket_name              = aws_s3_bucket.cloudtrail.id
  is_multi_region_trail       = true
  log_file_validation_enabled = true
  kms_key_id                  = aws_kms_key.cloudtrail.arn
}
