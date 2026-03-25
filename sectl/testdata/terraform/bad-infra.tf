# bad-infra.tf — intentionally misconfigured for sectl testing
# Expected: TF-S3-010, TF-S3-011, TF-IAM-001, TF-IAM-002, TF-IAM-010,
#           TF-SG-001, TF-SG-002, TF-RDS-001, TF-RDS-002, TF-EKS-002, TF-CT-001, TF-CT-002

resource "aws_s3_bucket" "data" {
  bucket = "my-company-data"
}

resource "aws_s3_bucket_acl" "data_acl" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"               # TF-S3-010 CRITICAL
}

resource "aws_s3_bucket_public_access_block" "data_pab" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false       # TF-S3-011 HIGH
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_iam_policy" "admin" {
  name = "AdminPolicy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      "Action"   = "*"                  # TF-IAM-001 CRITICAL
      "Resource" = "*"                  # TF-IAM-002 HIGH
    }]
  })
}

resource "aws_iam_user" "svc" {         # TF-IAM-010 MEDIUM
  name = "my-service-user"
}

resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 22                    # TF-SG-001 CRITICAL — SSH open to internet
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 3389                  # TF-SG-001 CRITICAL — RDP open to internet
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  identifier          = "main-db"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = "insecurepassword"
  storage_encrypted   = false            # TF-RDS-001 HIGH
  publicly_accessible = true             # TF-RDS-002 CRITICAL
}

resource "aws_eks_cluster" "main" {
  name     = "production"
  role_arn = "arn:aws:iam::123456789:role/eks-role"
  vpc_config {
    subnet_ids             = ["subnet-abc123"]
    endpoint_public_access = true         # TF-EKS-002 HIGH
  }
}

resource "aws_cloudtrail" "main" {
  name                        = "main-trail"
  s3_bucket_name              = "my-cloudtrail-bucket"
  is_multi_region_trail       = false     # TF-CT-001 MEDIUM
  log_file_validation_enabled = false     # TF-CT-002 MEDIUM
}
