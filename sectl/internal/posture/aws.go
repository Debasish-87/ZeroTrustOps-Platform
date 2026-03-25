package posture

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/Debasish-87/ZeroTrustOps-Platform/sectl/internal/scanner"
)

// AuditResult wraps findings and summary from a live cloud audit.
type AuditResult struct {
	Findings []scanner.Finding
	Summary  scanner.Summary
}

// AuditAWS performs live AWS account posture checks.
func AuditAWS(ctx context.Context, profile, region string) (*AuditResult, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	var findings []scanner.Finding
	passed := 0

	iamClient := iam.NewFromConfig(cfg)
	s3Client := s3.NewFromConfig(cfg)

	// ─── IAM Checks ──────────────────────────────────────────────────────────

	// AWS-IAM-001 / 002: Root account checks
	rootFindings, rootPassed, err := checkRootAccount(ctx, iamClient)
	if err == nil {
		findings = append(findings, rootFindings...)
		passed += rootPassed
	}

	// AWS-IAM-003 / 004 / 005: Password policy
	pwdFindings, pwdPassed, err := checkPasswordPolicy(ctx, iamClient)
	if err == nil {
		findings = append(findings, pwdFindings...)
		passed += pwdPassed
	}

	// AWS-IAM-006 / 007: Users without MFA, stale keys
	userFindings, userPassed, err := checkIAMUsers(ctx, iamClient)
	if err == nil {
		findings = append(findings, userFindings...)
		passed += userPassed
	}

	// ─── S3 Checks ───────────────────────────────────────────────────────────

	s3Findings, s3Passed, err := checkS3Buckets(ctx, s3Client)
	if err == nil {
		findings = append(findings, s3Findings...)
		passed += s3Passed
	}

	result := &AuditResult{
		Findings: findings,
		Summary:  scanner.BuildSummary(findings, passed),
	}
	return result, nil
}

// ─── IAM root ─────────────────────────────────────────────────────────────────

func checkRootAccount(ctx context.Context, client *iam.Client) ([]scanner.Finding, int, error) {
	var findings []scanner.Finding
	passed := 0

	summary, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, 0, err
	}

	sm := summary.SummaryMap

	// AWS-IAM-001: Root access keys
	if sm["AccountAccessKeysPresent"] > 0 {
		findings = append(findings, postFinding("AWS-IAM-001", scanner.SeverityCritical, "IAM",
			"Root account has active access keys",
			"Delete root access keys immediately and use IAM users or roles.",
			"iam/root"))
	} else {
		passed++
	}

	// AWS-IAM-002: Root MFA
	if sm["AccountMFAEnabled"] == 0 {
		findings = append(findings, postFinding("AWS-IAM-002", scanner.SeverityCritical, "IAM",
			"Root account MFA not enabled",
			"Enable MFA on the root account using a hardware token.",
			"iam/root"))
	} else {
		passed++
	}

	return findings, passed, nil
}

// ─── Password policy ──────────────────────────────────────────────────────────

func checkPasswordPolicy(ctx context.Context, client *iam.Client) ([]scanner.Finding, int, error) {
	var findings []scanner.Finding
	passed := 0

	policy, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		// No policy configured
		findings = append(findings, postFinding("AWS-IAM-003", scanner.SeverityHigh, "IAM",
			"No IAM password policy configured",
			"Configure an IAM account password policy with minimum length >= 14.",
			"iam/password-policy"))
		return findings, 0, nil
	}

	pp := policy.PasswordPolicy

	// AWS-IAM-004: Minimum length
	if pp.MinimumPasswordLength != nil && *pp.MinimumPasswordLength < 14 {
		findings = append(findings, postFinding("AWS-IAM-004", scanner.SeverityMedium, "IAM",
			fmt.Sprintf("Password policy minimum length is %d (should be >= 14)", *pp.MinimumPasswordLength),
			"Set minimum password length to 14 or more characters.",
			"iam/password-policy"))
	} else {
		passed++
	}

	// AWS-IAM-005: Password expiry
	if pp.MaxPasswordAge != nil && *pp.MaxPasswordAge > 90 {
		findings = append(findings, postFinding("AWS-IAM-005", scanner.SeverityMedium, "IAM",
			fmt.Sprintf("Password max age is %d days (should be <= 90)", *pp.MaxPasswordAge),
			"Set maximum password age to 90 days or fewer.",
			"iam/password-policy"))
	} else if pp.MaxPasswordAge == nil || *pp.MaxPasswordAge == 0 {
		findings = append(findings, postFinding("AWS-IAM-005", scanner.SeverityMedium, "IAM",
			"Password expiry not configured",
			"Set a maximum password age of 90 days.",
			"iam/password-policy"))
	} else {
		passed++
	}

	return findings, passed, nil
}

// ─── IAM Users ────────────────────────────────────────────────────────────────

func checkIAMUsers(ctx context.Context, client *iam.Client) ([]scanner.Finding, int, error) {
	var findings []scanner.Finding
	passed := 0

	// List all users
	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, 0, err
		}

		for _, user := range page.Users {
			userName := aws.ToString(user.UserName)

			// Check for console access (LoginProfile)
			_, err := client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
				UserName: user.UserName,
			})
			hasConsoleAccess := err == nil

			if hasConsoleAccess {
				// AWS-IAM-006: Console user without MFA
				mfaDevices, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{
					UserName: user.UserName,
				})
				if err == nil && len(mfaDevices.MFADevices) == 0 {
					findings = append(findings, postFinding("AWS-IAM-006", scanner.SeverityHigh, "IAM",
						fmt.Sprintf("Console user '%s' has no MFA device", userName),
						"Require MFA for all IAM users with console access.",
						"iam/users/"+userName))
				} else if err == nil {
					passed++
				}
			}

			// AWS-IAM-007: Stale access keys (> 90 days)
			keys, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
				UserName: user.UserName,
			})
			if err == nil {
				for _, key := range keys.AccessKeyMetadata {
					if key.CreateDate != nil {
						age := time.Since(*key.CreateDate)
						if age > 90*24*time.Hour {
							findings = append(findings, postFinding("AWS-IAM-007", scanner.SeverityHigh, "IAM",
								fmt.Sprintf("User '%s' has access key older than 90 days (%d days)", userName, int(age.Hours()/24)),
								"Rotate or delete stale access keys. Consider using IAM roles instead.",
								"iam/users/"+userName+"/access-keys"))
						} else {
							passed++
						}
					}
				}
			}
		}
	}

	return findings, passed, nil
}

// ─── S3 Bucket posture ────────────────────────────────────────────────────────

func checkS3Buckets(ctx context.Context, client *s3.Client) ([]scanner.Finding, int, error) {
	var findings []scanner.Finding
	passed := 0

	buckets, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, 0, err
	}

	for _, bucket := range buckets.Buckets {
		bucketName := aws.ToString(bucket.Name)
		resource := "s3://" + bucketName

		// AWS-S3-001 / 002: Public access block
		pab, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			findings = append(findings, postFinding("AWS-S3-001", scanner.SeverityHigh, "EXPOSURE",
				fmt.Sprintf("S3 bucket '%s' has no public access block configuration", bucketName),
				"Enable all public access block settings for the bucket.",
				resource))
		} else {
			cfg := pab.PublicAccessBlockConfiguration
			allBlocked := cfg != nil &&
				aws.ToBool(cfg.BlockPublicAcls) &&
				aws.ToBool(cfg.BlockPublicPolicy) &&
				aws.ToBool(cfg.IgnorePublicAcls) &&
				aws.ToBool(cfg.RestrictPublicBuckets)
			if !allBlocked {
				findings = append(findings, postFinding("AWS-S3-002", scanner.SeverityHigh, "EXPOSURE",
					fmt.Sprintf("S3 bucket '%s' public access not fully blocked", bucketName),
					"Set all four public access block settings to true.",
					resource))
			} else {
				passed++
			}
		}

		// AWS-S3-003: Encryption at rest
		enc, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: bucket.Name,
		})
		if err != nil || len(enc.ServerSideEncryptionConfiguration.Rules) == 0 {
			findings = append(findings, postFinding("AWS-S3-003", scanner.SeverityHigh, "ENCRYPTION",
				fmt.Sprintf("S3 bucket '%s' not encrypted at rest", bucketName),
				"Enable server-side encryption with aws:kms or AES256.",
				resource))
		} else {
			passed++
		}

		// AWS-S3-004: Versioning
		ver, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: bucket.Name,
		})
		if err == nil && string(ver.Status) != "Enabled" {
			findings = append(findings, postFinding("AWS-S3-004", scanner.SeverityMedium, "MISCONFIGURATION",
				fmt.Sprintf("S3 bucket '%s' versioning not enabled", bucketName),
				"Enable versioning to protect against accidental deletion and ransomware.",
				resource))
		} else if err == nil {
			passed++
		}

		// AWS-S3-005: Bucket policy allows public access
		pol, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: bucket.Name,
		})
		if err == nil && pol.Policy != nil {
			policyStr := aws.ToString(pol.Policy)
			if strings.Contains(policyStr, `"Principal": "*"`) ||
				strings.Contains(policyStr, `"Principal":"*"`) {
				findings = append(findings, postFinding("AWS-S3-005", scanner.SeverityCritical, "EXPOSURE",
					fmt.Sprintf("S3 bucket '%s' policy allows public access (Principal: *)", bucketName),
					"Remove wildcard Principal from the bucket policy.",
					resource))
			} else {
				passed++
			}
		}
	}

	return findings, passed, nil
}

// ─── Helper ───────────────────────────────────────────────────────────────────

func postFinding(id string, sev scanner.Severity, category, title, remediation, resource string) scanner.Finding {
	return scanner.Finding{
		RuleID:      id,
		Severity:    sev,
		Category:    category,
		Title:       title,
		Description: title,
		Resource:    resource,
		Remediation: remediation,
		Tags:        []string{"aws", "posture"},
	}
}
