package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ScanHelm scans a Helm chart directory for security issues.
func ScanHelm(path string, excludeRules []string) ([]Finding, int, error) {
	var findings []Finding
	passed := 0

	// Check Chart.yaml
	chartFile := filepath.Join(path, "Chart.yaml")
	chartFindings, chartPassed, err := checkChartYAML(chartFile)
	if err == nil {
		findings = append(findings, chartFindings...)
		passed += chartPassed
	}

	// Check values.yaml
	valuesFile := filepath.Join(path, "values.yaml")
	valFindings, valPassed, err := checkValuesYAML(valuesFile)
	if err == nil {
		findings = append(findings, valFindings...)
		passed += valPassed
	}

	// Check templates/
	templatesDir := filepath.Join(path, "templates")
	if info, err := os.Stat(templatesDir); err == nil && info.IsDir() {
		templateFindings, templatePassed := checkHelmTemplates(templatesDir)
		findings = append(findings, templateFindings...)
		passed += templatePassed
	}

	if len(findings) == 0 && passed == 0 {
		return nil, 0, fmt.Errorf("no Helm chart files found at %s (expected Chart.yaml)", path)
	}

	findings = ExcludeRules(findings, excludeRules)
	return findings, passed, nil
}

// ─── Chart.yaml checks ────────────────────────────────────────────────────────

func checkChartYAML(path string) ([]Finding, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}

	var chart map[string]interface{}
	if err := yaml.Unmarshal(data, &chart); err != nil {
		return nil, 0, err
	}

	var findings []Finding
	passed := 0

	// HELM-001: Deprecated apiVersion
	apiVersion := strField(chart, "apiVersion")
	if apiVersion == "v1" {
		findings = append(findings, helmFinding("HELM-001", SeverityLow, "MISCONFIGURATION",
			"Helm chart uses deprecated apiVersion v1",
			"Upgrade the chart apiVersion to v2 (requires Helm 3).",
			"Chart.yaml", path))
	} else {
		passed++
	}

	// HELM-002: Missing version
	version := strField(chart, "version")
	if version == "" {
		findings = append(findings, helmFinding("HELM-002", SeverityLow, "MISCONFIGURATION",
			"Helm chart missing version field",
			"Add a version field to Chart.yaml following SemVer (e.g., 1.0.0).",
			"Chart.yaml", path))
	} else {
		passed++
	}

	return findings, passed, nil
}

// ─── values.yaml checks ───────────────────────────────────────────────────────

func checkValuesYAML(path string) ([]Finding, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}

	var values map[string]interface{}
	if err := yaml.Unmarshal(data, &values); err != nil {
		return nil, 0, err
	}

	var findings []Finding
	passed := 0

	// HELM-010: Potential secrets in values.yaml
	secretFindings := findSecretsInValues(values, "values.yaml", path, "")
	findings = append(findings, secretFindings...)
	if len(secretFindings) == 0 {
		passed++
	}

	// HELM-011: :latest image tag in values.yaml
	imageTag := findImageTag(values)
	if imageTag == "latest" || imageTag == "" {
		findings = append(findings, helmFinding("HELM-011", SeverityMedium, "IMAGE",
			"Mutable :latest tag in values.yaml",
			"Pin the image tag to a specific version in values.yaml.",
			"values.yaml", path))
	} else {
		passed++
	}

	// HELM-012: Debug mode enabled
	if debugEnabled(values) {
		findings = append(findings, helmFinding("HELM-012", SeverityLow, "MISCONFIGURATION",
			"Debug mode enabled in values.yaml",
			"Set debug: false before deploying to production.",
			"values.yaml", path))
	} else {
		passed++
	}

	return findings, passed, nil
}

// ─── Template checks ──────────────────────────────────────────────────────────

func checkHelmTemplates(dir string) ([]Finding, int) {
	var findings []Finding
	passed := 0

	k8sFindings, k8sPassed, _ := ScanK8s(dir, nil)
	for _, f := range k8sFindings {
		// Re-label as helm findings
		f.Tags = append(f.Tags, "helm")
		findings = append(findings, f)
	}
	passed += k8sPassed

	return findings, passed
}

// ─── Value traversal helpers ──────────────────────────────────────────────────

func findSecretsInValues(values map[string]interface{}, keyPath, file, prefix string) []Finding {
	var findings []Finding
	for k, v := range values {
		fullKey := k
		if prefix != "" {
			fullKey = prefix + "." + k
		}
		switch val := v.(type) {
		case string:
			if isSecretKey(k) && val != "" && !strings.HasPrefix(val, "{{") {
				findings = append(findings, helmFinding("HELM-010", SeverityHigh, "SECRETS",
					fmt.Sprintf("Potential secret in values.yaml key: %s", fullKey),
					"Do not store secrets in values.yaml. Use Helm secrets plugin, external-secrets, or Vault.",
					keyPath, file))
			}
		case map[string]interface{}:
			findings = append(findings, findSecretsInValues(val, keyPath, file, fullKey)...)
		}
	}
	return findings
}

func findImageTag(values map[string]interface{}) string {
	// Check common patterns: image.tag, image: { tag: ... }
	if image, ok := values["image"].(map[string]interface{}); ok {
		return strField(image, "tag")
	}
	return ""
}

func debugEnabled(values map[string]interface{}) bool {
	for _, key := range []string{"debug", "debugMode", "enableDebug"} {
		if v, ok := values[key].(bool); ok && v {
			return true
		}
	}
	return false
}

func helmFinding(id string, sev Severity, category, title, remediation, resource, file string) Finding {
	return Finding{
		RuleID:      id,
		Severity:    sev,
		Category:    category,
		Title:       title,
		Description: title,
		Resource:    resource,
		File:        file,
		Remediation: remediation,
		Tags:        []string{"helm", strings.ToLower(category)},
	}
}
