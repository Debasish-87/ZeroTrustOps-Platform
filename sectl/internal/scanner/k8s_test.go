package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func tmpYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func findingIDs(findings []Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}

func hasRule(findings []Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// ─── K8s scanner tests ────────────────────────────────────────────────────────

func TestScanK8s_PrivilegedContainer(t *testing.T) {
	yaml := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
`
	path := tmpYAML(t, yaml)
	findings, _, err := ScanK8s(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(findings, "K8S-004") {
		t.Errorf("expected K8S-004 (privileged container), got: %v", findingIDs(findings))
	}
}

func TestScanK8s_HostPID(t *testing.T) {
	yaml := `
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  hostPID: true
  containers:
    - name: app
      image: nginx:1.25
`
	path := tmpYAML(t, yaml)
	findings, _, err := ScanK8s(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(findings, "K8S-001") {
		t.Errorf("expected K8S-001 (hostPID), got: %v", findingIDs(findings))
	}
}

func TestScanK8s_HostNetwork(t *testing.T) {
	yaml := `
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx:1.25
`
	path := tmpYAML(t, yaml)
	findings, _, err := ScanK8s(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(findings, "K8S-002") {
		t.Errorf("expected K8S-002 (hostNetwork), got: %v", findingIDs(findings))
	}
}

func TestScanK8s_LatestTag(t *testing.T) {
	yaml := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            readOnlyRootFilesystem: true
`
	path := tmpYAML(t, yaml)
	findings, _, err := ScanK8s(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(findings, "K8S-009") {
		t.Errorf("expected K8S-009 (:latest tag), got: %v", findingIDs(findings))
	}
}

func TestScanK8s_HardcodedSecret(t *testing.T) {
	yaml := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
          env:
            - name: DB_PASSWORD
              value: "supersecret123"
`
	path := tmpYAML(t, yaml)
	findings, _, err := ScanK8s(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(findings, "K8S-031") {
		t.Errorf("expected K8S-031 (hardcoded secret), got: %v", findingIDs(findings))
	}
}

func TestScanK8s_WildcardRBAC(t *testing.T) {
	yaml := `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: test-role
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
`
	path := tmpYAML(t, yaml)
	findings, _, err := ScanK8s(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(findings, "K8S-020") {
		t.Errorf("expected K8S-020 (wildcard apiGroups), got: %v", findingIDs(findings))
	}
	if !hasRule(findings, "K8S-021") {
		t.Errorf("expected K8S-021 (wildcard verbs), got: %v", findingIDs(findings))
	}
	if !hasRule(findings, "K8S-022") {
		t.Errorf("expected K8S-022 (wildcard resources), got: %v", findingIDs(findings))
	}
}

func TestScanK8s_ClusterAdminBinding(t *testing.T) {
	yaml := `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dangerous
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: User
    name: bob
    apiGroup: rbac.authorization.k8s.io
`
	path := tmpYAML(t, yaml)
	findings, _, err := ScanK8s(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(findings, "K8S-024") {
		t.Errorf("expected K8S-024 (cluster-admin binding), got: %v", findingIDs(findings))
	}
}

func TestScanK8s_AnonymousBinding(t *testing.T) {
	yaml := `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: anon-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
  - kind: User
    name: system:unauthenticated
    apiGroup: rbac.authorization.k8s.io
`
	path := tmpYAML(t, yaml)
	findings, _, err := ScanK8s(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(findings, "K8S-025") {
		t.Errorf("expected K8S-025 (anonymous binding), got: %v", findingIDs(findings))
	}
}

func TestScanK8s_GoodDeployment_NoHighCritical(t *testing.T) {
	yaml := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hardened
  namespace: production
spec:
  template:
    spec:
      hostPID: false
      hostNetwork: false
      hostIPC: false
      automountServiceAccountToken: false
      containers:
        - name: app
          image: myregistry.io/app@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 10001
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "500m"
              memory: "256Mi"
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: app-secrets
                  key: db-password
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
`
	path := tmpYAML(t, yaml)
	findings, _, err := ScanK8s(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh {
			t.Errorf("good deployment should have no CRITICAL/HIGH findings, got %s: %s", f.RuleID, f.Title)
		}
	}
}

func TestScanK8s_ExcludeRules(t *testing.T) {
	yaml := `
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  hostPID: true
  containers:
    - name: app
      image: nginx:latest
`
	path := tmpYAML(t, yaml)
	findings, _, err := ScanK8s(path, []string{"K8S-001"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.RuleID == "K8S-001" {
			t.Error("K8S-001 should have been excluded")
		}
	}
}

func TestScanK8s_NoFiles_Error(t *testing.T) {
	_, _, err := ScanK8s("/tmp/nonexistent-path-xyz", nil)
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

// ─── FilterBySeverity tests ───────────────────────────────────────────────────

func TestFilterBySeverity(t *testing.T) {
	findings := []Finding{
		{RuleID: "T1", Severity: SeverityCritical},
		{RuleID: "T2", Severity: SeverityHigh},
		{RuleID: "T3", Severity: SeverityMedium},
		{RuleID: "T4", Severity: SeverityLow},
	}

	filtered := FilterBySeverity(findings, SeverityHigh)
	if len(filtered) != 2 {
		t.Errorf("expected 2 findings at HIGH+, got %d", len(filtered))
	}

	filtered = FilterBySeverity(findings, SeverityCritical)
	if len(filtered) != 1 {
		t.Errorf("expected 1 finding at CRITICAL, got %d", len(filtered))
	}
}

// ─── BuildSummary tests ───────────────────────────────────────────────────────

func TestBuildSummary(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical},
		{Severity: SeverityCritical},
		{Severity: SeverityHigh},
		{Severity: SeverityMedium},
		{Severity: SeverityLow},
	}

	s := BuildSummary(findings, 10)
	if s.Critical != 2 {
		t.Errorf("expected Critical=2, got %d", s.Critical)
	}
	if s.High != 1 {
		t.Errorf("expected High=1, got %d", s.High)
	}
	if s.Total != 5 {
		t.Errorf("expected Total=5, got %d", s.Total)
	}
	if s.Passed != 10 {
		t.Errorf("expected Passed=10, got %d", s.Passed)
	}
}
