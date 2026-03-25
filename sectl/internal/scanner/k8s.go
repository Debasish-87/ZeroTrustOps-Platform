package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ─── Public entry point ───────────────────────────────────────────────────────

// ScanK8s scans a file or directory for Kubernetes security misconfigurations.
// Returns (findings, passedChecks, error).
func ScanK8s(path string, excludeRules []string) ([]Finding, int, error) {
	var findings []Finding
	passed := 0

	files, err := collectYAMLFiles(path)
	if err != nil {
		return nil, 0, err
	}
	if len(files) == 0 {
		return nil, 0, fmt.Errorf("no YAML files found at %s", path)
	}

	for _, f := range files {
		docs, err := parseYAMLFile(f)
		if err != nil {
			// skip malformed files with a warning finding
			findings = append(findings, Finding{
				RuleID:   "K8S-PARSE",
				Severity: SeverityLow,
				Category: "PARSE_ERROR",
				Title:    "Could not parse YAML file",
				File:     f,
				Description: fmt.Sprintf("File could not be parsed as valid YAML: %v", err),
				Remediation: "Ensure the file is valid YAML.",
			})
			continue
		}
		for _, doc := range docs {
			founds, p := checkK8sDoc(doc, f)
			findings = append(findings, founds...)
			passed += p
		}
	}

	findings = ExcludeRules(findings, excludeRules)
	return findings, passed, nil
}

// ─── File walking ─────────────────────────────────────────────────────────────

func collectYAMLFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("path not found: %s", path)
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	var files []string
	err = filepath.Walk(path, func(p string, i os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if !i.IsDir() && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
			files = append(files, p)
		}
		return nil
	})
	return files, err
}

// ─── YAML parsing ─────────────────────────────────────────────────────────────

func parseYAMLFile(path string) ([]map[string]interface{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var docs []map[string]interface{}
	decoder := yaml.NewDecoder(f)
	for {
		var doc map[string]interface{}
		err := decoder.Decode(&doc)
		if err != nil {
			break
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}
	return docs, nil
}

// ─── Document dispatcher ──────────────────────────────────────────────────────

func checkK8sDoc(doc map[string]interface{}, file string) ([]Finding, int) {
	kind := strField(doc, "kind")
	name := nestedStr(doc, "metadata", "name")
	ns := nestedStr(doc, "metadata", "namespace")
	resource := kind + "/" + name
	if ns != "" {
		resource = ns + "/" + resource
	}

	switch kind {
	case "Deployment", "DaemonSet", "StatefulSet", "Job", "ReplicaSet":
		podSpec := nestedMap(doc, "spec", "template", "spec")
		return checkPodSpec(podSpec, resource, file)
	case "CronJob":
		podSpec := nestedMap(doc, "spec", "jobTemplate", "spec", "template", "spec")
		return checkPodSpec(podSpec, resource, file)
	case "Pod":
		podSpec := nestedMap(doc, "spec")
		return checkPodSpec(podSpec, resource, file)
	case "ClusterRole", "Role":
		return checkRBAC(doc, resource, file)
	case "ClusterRoleBinding", "RoleBinding":
		return checkRoleBinding(doc, resource, file)
	case "ConfigMap":
		return checkConfigMap(doc, resource, file)
	case "Ingress":
		return checkIngress(doc, resource, file)
	case "ServiceAccount":
		return checkServiceAccount(doc, resource, file)
	}
	return nil, 0
}

// ─── Pod / Container checks ───────────────────────────────────────────────────

func checkPodSpec(spec map[string]interface{}, resource, file string) ([]Finding, int) {
	if spec == nil {
		return nil, 0
	}
	var findings []Finding
	passed := 0

	// K8S-001: hostPID
	if boolField(spec, "hostPID") {
		findings = append(findings, k8sFinding("K8S-001", SeverityCritical, "PRIVILEGE",
			"hostPID enabled — container sees all host processes",
			"Set hostPID: false in the pod spec.",
			resource, file))
	} else {
		passed++
	}

	// K8S-002: hostNetwork
	if boolField(spec, "hostNetwork") {
		findings = append(findings, k8sFinding("K8S-002", SeverityHigh, "NETWORK_POLICY",
			"hostNetwork enabled — shares host network stack",
			"Set hostNetwork: false unless explicitly required.",
			resource, file))
	} else {
		passed++
	}

	// K8S-003: hostIPC
	if boolField(spec, "hostIPC") {
		findings = append(findings, k8sFinding("K8S-003", SeverityHigh, "PRIVILEGE",
			"hostIPC enabled — shares host IPC namespace",
			"Set hostIPC: false in the pod spec.",
			resource, file))
	} else {
		passed++
	}

	// K8S-012: automountServiceAccountToken
	if automount, ok := spec["automountServiceAccountToken"]; ok {
		if b, _ := automount.(bool); b {
			findings = append(findings, k8sFinding("K8S-012", SeverityMedium, "RBAC",
				"Service account token auto-mounted",
				"Set automountServiceAccountToken: false if the workload does not need API access.",
				resource, file))
		} else {
			passed++
		}
	}

	// Check containers
	containers := listField(spec, "containers")
	initContainers := listField(spec, "initContainers")
	allContainers := append(containers, initContainers...)

	for _, c := range allContainers {
		cm, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		cname := strField(cm, "name")
		cresource := resource + "/" + cname
		f, p := checkContainer(cm, cresource, file)
		findings = append(findings, f...)
		passed += p
	}

	return findings, passed
}

func checkContainer(c map[string]interface{}, resource, file string) ([]Finding, int) {
	var findings []Finding
	passed := 0

	sc := nestedMap(c, "securityContext")

	// K8S-008: No securityContext
	if sc == nil {
		findings = append(findings, k8sFinding("K8S-008", SeverityHigh, "PRIVILEGE",
			"No securityContext defined on container",
			"Add a securityContext block with allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, runAsNonRoot: true.",
			resource, file))
	} else {
		passed++

		// K8S-004: privileged
		if boolField(sc, "privileged") {
			findings = append(findings, k8sFinding("K8S-004", SeverityCritical, "PRIVILEGE",
				"Privileged container — full host device access",
				"Remove privileged: true. Use specific capabilities instead.",
				resource, file))
		} else {
			passed++
		}

		// K8S-005: allowPrivilegeEscalation
		if v, exists := sc["allowPrivilegeEscalation"]; exists {
			if b, _ := v.(bool); b {
				findings = append(findings, k8sFinding("K8S-005", SeverityHigh, "PRIVILEGE",
					"allowPrivilegeEscalation not set to false",
					"Set allowPrivilegeEscalation: false in the securityContext.",
					resource, file))
			} else {
				passed++
			}
		} else {
			findings = append(findings, k8sFinding("K8S-005", SeverityHigh, "PRIVILEGE",
				"allowPrivilegeEscalation not set to false",
				"Explicitly set allowPrivilegeEscalation: false.",
				resource, file))
		}

		// K8S-006: runAsNonRoot
		if v, exists := sc["runAsNonRoot"]; exists {
			if b, _ := v.(bool); !b {
				findings = append(findings, k8sFinding("K8S-006", SeverityHigh, "PRIVILEGE",
					"Container may run as root (runAsNonRoot: false)",
					"Set runAsNonRoot: true and specify a non-zero runAsUser.",
					resource, file))
			} else {
				passed++
			}
		} else {
			findings = append(findings, k8sFinding("K8S-006", SeverityHigh, "PRIVILEGE",
				"Container may run as root (runAsNonRoot missing)",
				"Add runAsNonRoot: true to the securityContext.",
				resource, file))
		}

		// K8S-007: readOnlyRootFilesystem
		if v, exists := sc["readOnlyRootFilesystem"]; exists {
			if b, _ := v.(bool); !b {
				findings = append(findings, k8sFinding("K8S-007", SeverityMedium, "PRIVILEGE",
					"readOnlyRootFilesystem not enabled",
					"Set readOnlyRootFilesystem: true and mount tmpfs for writable paths.",
					resource, file))
			} else {
				passed++
			}
		} else {
			findings = append(findings, k8sFinding("K8S-007", SeverityMedium, "PRIVILEGE",
				"readOnlyRootFilesystem not set",
				"Add readOnlyRootFilesystem: true to the securityContext.",
				resource, file))
		}

		// Capabilities: DROP ALL preferred
		caps := nestedMap(sc, "capabilities")
		if caps != nil {
			drop := listField(caps, "drop")
			hasDropAll := false
			for _, d := range drop {
				if s, _ := d.(string); strings.ToUpper(s) == "ALL" {
					hasDropAll = true
				}
			}
			if !hasDropAll {
				findings = append(findings, k8sFinding("K8S-008-CAP", SeverityMedium, "PRIVILEGE",
					"Container does not drop all capabilities",
					"Add capabilities.drop: [ALL] and add only required capabilities.",
					resource, file))
			} else {
				passed++
			}
		}
	}

	// K8S-009: mutable :latest image tag
	image := strField(c, "image")
	if image != "" {
		if strings.HasSuffix(image, ":latest") || (!strings.Contains(image, ":") && !strings.Contains(image, "@")) {
			findings = append(findings, k8sFinding("K8S-009", SeverityMedium, "IMAGE",
				"Mutable :latest image tag",
				"Pin the image to a specific version tag or digest (e.g., image@sha256:...).",
				resource, file))
		} else if !strings.Contains(image, "@sha256:") {
			// Not pinned by digest — note as low
			findings = append(findings, k8sFinding("K8S-009-DIGEST", SeverityLow, "IMAGE",
				"Image not pinned by digest",
				"Consider pinning the image by SHA256 digest for reproducible deployments.",
				resource, file))
		} else {
			passed++
		}
	}

	// K8S-010: No resource requests/limits
	res := nestedMap(c, "resources")
	if res == nil {
		findings = append(findings, k8sFinding("K8S-010", SeverityMedium, "RESOURCE",
			"No resource requests/limits defined",
			"Add requests and limits for cpu and memory to prevent resource exhaustion.",
			resource, file))
	} else {
		if res["requests"] == nil || res["limits"] == nil {
			findings = append(findings, k8sFinding("K8S-010", SeverityMedium, "RESOURCE",
				"Resource requests or limits missing",
				"Define both requests and limits for cpu and memory.",
				resource, file))
		} else {
			passed++
		}
	}

	// K8S-011: No livenessProbe
	if c["livenessProbe"] == nil {
		findings = append(findings, k8sFinding("K8S-011", SeverityLow, "MISCONFIGURATION",
			"No livenessProbe defined",
			"Add a livenessProbe so Kubernetes can restart unhealthy containers.",
			resource, file))
	} else {
		passed++
	}

	// K8S-031: Hardcoded secret in env var
	envVars := listField(c, "env")
	for _, e := range envVars {
		em, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		envName := strings.ToLower(strField(em, "name"))
		envValue := strField(em, "value")
		if envValue != "" && isSecretKey(envName) {
			findings = append(findings, k8sFinding("K8S-031", SeverityHigh, "SECRETS",
				fmt.Sprintf("Hardcoded secret in env var: %s", strings.ToUpper(envName)),
				"Use secretKeyRef or valueFrom.secretKeyRef instead of plain text env values.",
				resource, file))
		}
	}

	return findings, passed
}

// ─── RBAC checks ─────────────────────────────────────────────────────────────

func checkRBAC(doc map[string]interface{}, resource, file string) ([]Finding, int) {
	var findings []Finding
	passed := 0

	rules := listField(doc, "rules")
	for _, r := range rules {
		rm, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		apiGroups := listField(rm, "apiGroups")
		verbs := listField(rm, "verbs")
		resources := listField(rm, "resources")

		if containsWildcard(apiGroups) {
			findings = append(findings, k8sFinding("K8S-020", SeverityCritical, "RBAC",
				"RBAC wildcard apiGroups (*)",
				"Restrict apiGroups to only the specific API groups required.",
				resource, file))
		} else {
			passed++
		}

		if containsWildcard(verbs) {
			findings = append(findings, k8sFinding("K8S-021", SeverityCritical, "RBAC",
				"RBAC wildcard verbs (*)",
				"Restrict verbs to only the actions required (e.g., get, list, watch).",
				resource, file))
		} else {
			passed++
		}

		if containsWildcard(resources) {
			findings = append(findings, k8sFinding("K8S-022", SeverityCritical, "RBAC",
				"RBAC wildcard resources (*)",
				"Restrict resources to only the specific resource types required.",
				resource, file))
		} else {
			passed++
		}

		// K8S-023: Dangerous verb on sensitive resource
		sensitiveResources := []string{"secrets", "pods/exec", "nodes", "clusterroles", "clusterrolebindings"}
		dangerousVerbs := []string{"create", "update", "patch", "delete", "deletecollection", "*"}
		for _, res := range resources {
			rs, _ := res.(string)
			for _, sensitiveRes := range sensitiveResources {
				if strings.EqualFold(rs, sensitiveRes) {
					for _, verb := range verbs {
						vs, _ := verb.(string)
						for _, dv := range dangerousVerbs {
							if strings.EqualFold(vs, dv) {
								findings = append(findings, k8sFinding("K8S-023", SeverityHigh, "RBAC",
									fmt.Sprintf("Dangerous RBAC: %s on %s", vs, rs),
									"Restrict access to sensitive resources. Avoid create/update/delete on secrets, exec on pods.",
									resource, file))
							}
						}
					}
					break
				}
			}
		}
	}

	return findings, passed
}

func checkRoleBinding(doc map[string]interface{}, resource, file string) ([]Finding, int) {
	var findings []Finding
	passed := 0

	// K8S-024: Binding to cluster-admin
	roleRef := nestedMap(doc, "roleRef")
	if roleRef != nil {
		roleName := strField(roleRef, "name")
		if strings.EqualFold(roleName, "cluster-admin") {
			findings = append(findings, k8sFinding("K8S-024", SeverityCritical, "RBAC",
				"Binding to cluster-admin role",
				"Avoid binding to cluster-admin. Create a least-privilege custom role instead.",
				resource, file))
		} else {
			passed++
		}
	}

	// K8S-025: Binding to unauthenticated/anonymous subject
	subjects := listField(doc, "subjects")
	for _, s := range subjects {
		sm, ok := s.(map[string]interface{})
		if !ok {
			continue
		}
		subjName := strings.ToLower(strField(sm, "name"))
		if subjName == "system:unauthenticated" || subjName == "system:anonymous" {
			findings = append(findings, k8sFinding("K8S-025", SeverityCritical, "RBAC",
				"Binding to unauthenticated/anonymous subject",
				"Never bind roles to system:unauthenticated or system:anonymous subjects.",
				resource, file))
		} else {
			passed++
		}
	}

	return findings, passed
}

// ─── ConfigMap checks ─────────────────────────────────────────────────────────

func checkConfigMap(doc map[string]interface{}, resource, file string) ([]Finding, int) {
	var findings []Finding
	passed := 0

	data, ok := doc["data"].(map[string]interface{})
	if !ok {
		return nil, 0
	}

	for k, v := range data {
		key := strings.ToLower(k)
		val, _ := v.(string)
		if isSecretKey(key) && val != "" {
			findings = append(findings, k8sFinding("K8S-030", SeverityHigh, "SECRETS",
				fmt.Sprintf("Potential secret stored in ConfigMap key: %s", k),
				"Move secrets to a Kubernetes Secret resource and use secretKeyRef.",
				resource, file))
		} else {
			passed++
		}
	}

	return findings, passed
}

// ─── Ingress checks ───────────────────────────────────────────────────────────

func checkIngress(doc map[string]interface{}, resource, file string) ([]Finding, int) {
	var findings []Finding
	passed := 0

	spec := nestedMap(doc, "spec")
	if spec == nil {
		return nil, 0
	}

	// K8S-040: No TLS configured
	tls := listField(spec, "tls")
	if len(tls) == 0 {
		findings = append(findings, k8sFinding("K8S-040", SeverityHigh, "ENCRYPTION",
			"Ingress has no TLS configured",
			"Add a tls section to the Ingress spec with a valid certificate secret.",
			resource, file))
	} else {
		passed++
	}

	// K8S-041: TLS redirect annotation
	annotations, _ := doc["metadata"].(map[string]interface{})
	if annotations != nil {
		ann, _ := annotations["annotations"].(map[string]interface{})
		if ann != nil {
			redirectVal, _ := ann["nginx.ingress.kubernetes.io/ssl-redirect"].(string)
			if redirectVal == "false" {
				findings = append(findings, k8sFinding("K8S-041", SeverityMedium, "ENCRYPTION",
					"TLS redirect disabled on Ingress",
					"Set nginx.ingress.kubernetes.io/ssl-redirect: 'true' to force HTTPS.",
					resource, file))
			} else {
				passed++
			}
		}
	}

	return findings, passed
}

// ─── ServiceAccount checks ────────────────────────────────────────────────────

func checkServiceAccount(doc map[string]interface{}, resource, file string) ([]Finding, int) {
	var findings []Finding
	passed := 0

	annotations, _ := nestedMap(doc, "metadata")["annotations"].(map[string]interface{})
	if annotations != nil {
		for k := range annotations {
			if strings.Contains(k, "eks.amazonaws.com/role-arn") {
				findings = append(findings, k8sFinding("K8S-050", SeverityInfo, "IAM",
					"ServiceAccount IRSA annotation — verify IAM role scope",
					"Ensure the IAM role attached via IRSA follows least privilege.",
					resource, file))
			} else {
				passed++
			}
		}
	}

	return findings, passed
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func k8sFinding(id string, sev Severity, category, title, remediation, resource, file string) Finding {
	return Finding{
		RuleID:      id,
		Severity:    sev,
		Category:    category,
		Title:       title,
		Description: title,
		Resource:    resource,
		File:        file,
		Remediation: remediation,
		Tags:        []string{"kubernetes", strings.ToLower(category)},
	}
}

func strField(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}

func boolField(m map[string]interface{}, key string) bool {
	if m == nil {
		return false
	}
	v, _ := m[key].(bool)
	return v
}

func listField(m map[string]interface{}, key string) []interface{} {
	if m == nil {
		return nil
	}
	v, _ := m[key].([]interface{})
	return v
}

func nestedMap(m map[string]interface{}, keys ...string) map[string]interface{} {
	cur := m
	for _, k := range keys {
		if cur == nil {
			return nil
		}
		next, _ := cur[k].(map[string]interface{})
		cur = next
	}
	return cur
}

func nestedStr(m map[string]interface{}, keys ...string) string {
	keys2 := keys[:len(keys)-1]
	lastKey := keys[len(keys)-1]
	parent := nestedMap(m, keys2...)
	return strField(parent, lastKey)
}

func containsWildcard(list []interface{}) bool {
	for _, v := range list {
		if s, _ := v.(string); s == "*" {
			return true
		}
	}
	return false
}

var secretKeywords = []string{
	"password", "passwd", "secret", "api_key", "apikey", "token", "private_key",
	"access_key", "secret_key", "auth", "credential", "jwt", "cert", "ssl_key",
}

func isSecretKey(key string) bool {
	key = strings.ToLower(key)
	for _, kw := range secretKeywords {
		if strings.Contains(key, kw) {
			return true
		}
	}
	return false
}

// splitYAMLDocs splits a YAML file on --- separators (used for alternative parsing).
func splitYAMLDocs(content string) []string {
	var docs []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	var cur strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "---" {
			if s := strings.TrimSpace(cur.String()); s != "" {
				docs = append(docs, s)
			}
			cur.Reset()
		} else {
			cur.WriteString(line + "\n")
		}
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		docs = append(docs, s)
	}
	return docs
}
