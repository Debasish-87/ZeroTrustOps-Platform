package supply

import (
	"fmt"
	"strings"
	"time"

	"github.com/Debasish-87/ZeroTrustOps-Platform/sectl/internal/scanner"
)

// ImageInfo holds metadata about a container image.
type ImageInfo struct {
	Ref      string
	Name     string
	Tag      string
	Digest   string
	Registry string
	Created  *time.Time
}

// CheckImages runs supply-chain checks against a list of image references.
func CheckImages(images []string) ([]scanner.Finding, int) {
	var findings []scanner.Finding
	passed := 0

	for _, img := range images {
		info := parseImageRef(img)

		// SC-001: Not pinned by digest
		if info.Digest == "" {
			findings = append(findings, scFinding("SC-001", scanner.SeverityHigh, "SUPPLY_CHAIN",
				fmt.Sprintf("Image not pinned by digest: %s", img),
				"Pin the image using @sha256:<digest> for reproducible, tamper-proof builds.",
				img))
		} else {
			passed++
		}

		// SC-002: :latest tag
		if info.Tag == "latest" || (info.Tag == "" && info.Digest == "") {
			findings = append(findings, scFinding("SC-002", scanner.SeverityHigh, "SUPPLY_CHAIN",
				fmt.Sprintf("Image uses :latest tag: %s", img),
				"Use a specific version tag or digest instead of :latest.",
				img))
		} else if info.Tag != "" && info.Digest == "" {
			passed++
		}

		// SC-020: Known EOL base images
		if isEOLImage(info) {
			findings = append(findings, scFinding("SC-020", scanner.SeverityHigh, "SUPPLY_CHAIN",
				fmt.Sprintf("Potentially EOL base image detected: %s", img),
				"Upgrade to a supported base image version.",
				img))
		} else {
			passed++
		}
	}

	return findings, passed
}

// ─── Image reference parser ───────────────────────────────────────────────────

func parseImageRef(ref string) ImageInfo {
	info := ImageInfo{Ref: ref}

	// Extract digest
	if idx := strings.Index(ref, "@"); idx >= 0 {
		info.Digest = ref[idx+1:]
		ref = ref[:idx]
	}

	// Extract registry and name
	parts := strings.SplitN(ref, "/", 3)
	switch len(parts) {
	case 1:
		info.Registry = "docker.io"
		info.Name = "library/" + parts[0]
	case 2:
		if strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost" {
			info.Registry = parts[0]
			info.Name = parts[1]
		} else {
			info.Registry = "docker.io"
			info.Name = strings.Join(parts, "/")
		}
	case 3:
		info.Registry = parts[0]
		info.Name = strings.Join(parts[1:], "/")
	}

	// Extract tag from name
	if idx := strings.LastIndex(info.Name, ":"); idx >= 0 {
		info.Tag = info.Name[idx+1:]
		info.Name = info.Name[:idx]
	}

	return info
}

// ─── EOL detection ────────────────────────────────────────────────────────────

var eolImages = []struct {
	name string
	tags []string
}{
	{"ubuntu", []string{"14.04", "16.04", "18.04", "21.10", "22.10"}},
	{"debian", []string{"8", "9", "10", "jessie", "stretch", "buster", "wheezy"}},
	{"centos", []string{"6", "7", "8"}},
	{"python", []string{"2.7", "3.6", "3.7", "3.8"}},
	{"node", []string{"10", "12", "14", "15", "17", "19"}},
	{"golang", []string{"1.16", "1.17", "1.18", "1.19"}},
	{"alpine", []string{"3.10", "3.11", "3.12", "3.13"}},
}

func isEOLImage(info ImageInfo) bool {
	imgName := strings.ToLower(info.Name)
	// Strip registry prefix for comparison
	if idx := strings.LastIndex(imgName, "/"); idx >= 0 {
		imgName = imgName[idx+1:]
	}

	for _, eol := range eolImages {
		if imgName == eol.name || strings.HasSuffix(imgName, "/"+eol.name) {
			for _, eolTag := range eol.tags {
				if info.Tag == eolTag || strings.HasPrefix(info.Tag, eolTag+".") {
					return true
				}
			}
		}
	}
	return false
}

func scFinding(id string, sev scanner.Severity, category, title, remediation, resource string) scanner.Finding {
	return scanner.Finding{
		RuleID:      id,
		Severity:    sev,
		Category:    category,
		Title:       title,
		Description: title,
		Resource:    resource,
		Remediation: remediation,
		Tags:        []string{"supply-chain"},
	}
}
