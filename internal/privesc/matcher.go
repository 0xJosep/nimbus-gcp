package privesc

import "strings"

// MatchResult represents a technique that an identity can exploit.
type MatchResult struct {
	Technique        Technique
	MatchedPerms     []string
	MissingPerms     []string
	FullMatch        bool
	MatchPercentage  float64
}

// MatchTechniques checks which escalation techniques are available given a set of permissions.
// Returns full matches and partial matches (>50% of required permissions present).
func MatchTechniques(grantedPermissions []string) []MatchResult {
	permSet := make(map[string]bool, len(grantedPermissions))
	for _, p := range grantedPermissions {
		permSet[p] = true
		// Also add wildcard matches: "iam.serviceAccountKeys.*" matches "iam.serviceAccountKeys.create".
		parts := strings.Split(p, ".")
		if len(parts) >= 2 {
			permSet[strings.Join(parts[:len(parts)-1], ".")+".*"] = true
		}
	}

	var results []MatchResult
	for _, tech := range KnownTechniques {
		var matched, missing []string
		for _, required := range tech.Permissions {
			if permSet[required] {
				matched = append(matched, required)
			} else {
				missing = append(missing, required)
			}
		}

		pct := float64(len(matched)) / float64(len(tech.Permissions)) * 100
		if pct >= 50 {
			results = append(results, MatchResult{
				Technique:       tech,
				MatchedPerms:    matched,
				MissingPerms:    missing,
				FullMatch:       len(missing) == 0,
				MatchPercentage: pct,
			})
		}
	}
	return results
}

// FindFullMatches returns only techniques where all required permissions are present.
func FindFullMatches(grantedPermissions []string) []MatchResult {
	all := MatchTechniques(grantedPermissions)
	var full []MatchResult
	for _, r := range all {
		if r.FullMatch {
			full = append(full, r)
		}
	}
	return full
}
