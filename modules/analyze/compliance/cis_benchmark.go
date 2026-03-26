package compliance

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
)

func init() {
	module.Register(&CISBenchmark{})
}

// CISBenchmark runs offline CIS Google Cloud Platform Foundation Benchmark checks
// against already-collected data in the SQLite database.
type CISBenchmark struct{}

func (m *CISBenchmark) Info() module.Info {
	return module.Info{
		Name:         "analyze.compliance.cis-benchmark",
		Tactic:       module.TacticAnalyze,
		Service:      "compliance",
		Description:  "CIS Google Cloud Platform Foundation Benchmark analysis (offline)",
		RequiresAuth: false,
	}
}

// checkResult holds the outcome of a single CIS benchmark check.
type checkResult struct {
	ID          string
	Status      string // PASS, FAIL, NOT TESTED
	Description string
	Severity    module.Severity
	Affected    []string
}

func (m *CISBenchmark) Run(ctx module.RunContext) error {
	output.Info("Running CIS Google Cloud Platform Foundation Benchmark checks...")
	output.Info("This module operates OFFLINE using previously collected data.\n")

	var results []checkResult

	// --- IAM checks ---
	results = append(results, m.check1_1(ctx))
	results = append(results, m.check1_4(ctx))
	results = append(results, m.check1_5(ctx))
	results = append(results, m.check1_6(ctx))

	// --- Compute checks ---
	results = append(results, m.check4_1(ctx))
	results = append(results, m.check4_2(ctx))
	results = append(results, m.check4_4(ctx))
	results = append(results, m.check4_6(ctx))

	// --- Storage checks ---
	results = append(results, m.check5_1(ctx))
	results = append(results, m.check5_2(ctx))

	// --- Network checks ---
	results = append(results, m.check3_6(ctx))
	results = append(results, m.check3_7(ctx))

	// --- Database checks ---
	results = append(results, m.check6_1(ctx))
	results = append(results, m.check6_2(ctx))
	results = append(results, m.check6_5(ctx))

	// --- Logging checks ---
	results = append(results, m.check2_1(ctx))
	results = append(results, m.check2_2(ctx))

	// --- GKE checks ---
	results = append(results, m.check7_1(ctx))
	results = append(results, m.check7_3(ctx))
	results = append(results, m.check7_10(ctx))

	// Build output table.
	var rows [][]string
	passed, failed, notTested := 0, 0, 0
	for _, r := range results {
		status := r.Status
		switch r.Status {
		case "PASS":
			passed++
			status = output.Green + "PASS" + output.Reset
		case "FAIL":
			failed++
			status = output.Red + "FAIL" + output.Reset
		case "NOT TESTED":
			notTested++
			status = output.Yellow + "NOT TESTED" + output.Reset
		}
		affected := strings.Join(r.Affected, ", ")
		if len(affected) > 80 {
			affected = affected[:77] + "..."
		}
		rows = append(rows, []string{r.ID, status, r.Description, affected})
	}

	output.Table(
		[]string{"CHECK ID", "STATUS", "DESCRIPTION", "AFFECTED RESOURCES"},
		rows,
	)

	// Emit findings for each FAIL.
	for _, r := range results {
		if r.Status != "FAIL" {
			continue
		}
		if ctx.Findings != nil {
			ctx.Findings <- module.Finding{
				Module:      "analyze.compliance.cis-benchmark",
				Severity:    r.Severity,
				Title:       fmt.Sprintf("CIS %s: %s", r.ID, r.Description),
				Description: fmt.Sprintf("CIS Benchmark check %s failed. Affected resources: %s", r.ID, strings.Join(r.Affected, ", ")),
				Data: map[string]any{
					"check_id":           r.ID,
					"affected_resources": r.Affected,
				},
			}
		}
	}

	// Summary.
	fmt.Println()
	output.Info("CIS Benchmark Summary: %s%d/%d passed%s, %s%d/%d failed%s, %s%d/%d not tested%s",
		output.Green, passed, len(results), output.Reset,
		output.Red, failed, len(results), output.Reset,
		output.Yellow, notTested, len(results), output.Reset,
	)

	return nil
}

// queryRoleBindings returns role_bindings rows for the current workspace.
func queryRoleBindings(ctx module.RunContext) ([]roleBinding, error) {
	rows, err := ctx.Store.DB.Query(
		`SELECT identity, role, scope, project FROM role_bindings WHERE workspace_id = ?`,
		ctx.Workspace,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bindings []roleBinding
	for rows.Next() {
		var b roleBinding
		if err := rows.Scan(&b.Identity, &b.Role, &b.Scope, &b.Project); err != nil {
			return nil, err
		}
		bindings = append(bindings, b)
	}
	return bindings, rows.Err()
}

type roleBinding struct {
	Identity string
	Role     string
	Scope    string
	Project  string
}

// getResourceData unmarshals the JSON data field from a resource.
func getResourceData(dataStr string) map[string]any {
	var data map[string]any
	_ = json.Unmarshal([]byte(dataStr), &data)
	if data == nil {
		data = make(map[string]any)
	}
	return data
}

// getStringField safely extracts a string from a map.
func getStringField(data map[string]any, key string) string {
	if v, ok := data[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// getBoolField safely extracts a bool from a map.
func getBoolField(data map[string]any, key string) (bool, bool) {
	if v, ok := data[key]; ok {
		switch b := v.(type) {
		case bool:
			return b, true
		case string:
			return strings.EqualFold(b, "true"), true
		}
	}
	return false, false
}

// ---------------------------------------------------------------------------
// IAM Checks
// ---------------------------------------------------------------------------

// Check 1.1: Avoid use of roles/owner
func (m *CISBenchmark) check1_1(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "1.1",
		Description: "Ensure corporate login credentials are used (no roles/owner)",
		Severity:    module.SevCritical,
	}
	bindings, err := queryRoleBindings(ctx)
	if err != nil || len(bindings) == 0 {
		r.Status = "NOT TESTED"
		return r
	}
	r.Status = "PASS"
	for _, b := range bindings {
		if b.Role == "roles/owner" {
			r.Status = "FAIL"
			r.Affected = append(r.Affected, fmt.Sprintf("%s (roles/owner on %s)", b.Identity, b.Scope))
		}
	}
	return r
}

// Check 1.4: SA keys should be rotated
func (m *CISBenchmark) check1_4(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "1.4",
		Description: "Ensure service account keys are rotated within 90 days",
		Severity:    module.SevMedium,
	}
	resources, err := ctx.Store.ListResources(ctx.Workspace, "iam", "service_account")
	if err != nil || len(resources) == 0 {
		r.Status = "NOT TESTED"
		return r
	}
	r.Status = "PASS"
	for _, res := range resources {
		keys, ok := res.Data["keys"]
		if !ok {
			continue
		}
		// Keys may be a slice of maps with "keyType" field.
		if keyList, ok := keys.([]any); ok {
			for _, k := range keyList {
				if km, ok := k.(map[string]any); ok {
					keyType := getStringField(km, "keyType")
					if keyType == "USER_MANAGED" {
						r.Status = "FAIL"
						r.Affected = append(r.Affected, res.Name)
						break
					}
				}
			}
		}
	}
	return r
}

// Check 1.5: SA should not have admin privileges
func (m *CISBenchmark) check1_5(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "1.5",
		Description: "Ensure service accounts do not have admin privileges",
		Severity:    module.SevCritical,
	}
	bindings, err := queryRoleBindings(ctx)
	if err != nil || len(bindings) == 0 {
		r.Status = "NOT TESTED"
		return r
	}
	r.Status = "PASS"
	for _, b := range bindings {
		if !strings.HasPrefix(b.Identity, "serviceAccount:") {
			continue
		}
		if b.Role == "roles/editor" || b.Role == "roles/owner" {
			r.Status = "FAIL"
			r.Affected = append(r.Affected, fmt.Sprintf("%s (%s)", b.Identity, b.Role))
		}
	}
	return r
}

// Check 1.6: Users should not have SA user role at project level
func (m *CISBenchmark) check1_6(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "1.6",
		Description: "Ensure user: members do not have roles/iam.serviceAccountUser at project level",
		Severity:    module.SevHigh,
	}
	bindings, err := queryRoleBindings(ctx)
	if err != nil || len(bindings) == 0 {
		r.Status = "NOT TESTED"
		return r
	}
	r.Status = "PASS"
	for _, b := range bindings {
		if !strings.HasPrefix(b.Identity, "user:") {
			continue
		}
		if b.Role == "roles/iam.serviceAccountUser" && strings.HasPrefix(b.Scope, "projects/") {
			r.Status = "FAIL"
			r.Affected = append(r.Affected, fmt.Sprintf("%s (on %s)", b.Identity, b.Scope))
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// Compute Checks
// ---------------------------------------------------------------------------

// Check 4.1: Default SA should not be used on instances
func (m *CISBenchmark) check4_1(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "4.1",
		Description: "Ensure default service account is not used for instances",
		Severity:    module.SevHigh,
	}
	resources, err := ctx.Store.ListResources(ctx.Workspace, "compute", "instance")
	if err != nil || len(resources) == 0 {
		r.Status = "NOT TESTED"
		return r
	}
	r.Status = "PASS"
	for _, res := range resources {
		sa := getStringField(res.Data, "service_account")
		if sa == "" {
			sa = getStringField(res.Data, "serviceAccount")
		}
		if strings.Contains(sa, "-compute@developer.gserviceaccount.com") {
			r.Status = "FAIL"
			r.Affected = append(r.Affected, res.Name)
		}
	}
	return r
}

// Check 4.2: Instances should not have external IPs
func (m *CISBenchmark) check4_2(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "4.2",
		Description: "Ensure instances do not have public/external IP addresses",
		Severity:    module.SevHigh,
	}
	resources, err := ctx.Store.ListResources(ctx.Workspace, "compute", "instance")
	if err != nil || len(resources) == 0 {
		r.Status = "NOT TESTED"
		return r
	}
	r.Status = "PASS"
	for _, res := range resources {
		extIP := getStringField(res.Data, "external_ip")
		if extIP == "" {
			extIP = getStringField(res.Data, "externalIp")
		}
		if extIP != "" {
			r.Status = "FAIL"
			r.Affected = append(r.Affected, fmt.Sprintf("%s (%s)", res.Name, extIP))
		}
	}
	return r
}

// Check 4.4: OS Login should be enabled
func (m *CISBenchmark) check4_4(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "4.4",
		Description: "Ensure OS Login is enabled for project",
		Severity:    module.SevMedium,
	}
	// Check project metadata for os-login.
	resources, err := ctx.Store.ListResources(ctx.Workspace, "compute", "project_metadata")
	if err != nil || len(resources) == 0 {
		// Fall back to checking instances.
		instances, err2 := ctx.Store.ListResources(ctx.Workspace, "compute", "instance")
		if err2 != nil || len(instances) == 0 {
			r.Status = "NOT TESTED"
			return r
		}
		// If we have instances but no project metadata, flag it.
		r.Status = "FAIL"
		r.Affected = append(r.Affected, "project metadata not collected (os-login status unknown)")
		return r
	}
	r.Status = "PASS"
	for _, res := range resources {
		osLogin := getStringField(res.Data, "enable-oslogin")
		if osLogin == "" {
			osLogin = getStringField(res.Data, "enableOsLogin")
		}
		if !strings.EqualFold(osLogin, "true") {
			r.Status = "FAIL"
			r.Affected = append(r.Affected, fmt.Sprintf("project %s", res.Project))
		}
	}
	return r
}

// Check 4.6: Serial port should be disabled
func (m *CISBenchmark) check4_6(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "4.6",
		Description: "Ensure serial port access is disabled on instances",
		Severity:    module.SevMedium,
	}
	resources, err := ctx.Store.ListResources(ctx.Workspace, "compute", "instance")
	if err != nil || len(resources) == 0 {
		r.Status = "NOT TESTED"
		return r
	}
	r.Status = "PASS"
	for _, res := range resources {
		serial := getStringField(res.Data, "serial_port_enabled")
		if serial == "" {
			serial = getStringField(res.Data, "serialPortEnabled")
		}
		if strings.EqualFold(serial, "true") {
			r.Status = "FAIL"
			r.Affected = append(r.Affected, res.Name)
		}
	}
	// Also check project metadata.
	pmResources, err := ctx.Store.ListResources(ctx.Workspace, "compute", "project_metadata")
	if err == nil {
		for _, res := range pmResources {
			serial := getStringField(res.Data, "serial-port-enable")
			if serial == "" {
				serial = getStringField(res.Data, "serialPortEnable")
			}
			if strings.EqualFold(serial, "true") {
				r.Status = "FAIL"
				r.Affected = append(r.Affected, fmt.Sprintf("project %s (metadata)", res.Project))
			}
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// Storage Checks
// ---------------------------------------------------------------------------

// Check 5.1: Buckets should not be publicly accessible
func (m *CISBenchmark) check5_1(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "5.1",
		Description: "Ensure Cloud Storage buckets are not publicly accessible",
		Severity:    module.SevHigh,
	}
	resources, err := ctx.Store.ListResources(ctx.Workspace, "storage", "bucket")
	if err != nil || len(resources) == 0 {
		r.Status = "NOT TESTED"
		return r
	}
	r.Status = "PASS"
	for _, res := range resources {
		pap := getStringField(res.Data, "public_access_prevention")
		if pap == "" {
			pap = getStringField(res.Data, "publicAccessPrevention")
		}
		if !strings.EqualFold(pap, "enforced") {
			r.Status = "FAIL"
			r.Affected = append(r.Affected, res.Name)
		}
	}
	return r
}

// Check 5.2: Bucket versioning should be enabled
func (m *CISBenchmark) check5_2(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "5.2",
		Description: "Ensure Cloud Storage bucket versioning is enabled",
		Severity:    module.SevMedium,
	}
	resources, err := ctx.Store.ListResources(ctx.Workspace, "storage", "bucket")
	if err != nil || len(resources) == 0 {
		r.Status = "NOT TESTED"
		return r
	}
	r.Status = "PASS"
	for _, res := range resources {
		versioning, exists := getBoolField(res.Data, "versioning")
		if !exists {
			versioningStr := getStringField(res.Data, "versioning")
			if strings.EqualFold(versioningStr, "false") || versioningStr == "" {
				r.Status = "FAIL"
				r.Affected = append(r.Affected, res.Name)
			}
			continue
		}
		if !versioning {
			r.Status = "FAIL"
			r.Affected = append(r.Affected, res.Name)
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// Network Checks
// ---------------------------------------------------------------------------

// checkFirewallForPort checks firewall rules for unrestricted access on a given port.
func (m *CISBenchmark) checkFirewallForPort(ctx module.RunContext, port string) ([]string, bool) {
	resources, err := ctx.Store.ListResources(ctx.Workspace, "compute", "firewall")
	if err != nil || len(resources) == 0 {
		return nil, false
	}
	var affected []string
	for _, res := range resources {
		direction := getStringField(res.Data, "direction")
		if strings.EqualFold(direction, "EGRESS") {
			continue
		}
		// Check source ranges for 0.0.0.0/0.
		if !hasUnrestrictedSource(res.Data) {
			continue
		}
		// Check if the rule allows traffic on the target port.
		if allowsPort(res.Data, port) {
			affected = append(affected, res.Name)
		}
	}
	return affected, true
}

// hasUnrestrictedSource checks if a firewall rule has 0.0.0.0/0 in source ranges.
func hasUnrestrictedSource(data map[string]any) bool {
	for _, key := range []string{"source_ranges", "sourceRanges"} {
		if v, ok := data[key]; ok {
			switch ranges := v.(type) {
			case []any:
				for _, r := range ranges {
					if s, ok := r.(string); ok && s == "0.0.0.0/0" {
						return true
					}
				}
			case string:
				if strings.Contains(ranges, "0.0.0.0/0") {
					return true
				}
			}
		}
	}
	return false
}

// allowsPort checks if a firewall rule allows a specific port.
func allowsPort(data map[string]any, targetPort string) bool {
	for _, key := range []string{"allowed", "rules"} {
		if v, ok := data[key]; ok {
			if rules, ok := v.([]any); ok {
				for _, rule := range rules {
					if rm, ok := rule.(map[string]any); ok {
						protocol := getStringField(rm, "IPProtocol")
						if protocol == "" {
							protocol = getStringField(rm, "protocol")
						}
						if protocol != "tcp" && protocol != "all" {
							continue
						}
						if protocol == "all" {
							return true
						}
						if ports, ok := rm["ports"]; ok {
							if portList, ok := ports.([]any); ok {
								for _, p := range portList {
									ps := fmt.Sprintf("%v", p)
									if ps == targetPort || ps == "0-65535" || strings.Contains(ps, targetPort) {
										return true
									}
								}
							}
						} else {
							// TCP with no port restriction = all ports.
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// Check 3.6: SSH access should be restricted
func (m *CISBenchmark) check3_6(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "3.6",
		Description: "Ensure SSH access is restricted from the internet",
		Severity:    module.SevHigh,
	}
	affected, hasData := m.checkFirewallForPort(ctx, "22")
	if !hasData {
		r.Status = "NOT TESTED"
		return r
	}
	if len(affected) > 0 {
		r.Status = "FAIL"
		r.Affected = affected
	} else {
		r.Status = "PASS"
	}
	return r
}

// Check 3.7: RDP access should be restricted
func (m *CISBenchmark) check3_7(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "3.7",
		Description: "Ensure RDP access is restricted from the internet",
		Severity:    module.SevHigh,
	}
	affected, hasData := m.checkFirewallForPort(ctx, "3389")
	if !hasData {
		r.Status = "NOT TESTED"
		return r
	}
	if len(affected) > 0 {
		r.Status = "FAIL"
		r.Affected = affected
	} else {
		r.Status = "PASS"
	}
	return r
}

// ---------------------------------------------------------------------------
// Database Checks
// ---------------------------------------------------------------------------

// Check 6.1: Cloud SQL should require SSL
func (m *CISBenchmark) check6_1(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "6.1",
		Description: "Ensure Cloud SQL instances require SSL connections",
		Severity:    module.SevHigh,
	}
	resources, err := ctx.Store.ListResources(ctx.Workspace, "cloudsql", "instance")
	if err != nil || len(resources) == 0 {
		r.Status = "NOT TESTED"
		return r
	}
	r.Status = "PASS"
	for _, res := range resources {
		sslRequired, exists := getBoolField(res.Data, "ssl_required")
		if !exists {
			sslRequired, exists = getBoolField(res.Data, "sslRequired")
		}
		if exists && !sslRequired {
			r.Status = "FAIL"
			r.Affected = append(r.Affected, res.Name)
		}
		// Also check requireSsl inside settings.ipConfiguration.
		if !exists {
			sslStr := getStringField(res.Data, "ssl_required")
			if sslStr == "" {
				sslStr = getStringField(res.Data, "sslRequired")
			}
			if strings.EqualFold(sslStr, "false") {
				r.Status = "FAIL"
				r.Affected = append(r.Affected, res.Name)
			}
		}
	}
	return r
}

// Check 6.2: Cloud SQL should not have public IPs
func (m *CISBenchmark) check6_2(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "6.2",
		Description: "Ensure Cloud SQL instances do not have public IPs",
		Severity:    module.SevHigh,
	}
	resources, err := ctx.Store.ListResources(ctx.Workspace, "cloudsql", "instance")
	if err != nil || len(resources) == 0 {
		r.Status = "NOT TESTED"
		return r
	}
	r.Status = "PASS"
	for _, res := range resources {
		publicIP := getStringField(res.Data, "public_ip")
		if publicIP == "" {
			publicIP = getStringField(res.Data, "publicIp")
		}
		if publicIP != "" {
			r.Status = "FAIL"
			r.Affected = append(r.Affected, fmt.Sprintf("%s (%s)", res.Name, publicIP))
		}
	}
	return r
}

// Check 6.5: Cloud SQL should not allow 0.0.0.0/0
func (m *CISBenchmark) check6_5(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "6.5",
		Description: "Ensure Cloud SQL does not allow 0.0.0.0/0 in authorized networks",
		Severity:    module.SevCritical,
	}
	resources, err := ctx.Store.ListResources(ctx.Workspace, "cloudsql", "instance")
	if err != nil || len(resources) == 0 {
		r.Status = "NOT TESTED"
		return r
	}
	r.Status = "PASS"
	for _, res := range resources {
		for _, key := range []string{"authorized_networks", "authorizedNetworks"} {
			if v, ok := res.Data[key]; ok {
				raw, _ := json.Marshal(v)
				if strings.Contains(string(raw), "0.0.0.0/0") {
					r.Status = "FAIL"
					r.Affected = append(r.Affected, res.Name)
					break
				}
			}
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// Logging Checks
// ---------------------------------------------------------------------------

// Check 2.1: Log sinks should be configured
func (m *CISBenchmark) check2_1(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "2.1",
		Description: "Ensure log sinks are configured for all projects",
		Severity:    module.SevMedium,
	}
	sinks, err := ctx.Store.ListResources(ctx.Workspace, "logging", "sink")
	if err != nil {
		r.Status = "NOT TESTED"
		return r
	}
	// Check if we have any logging data at all.
	if len(sinks) == 0 {
		// Check if we have any resources to compare against.
		counts, err := ctx.Store.CountResources(ctx.Workspace)
		if err != nil || len(counts) == 0 {
			r.Status = "NOT TESTED"
			return r
		}
		// We have other resources but no sinks -- flag it.
		r.Status = "FAIL"
		r.Affected = append(r.Affected, "no log sinks found in collected data")
		return r
	}
	r.Status = "PASS"
	return r
}

// Check 2.2: Log sinks should not be disabled
func (m *CISBenchmark) check2_2(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "2.2",
		Description: "Ensure log sinks are not disabled",
		Severity:    module.SevMedium,
	}
	sinks, err := ctx.Store.ListResources(ctx.Workspace, "logging", "sink")
	if err != nil || len(sinks) == 0 {
		r.Status = "NOT TESTED"
		return r
	}
	r.Status = "PASS"
	for _, res := range sinks {
		disabled, exists := getBoolField(res.Data, "disabled")
		if exists && disabled {
			r.Status = "FAIL"
			r.Affected = append(r.Affected, res.Name)
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// GKE Checks
// ---------------------------------------------------------------------------

// Check 7.1: Legacy ABAC should be disabled
func (m *CISBenchmark) check7_1(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "7.1",
		Description: "Ensure legacy ABAC is disabled on GKE clusters",
		Severity:    module.SevHigh,
	}
	resources, err := ctx.Store.ListResources(ctx.Workspace, "gke", "cluster")
	if err != nil || len(resources) == 0 {
		r.Status = "NOT TESTED"
		return r
	}
	r.Status = "PASS"
	for _, res := range resources {
		legacyAbac, exists := getBoolField(res.Data, "legacy_abac")
		if !exists {
			legacyAbac, exists = getBoolField(res.Data, "legacyAbac")
		}
		if exists && legacyAbac {
			r.Status = "FAIL"
			r.Affected = append(r.Affected, res.Name)
		}
	}
	return r
}

// Check 7.3: Network policy should be enabled
func (m *CISBenchmark) check7_3(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "7.3",
		Description: "Ensure network policy is enabled on GKE clusters",
		Severity:    module.SevMedium,
	}
	resources, err := ctx.Store.ListResources(ctx.Workspace, "gke", "cluster")
	if err != nil || len(resources) == 0 {
		r.Status = "NOT TESTED"
		return r
	}
	r.Status = "PASS"
	for _, res := range resources {
		netPolicy, exists := getBoolField(res.Data, "network_policy")
		if !exists {
			netPolicy, exists = getBoolField(res.Data, "networkPolicy")
		}
		if exists && !netPolicy {
			r.Status = "FAIL"
			r.Affected = append(r.Affected, res.Name)
		}
	}
	return r
}

// Check 7.10: Master basic auth should be disabled
func (m *CISBenchmark) check7_10(ctx module.RunContext) checkResult {
	r := checkResult{
		ID:          "7.10",
		Description: "Ensure master basic authentication is disabled on GKE clusters",
		Severity:    module.SevCritical,
	}
	resources, err := ctx.Store.ListResources(ctx.Workspace, "gke", "cluster")
	if err != nil || len(resources) == 0 {
		r.Status = "NOT TESTED"
		return r
	}
	r.Status = "PASS"
	for _, res := range resources {
		basicAuth, exists := getBoolField(res.Data, "master_basic_auth")
		if !exists {
			basicAuth, exists = getBoolField(res.Data, "masterBasicAuth")
		}
		if exists && basicAuth {
			r.Status = "FAIL"
			r.Affected = append(r.Affected, res.Name)
		}
	}
	return r
}
