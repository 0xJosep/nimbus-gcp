package whatcanido

import (
	"fmt"
	"sort"
	"strings"

	"github.com/user/nimbus/internal/db"
	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
	"github.com/user/nimbus/internal/privesc"
)

func init() {
	module.Register(&WhatCanIDo{})
}

// Action describes an available attack action the current identity can perform.
type Action struct {
	Name                string
	Description         string
	Severity            string
	Category            string
	Technique           *privesc.Technique
	RequiredPermissions []string
	Command             string
}

// WhatCanIDo analyzes the current session's permissions and reports every
// available attack technique, ranked by impact.
type WhatCanIDo struct{}

func (m *WhatCanIDo) Info() module.Info {
	return module.Info{
		Name:         "analyze.whatcanido",
		Tactic:       module.TacticAnalyze,
		Service:      "all",
		Description:  "Determine every available attack based on granted permissions and rank by impact",
		RequiresAuth: false,
		Concurrent:   false,
	}
}

func (m *WhatCanIDo) Run(ctx module.RunContext) error {
	if ctx.Session == nil {
		output.Error("No active session")
		return fmt.Errorf("no active session")
	}

	// Step A: Load all granted permissions for the current session.
	perms, err := ctx.Store.ListGrantedPermissions(ctx.Session.ID)
	if err != nil {
		return fmt.Errorf("list granted permissions: %w", err)
	}
	if len(perms) == 0 {
		output.Warn("No granted permissions found for this session. Run recon.iam.bruteforce-permissions first.")
		return nil
	}

	var permStrings []string
	permSet := make(map[string]bool)
	for _, p := range perms {
		if !permSet[p.Permission] {
			permSet[p.Permission] = true
			permStrings = append(permStrings, p.Permission)
		}
	}

	output.Info("Analyzing %d granted permissions for %s", len(permStrings), ctx.Session.Email)
	fmt.Println()

	// Load discovered resources for target-specific commands.
	serviceAccounts := listResourceNames(ctx.Store, ctx.Workspace, "iam", "service_account")
	buckets := listResourceNames(ctx.Store, ctx.Workspace, "storage", "bucket")
	instances := listResourceNames(ctx.Store, ctx.Workspace, "compute", "instance")
	secrets := listResourceNames(ctx.Store, ctx.Workspace, "secretmanager", "secret")
	bqDatasets := listResourceNames(ctx.Store, ctx.Workspace, "bigquery", "dataset")
	functions := listResourceNames(ctx.Store, ctx.Workspace, "cloudfunctions", "function")
	projects := gatherProjects(ctx)

	// Step B: Match against privesc techniques (full and partial).
	matches := privesc.MatchTechniques(permStrings)

	var actions []Action

	// Build privesc actions from technique matches.
	for _, match := range matches {
		if !match.FullMatch {
			continue
		}
		tech := match.Technique
		category := categoryForTechnique(tech)
		cmds := commandsForTechnique(tech, serviceAccounts, instances, functions, projects)
		for _, cmd := range cmds {
			actions = append(actions, Action{
				Name:                tech.Name,
				Description:         tech.Description,
				Severity:            tech.Severity,
				Category:            category,
				Technique:           &tech,
				RequiredPermissions: tech.Permissions,
				Command:             cmd,
			})
		}
	}

	// Partial matches as informational.
	for _, match := range matches {
		if match.FullMatch {
			continue
		}
		tech := match.Technique
		actions = append(actions, Action{
			Name:                fmt.Sprintf("%s (partial — %.0f%%)", tech.Name, match.MatchPercentage),
			Description:         fmt.Sprintf("%s [missing: %s]", tech.Description, strings.Join(match.MissingPerms, ", ")),
			Severity:            "LOW",
			Category:            categoryForTechnique(tech),
			Technique:           &tech,
			RequiredPermissions: match.MatchedPerms,
			Command:             "# acquire missing permissions: " + strings.Join(match.MissingPerms, ", "),
		})
	}

	// Step C: Data access capabilities.
	if permSet["secretmanager.versions.access"] {
		for _, proj := range projects {
			if len(secrets) > 0 {
				for _, s := range secrets {
					actions = append(actions, Action{
						Name:                "Read Secret Value",
						Description:         fmt.Sprintf("Access secret value: %s", s),
						Severity:            "HIGH",
						Category:            catDataAccess,
						RequiredPermissions: []string{"secretmanager.versions.access"},
						Command:             fmt.Sprintf("run exfil.secrets.dump-values -p %s --secret %s", proj, s),
					})
				}
			} else {
				actions = append(actions, Action{
					Name:                "Read Secrets from Secret Manager",
					Description:         "Access secret values which may contain credentials, API keys, or other sensitive data",
					Severity:            "HIGH",
					Category:            catDataAccess,
					RequiredPermissions: []string{"secretmanager.versions.access"},
					Command:             fmt.Sprintf("run exfil.secrets.dump-values -p %s", proj),
				})
			}
		}
	}

	if permSet["storage.objects.get"] || permSet["storage.objects.list"] {
		for _, b := range buckets {
			actions = append(actions, Action{
				Name:                "Read Storage Bucket Objects",
				Description:         fmt.Sprintf("List and read objects in bucket: %s", b),
				Severity:            "HIGH",
				Category:            catDataAccess,
				RequiredPermissions: []string{"storage.objects.get"},
				Command:             fmt.Sprintf("run exfil.storage.dump-bucket --bucket %s", b),
			})
		}
		if len(buckets) == 0 {
			for _, proj := range projects {
				actions = append(actions, Action{
					Name:                "List and Read Storage Buckets",
					Description:         "Enumerate and read objects from Cloud Storage buckets",
					Severity:            "HIGH",
					Category:            catDataAccess,
					RequiredPermissions: []string{"storage.objects.get"},
					Command:             fmt.Sprintf("run exfil.storage.dump-bucket -p %s", proj),
				})
			}
		}
	}

	if permSet["bigquery.tables.getData"] || permSet["bigquery.jobs.create"] {
		for _, proj := range projects {
			if len(bqDatasets) > 0 {
				for _, ds := range bqDatasets {
					actions = append(actions, Action{
						Name:                "Query BigQuery Dataset",
						Description:         fmt.Sprintf("Query data from BigQuery dataset: %s", ds),
						Severity:            "HIGH",
						Category:            catDataAccess,
						RequiredPermissions: []string{"bigquery.tables.getData", "bigquery.jobs.create"},
						Command:             fmt.Sprintf("run exfil.bigquery.dump-tables -p %s --dataset %s", proj, ds),
					})
				}
			} else {
				actions = append(actions, Action{
					Name:                "Query BigQuery Datasets",
					Description:         "Query and exfiltrate data from BigQuery datasets",
					Severity:            "HIGH",
					Category:            catDataAccess,
					RequiredPermissions: []string{"bigquery.tables.getData", "bigquery.jobs.create"},
					Command:             fmt.Sprintf("run exfil.bigquery.dump-tables -p %s", proj),
				})
			}
		}
	}

	if permSet["cloudsql.instances.export"] {
		for _, proj := range projects {
			actions = append(actions, Action{
				Name:                "Export Cloud SQL Database",
				Description:         "Export Cloud SQL database to an attacker-controlled bucket",
				Severity:            "HIGH",
				Category:            catDataAccess,
				RequiredPermissions: []string{"cloudsql.instances.export"},
				Command:             fmt.Sprintf("run exfil.cloudsql.export -p %s", proj),
			})
		}
	}

	// Step D: Lateral movement capabilities.
	if permSet["compute.instances.osLogin"] || permSet["compute.instances.setMetadata"] {
		for _, inst := range instances {
			actions = append(actions, Action{
				Name:                "SSH into Compute Instance",
				Description:         fmt.Sprintf("SSH into instance %s to access its SA token", inst),
				Severity:            "HIGH",
				Category:            catLateralMovement,
				RequiredPermissions: []string{"compute.instances.osLogin"},
				Command:             fmt.Sprintf("run lateral.compute.ssh --instance %s", inst),
			})
		}
		if len(instances) == 0 {
			for _, proj := range projects {
				actions = append(actions, Action{
					Name:                "SSH into Compute Instances",
					Description:         "SSH into VM instances to access attached SA tokens",
					Severity:            "HIGH",
					Category:            catLateralMovement,
					RequiredPermissions: []string{"compute.instances.osLogin"},
					Command:             fmt.Sprintf("run lateral.compute.ssh -p %s", proj),
				})
			}
		}
	}

	if permSet["container.pods.exec"] {
		for _, proj := range projects {
			actions = append(actions, Action{
				Name:                "Exec into GKE Pods",
				Description:         "Execute commands inside GKE pods for lateral movement",
				Severity:            "HIGH",
				Category:            catLateralMovement,
				RequiredPermissions: []string{"container.pods.exec"},
				Command:             fmt.Sprintf("run lateral.gke.exec-pod -p %s", proj),
			})
		}
	}

	if permSet["iam.serviceAccounts.getAccessToken"] {
		for _, sa := range serviceAccounts {
			actions = append(actions, Action{
				Name:                "Impersonate Service Account",
				Description:         fmt.Sprintf("Generate access token to impersonate %s", sa),
				Severity:            "CRITICAL",
				Category:            catLateralMovement,
				RequiredPermissions: []string{"iam.serviceAccounts.getAccessToken"},
				Command:             fmt.Sprintf("run lateral.iam.impersonate-sa --target-sa %s", sa),
			})
		}
	}

	// Persistence capabilities.
	if permSet["iam.serviceAccountKeys.create"] {
		for _, sa := range serviceAccounts {
			actions = append(actions, Action{
				Name:                "Create Persistent SA Key",
				Description:         fmt.Sprintf("Create a long-lived key for %s", sa),
				Severity:            "CRITICAL",
				Category:            catPersistence,
				RequiredPermissions: []string{"iam.serviceAccountKeys.create"},
				Command:             fmt.Sprintf("run persist.iam.create-sa-key --target-sa %s", sa),
			})
		}
	}

	if permSet["resourcemanager.projects.setIamPolicy"] {
		for _, proj := range projects {
			actions = append(actions, Action{
				Name:                "Add Backdoor IAM Binding",
				Description:         fmt.Sprintf("Add a new IAM binding to project %s for persistent access", proj),
				Severity:            "CRITICAL",
				Category:            catPersistence,
				RequiredPermissions: []string{"resourcemanager.projects.setIamPolicy"},
				Command:             fmt.Sprintf("run persist.iam.backdoor-policy -p %s", proj),
			})
		}
	}

	if permSet["cloudfunctions.functions.create"] && permSet["iam.serviceAccounts.actAs"] {
		for _, proj := range projects {
			actions = append(actions, Action{
				Name:                "Deploy Backdoor Cloud Function",
				Description:         fmt.Sprintf("Deploy a Cloud Function for persistent access in %s", proj),
				Severity:            "HIGH",
				Category:            catPersistence,
				RequiredPermissions: []string{"cloudfunctions.functions.create", "iam.serviceAccounts.actAs"},
				Command:             fmt.Sprintf("run persist.functions.deploy-backdoor -p %s", proj),
			})
		}
	}

	// Credential theft capabilities.
	if permSet["secretmanager.versions.access"] {
		for _, proj := range projects {
			actions = append(actions, Action{
				Name:                "Dump Credentials from Secrets",
				Description:         "Extract credentials, API keys, and tokens stored in Secret Manager",
				Severity:            "CRITICAL",
				Category:            catCredentialTheft,
				RequiredPermissions: []string{"secretmanager.versions.access"},
				Command:             fmt.Sprintf("run credential.secrets.extract-creds -p %s", proj),
			})
		}
	}

	if permSet["compute.instances.getSerialPortOutput"] {
		for _, inst := range instances {
			actions = append(actions, Action{
				Name:                "Read Serial Port Output",
				Description:         fmt.Sprintf("Read serial output from %s for leaked credentials", inst),
				Severity:            "MEDIUM",
				Category:            catCredentialTheft,
				RequiredPermissions: []string{"compute.instances.getSerialPortOutput"},
				Command:             fmt.Sprintf("run credential.compute.serial-output --instance %s", inst),
			})
		}
	}

	if permSet["storage.hmacKeys.create"] {
		for _, sa := range serviceAccounts {
			actions = append(actions, Action{
				Name:                "Create HMAC Key",
				Description:         fmt.Sprintf("Create S3-compatible HMAC credentials for %s", sa),
				Severity:            "MEDIUM",
				Category:            catCredentialTheft,
				RequiredPermissions: []string{"storage.hmacKeys.create"},
				Command:             fmt.Sprintf("run credential.storage.create-hmac --target-sa %s", sa),
			})
		}
	}

	if len(actions) == 0 {
		output.Info("No actionable attack techniques found with current permissions.")
		output.Info("Try running recon.iam.bruteforce-permissions to discover more permissions.")
		return nil
	}

	// Deduplicate actions by command.
	actions = deduplicateActions(actions)

	// Sort by severity then name.
	sort.Slice(actions, func(i, j int) bool {
		si := severityRank(actions[i].Severity)
		sj := severityRank(actions[j].Severity)
		if si != sj {
			return si < sj
		}
		return actions[i].Name < actions[j].Name
	})

	// Group by category and output.
	categories := []struct {
		key  string
		icon string
	}{
		{catPrivesc, ">>>"},
		{catDataAccess, ">>>"},
		{catLateralMovement, ">>>"},
		{catPersistence, ">>>"},
		{catCredentialTheft, ">>>"},
	}

	categoryIcons := map[string]string{
		catPrivesc:         "PRIVILEGE ESCALATION",
		catDataAccess:      "DATA ACCESS",
		catLateralMovement: "LATERAL MOVEMENT",
		catPersistence:     "PERSISTENCE",
		catCredentialTheft: "CREDENTIAL THEFT",
	}

	totalActions := 0
	for _, cat := range categories {
		var catActions []Action
		for _, a := range actions {
			if a.Category == cat.key {
				catActions = append(catActions, a)
			}
		}
		if len(catActions) == 0 {
			continue
		}
		totalActions += len(catActions)
		label := categoryIcons[cat.key]
		fmt.Printf("%s%s=== %s (%d available) ===%s\n",
			output.Bold, colorForCategory(cat.key), label, len(catActions), output.Reset)
		fmt.Println()

		for _, a := range catActions {
			sevColor := colorForSeverity(a.Severity)
			fmt.Printf("  %s[%s]%s %s\n", sevColor, a.Severity, output.Reset, a.Name)
			fmt.Printf("    %s%s%s\n", output.Dim, a.Description, output.Reset)
			fmt.Printf("    %s-> %s%s\n", output.Cyan, a.Command, output.Reset)
			fmt.Println()
		}
	}

	// Summary.
	fmt.Printf("%s%s=== SUMMARY ===%s\n", output.Bold, output.Cyan, output.Reset)
	fmt.Printf("  %d total actions available across %d categories\n", totalActions, countCategories(actions))
	fmt.Println()

	// Emit findings.
	if ctx.Findings != nil {
		ctx.Findings <- module.Finding{
			Module:   "analyze.whatcanido",
			Severity: module.SevInfo,
			Title:    fmt.Sprintf("%d attack actions available", totalActions),
			Description: fmt.Sprintf(
				"Analysis of %d granted permissions identified %d available attack actions across privilege escalation, data access, lateral movement, persistence, and credential theft categories.",
				len(permStrings), totalActions,
			),
			Data: map[string]any{
				"total_permissions": len(permStrings),
				"total_actions":    totalActions,
			},
		}
	}

	return nil
}

// Category constants.
const (
	catPrivesc         = "privesc"
	catDataAccess      = "data_access"
	catLateralMovement = "lateral_movement"
	catPersistence     = "persistence"
	catCredentialTheft = "credential_theft"
)

func categoryForTechnique(t privesc.Technique) string {
	switch t.ID {
	case "NIM-001", "NIM-002", "NIM-003", "NIM-004", "NIM-005",
		"NIM-006", "NIM-007", "NIM-008", "NIM-011", "NIM-013",
		"NIM-015", "NIM-018":
		return catPrivesc
	case "NIM-016", "NIM-017":
		return catDataAccess
	case "NIM-009", "NIM-010", "NIM-019":
		return catLateralMovement
	case "NIM-020":
		return catPersistence
	case "NIM-012":
		return catPrivesc
	case "NIM-014":
		return catCredentialTheft
	}
	return catPrivesc
}

func commandsForTechnique(t privesc.Technique, sas, instances, functions, projects []string) []string {
	var cmds []string
	switch t.ID {
	case "NIM-001": // SA Key Creation
		for _, sa := range sas {
			cmds = append(cmds, fmt.Sprintf("run privesc.iam.escalate-sa-key-create --target-sa %s", sa))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run privesc.iam.escalate-sa-key-create --target-sa <service-account-email>")
		}
	case "NIM-002": // SA Impersonation
		for _, sa := range sas {
			cmds = append(cmds, fmt.Sprintf("run privesc.iam.escalate-sa-impersonate --target-sa %s", sa))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run privesc.iam.escalate-sa-impersonate --target-sa <service-account-email>")
		}
	case "NIM-003": // Implicit Delegation
		for _, sa := range sas {
			cmds = append(cmds, fmt.Sprintf("run privesc.iam.escalate-delegation --target-sa %s", sa))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run privesc.iam.escalate-delegation --target-sa <service-account-email>")
		}
	case "NIM-004": // signBlob
		for _, sa := range sas {
			cmds = append(cmds, fmt.Sprintf("run privesc.iam.escalate-sign-blob --target-sa %s", sa))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run privesc.iam.escalate-sign-blob --target-sa <service-account-email>")
		}
	case "NIM-005": // signJwt
		for _, sa := range sas {
			cmds = append(cmds, fmt.Sprintf("run privesc.iam.escalate-sign-jwt --target-sa %s", sa))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run privesc.iam.escalate-sign-jwt --target-sa <service-account-email>")
		}
	case "NIM-006": // Project IAM
		for _, p := range projects {
			cmds = append(cmds, fmt.Sprintf("run privesc.iam.escalate-set-policy -p %s", p))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run privesc.iam.escalate-set-policy -p <project-id>")
		}
	case "NIM-007": // Org IAM
		cmds = append(cmds, "run privesc.iam.escalate-org-policy --org <org-id>")
	case "NIM-008": // Custom Role Update
		for _, p := range projects {
			cmds = append(cmds, fmt.Sprintf("run privesc.iam.escalate-role-update -p %s", p))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run privesc.iam.escalate-role-update -p <project-id>")
		}
	case "NIM-009": // Startup Script
		for _, inst := range instances {
			cmds = append(cmds, fmt.Sprintf("run privesc.compute.escalate-startup-script --instance %s", inst))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run privesc.compute.escalate-startup-script --instance <instance-name>")
		}
	case "NIM-010": // SSH Key Injection
		for _, inst := range instances {
			cmds = append(cmds, fmt.Sprintf("run privesc.compute.escalate-ssh-key --instance %s", inst))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run privesc.compute.escalate-ssh-key --instance <instance-name>")
		}
	case "NIM-011": // Cloud Function Deploy
		for _, sa := range sas {
			cmds = append(cmds, fmt.Sprintf("run privesc.functions.escalate-deploy --target-sa %s", sa))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run privesc.functions.escalate-deploy --target-sa <service-account-email>")
		}
	case "NIM-012": // Cloud Function Update
		for _, fn := range functions {
			cmds = append(cmds, fmt.Sprintf("run privesc.functions.escalate-update --function %s", fn))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run privesc.functions.escalate-update --function <function-name>")
		}
	case "NIM-013": // Cloud Run Deploy
		for _, sa := range sas {
			cmds = append(cmds, fmt.Sprintf("run privesc.run.escalate-deploy --target-sa %s", sa))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run privesc.run.escalate-deploy --target-sa <service-account-email>")
		}
	case "NIM-014": // HMAC Key
		for _, sa := range sas {
			cmds = append(cmds, fmt.Sprintf("run credential.storage.create-hmac --target-sa %s", sa))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run credential.storage.create-hmac --target-sa <service-account-email>")
		}
	case "NIM-015": // Compute Instance Create as SA
		for _, sa := range sas {
			cmds = append(cmds, fmt.Sprintf("run privesc.compute.escalate-create-instance --target-sa %s", sa))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run privesc.compute.escalate-create-instance --target-sa <service-account-email>")
		}
	case "NIM-016": // Secret Access
		for _, p := range projects {
			cmds = append(cmds, fmt.Sprintf("run exfil.secrets.dump-values -p %s", p))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run exfil.secrets.dump-values -p <project-id>")
		}
	case "NIM-017": // Cloud SQL Export
		for _, p := range projects {
			cmds = append(cmds, fmt.Sprintf("run exfil.cloudsql.export -p %s", p))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run exfil.cloudsql.export -p <project-id>")
		}
	case "NIM-018": // Folder IAM
		cmds = append(cmds, "run privesc.iam.escalate-folder-policy --folder <folder-id>")
	case "NIM-019": // OS Login
		for _, inst := range instances {
			cmds = append(cmds, fmt.Sprintf("run lateral.compute.os-login --instance %s", inst))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run lateral.compute.os-login --instance <instance-name>")
		}
	case "NIM-020": // Logging Sink Disable
		for _, p := range projects {
			cmds = append(cmds, fmt.Sprintf("run defense-evasion.logging.disable-sinks -p %s", p))
		}
		if len(cmds) == 0 {
			cmds = append(cmds, "run defense-evasion.logging.disable-sinks -p <project-id>")
		}
	default:
		cmds = append(cmds, fmt.Sprintf("# no specific command mapped for technique %s", t.ID))
	}
	return cmds
}

func listResourceNames(store *db.Store, workspaceID int64, service, resourceType string) []string {
	resources, err := store.ListResources(workspaceID, service, resourceType)
	if err != nil {
		return nil
	}
	var names []string
	for _, r := range resources {
		names = append(names, r.Name)
	}
	return names
}

func gatherProjects(ctx module.RunContext) []string {
	if len(ctx.Projects) > 0 {
		return ctx.Projects
	}
	if ctx.Session != nil && ctx.Session.Project != "" {
		return []string{ctx.Session.Project}
	}
	return []string{"<project-id>"}
}

func severityRank(s string) int {
	switch s {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	default:
		return 4
	}
}

func colorForSeverity(s string) string {
	switch s {
	case "CRITICAL":
		return output.Red + output.Bold
	case "HIGH":
		return output.Red
	case "MEDIUM":
		return output.Yellow
	case "LOW":
		return output.Blue
	default:
		return output.Dim
	}
}

func colorForCategory(cat string) string {
	switch cat {
	case catPrivesc:
		return output.Red
	case catDataAccess:
		return output.Yellow
	case catLateralMovement:
		return output.Cyan
	case catPersistence:
		return output.Blue
	case catCredentialTheft:
		return output.Red
	default:
		return output.Dim
	}
}

func countCategories(actions []Action) int {
	seen := make(map[string]bool)
	for _, a := range actions {
		seen[a.Category] = true
	}
	return len(seen)
}

func deduplicateActions(actions []Action) []Action {
	seen := make(map[string]bool)
	var result []Action
	for _, a := range actions {
		key := a.Category + "|" + a.Command
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, a)
	}
	return result
}
