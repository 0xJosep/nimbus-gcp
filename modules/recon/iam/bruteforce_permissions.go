package iam

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	crm "google.golang.org/api/cloudresourcemanager/v1"

	"github.com/user/nimbus/internal/module"
	"github.com/user/nimbus/internal/output"
	"github.com/user/nimbus/internal/privesc"
)

func init() {
	module.Register(&BruteforcePermissions{})
	allPermissions = make([]string, 0, len(curatedPermissions)+len(additionalPermissions))
	allPermissions = append(allPermissions, curatedPermissions...)
	allPermissions = append(allPermissions, additionalPermissions...)
}

// BruteforcePermissions tests which permissions the current identity holds on target projects
// using the Cloud Resource Manager testIamPermissions API.
type BruteforcePermissions struct{}

func (m *BruteforcePermissions) Info() module.Info {
	return module.Info{
		Name:         "recon.iam.bruteforce-permissions",
		Tactic:       module.TacticRecon,
		Service:      "iam",
		Description:  "Brute-force test IAM permissions on target projects",
		RequiresAuth: true,
		Concurrent:   true,
		AttackID:     "T1069.003",
	}
}

func (m *BruteforcePermissions) Run(ctx module.RunContext) error {
	if projects := module.EnsureProjects(&ctx); len(projects) == 0 {
		return nil
	}

	svc, err := crm.NewService(context.Background(), ctx.Session.ClientOption())
	if err != nil {
		return fmt.Errorf("create CRM client: %w", err)
	}

	// Determine which permission list to use.
	permList := curatedPermissions
	if v, ok := ctx.Flags["all-permissions"]; ok && (v == "true" || v == "") {
		permList = allPermissions
	}

	// Build the set of dangerous permissions from known privesc techniques.
	dangerousPerms := buildDangerousSet()

	for _, project := range ctx.Projects {
		output.Info("Testing %d permissions on project: %s", len(permList), project)

		granted, err := testPermissionsConcurrent(svc, project, permList, ctx.Concurrency)
		if err != nil {
			output.Error("Project %s: %v", project, err)
			continue
		}

		// Save each granted permission to the DB.
		for _, perm := range granted {
			if saveErr := ctx.Store.SavePermission(
				ctx.Session.ID, "project", project, perm, true,
			); saveErr != nil {
				output.Error("Save permission %s: %v", perm, saveErr)
			}
		}

		if len(granted) == 0 {
			output.Info("No permissions granted on %s", project)
			continue
		}

		// Group by service for display.
		grouped := groupByService(granted)
		services := make([]string, 0, len(grouped))
		for svcName := range grouped {
			services = append(services, svcName)
		}
		sort.Strings(services)

		headers := []string{"SERVICE", "PERMISSION", "DANGEROUS"}
		var rows [][]string
		for _, svcName := range services {
			perms := grouped[svcName]
			sort.Strings(perms)
			for _, perm := range perms {
				dangerous := ""
				if dangerousPerms[perm] {
					dangerous = "YES"
				}
				rows = append(rows, []string{svcName, perm, dangerous})
			}
		}

		output.Success("Found %d granted permissions on %s", len(granted), project)
		output.Table(headers, rows)

		// Emit HIGH findings for dangerous permissions.
		if ctx.Findings != nil {
			for _, perm := range granted {
				if dangerousPerms[perm] {
					ctx.Findings <- module.Finding{
						Module:      "recon.iam.bruteforce-permissions",
						Severity:    module.SevHigh,
						Title:       "Dangerous permission granted",
						Description: fmt.Sprintf("Permission %s is granted on project %s and is associated with known privilege escalation techniques", perm, project),
						Resource:    perm,
						Project:     project,
						Data: map[string]any{
							"permission": perm,
							"project":    project,
						},
					}
				}
			}
		}
	}

	return nil
}

// testPermissionsConcurrent tests permissions in batches of 100 using concurrent goroutines.
func testPermissionsConcurrent(svc *crm.Service, project string, perms []string, concurrency int) ([]string, error) {
	if concurrency < 1 {
		concurrency = 5
	}

	// Split into batches of 100 (API limit).
	var batches [][]string
	for i := 0; i < len(perms); i += 100 {
		end := i + 100
		if end > len(perms) {
			end = len(perms)
		}
		batches = append(batches, perms[i:end])
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		granted []string
		firstErr error
		sem     = make(chan struct{}, concurrency)
	)

	for _, batch := range batches {
		wg.Add(1)
		sem <- struct{}{}

		go func(b []string) {
			defer wg.Done()
			defer func() { <-sem }()

			req := &crm.TestIamPermissionsRequest{
				Permissions: b,
			}
			resp, err := svc.Projects.TestIamPermissions(project, req).Do()
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("testIamPermissions: %w", err)
				}
				mu.Unlock()
				return
			}

			if len(resp.Permissions) > 0 {
				mu.Lock()
				granted = append(granted, resp.Permissions...)
				mu.Unlock()
			}
		}(batch)
	}

	wg.Wait()

	if firstErr != nil && len(granted) == 0 {
		return nil, firstErr
	}

	sort.Strings(granted)
	return granted, nil
}

// groupByService groups permissions by their service prefix (e.g., "iam", "compute").
func groupByService(perms []string) map[string][]string {
	grouped := make(map[string][]string)
	for _, perm := range perms {
		parts := strings.SplitN(perm, ".", 2)
		svcName := parts[0]
		grouped[svcName] = append(grouped[svcName], perm)
	}
	return grouped
}

// buildDangerousSet extracts all permissions from known privesc techniques into a lookup set.
func buildDangerousSet() map[string]bool {
	dangerous := make(map[string]bool)
	for _, t := range privesc.KnownTechniques {
		for _, p := range t.Permissions {
			dangerous[p] = true
		}
	}
	return dangerous
}

// curatedPermissions contains ~200 security-relevant GCP permissions organized by service.
// These focus on privilege escalation, data access, lateral movement, and defense evasion.
var curatedPermissions = []string{
	// ---- IAM ----
	"iam.serviceAccountKeys.create",
	"iam.serviceAccountKeys.delete",
	"iam.serviceAccountKeys.get",
	"iam.serviceAccountKeys.list",
	"iam.serviceAccounts.create",
	"iam.serviceAccounts.delete",
	"iam.serviceAccounts.get",
	"iam.serviceAccounts.getAccessToken",
	"iam.serviceAccounts.getIamPolicy",
	"iam.serviceAccounts.implicitDelegation",
	"iam.serviceAccounts.list",
	"iam.serviceAccounts.setIamPolicy",
	"iam.serviceAccounts.signBlob",
	"iam.serviceAccounts.signJwt",
	"iam.serviceAccounts.actAs",
	"iam.serviceAccounts.update",
	"iam.roles.create",
	"iam.roles.delete",
	"iam.roles.get",
	"iam.roles.list",
	"iam.roles.update",
	"iam.roles.undelete",

	// ---- Resource Manager ----
	"resourcemanager.projects.get",
	"resourcemanager.projects.getIamPolicy",
	"resourcemanager.projects.setIamPolicy",
	"resourcemanager.projects.list",
	"resourcemanager.projects.create",
	"resourcemanager.projects.delete",
	"resourcemanager.projects.update",
	"resourcemanager.organizations.get",
	"resourcemanager.organizations.getIamPolicy",
	"resourcemanager.organizations.setIamPolicy",
	"resourcemanager.folders.get",
	"resourcemanager.folders.getIamPolicy",
	"resourcemanager.folders.setIamPolicy",
	"resourcemanager.folders.list",
	"resourcemanager.folders.create",

	// ---- Compute ----
	"compute.instances.create",
	"compute.instances.delete",
	"compute.instances.get",
	"compute.instances.getSerialPortOutput",
	"compute.instances.list",
	"compute.instances.osLogin",
	"compute.instances.reset",
	"compute.instances.setMetadata",
	"compute.instances.setServiceAccount",
	"compute.instances.start",
	"compute.instances.stop",
	"compute.instances.update",
	"compute.instances.getIamPolicy",
	"compute.instances.setIamPolicy",
	"compute.projects.get",
	"compute.projects.setCommonInstanceMetadata",
	"compute.disks.create",
	"compute.disks.get",
	"compute.disks.list",
	"compute.disks.useReadOnly",
	"compute.firewalls.create",
	"compute.firewalls.delete",
	"compute.firewalls.get",
	"compute.firewalls.list",
	"compute.firewalls.update",
	"compute.networks.get",
	"compute.networks.list",
	"compute.subnetworks.get",
	"compute.subnetworks.list",
	"compute.snapshots.create",
	"compute.snapshots.get",
	"compute.snapshots.list",
	"compute.images.create",
	"compute.images.get",
	"compute.images.list",

	// ---- Storage ----
	"storage.buckets.create",
	"storage.buckets.delete",
	"storage.buckets.get",
	"storage.buckets.getIamPolicy",
	"storage.buckets.list",
	"storage.buckets.setIamPolicy",
	"storage.buckets.update",
	"storage.objects.create",
	"storage.objects.delete",
	"storage.objects.get",
	"storage.objects.getIamPolicy",
	"storage.objects.list",
	"storage.objects.setIamPolicy",
	"storage.objects.update",
	"storage.hmacKeys.create",
	"storage.hmacKeys.delete",
	"storage.hmacKeys.get",
	"storage.hmacKeys.list",

	// ---- Cloud Functions ----
	"cloudfunctions.functions.call",
	"cloudfunctions.functions.create",
	"cloudfunctions.functions.delete",
	"cloudfunctions.functions.get",
	"cloudfunctions.functions.getIamPolicy",
	"cloudfunctions.functions.list",
	"cloudfunctions.functions.setIamPolicy",
	"cloudfunctions.functions.sourceCodeGet",
	"cloudfunctions.functions.sourceCodeSet",
	"cloudfunctions.functions.update",

	// ---- Cloud Run ----
	"run.services.create",
	"run.services.delete",
	"run.services.get",
	"run.services.getIamPolicy",
	"run.services.list",
	"run.services.setIamPolicy",
	"run.services.update",
	"run.routes.get",
	"run.routes.list",
	"run.jobs.create",
	"run.jobs.get",
	"run.jobs.list",
	"run.jobs.run",
	"run.jobs.update",

	// ---- BigQuery ----
	"bigquery.datasets.create",
	"bigquery.datasets.delete",
	"bigquery.datasets.get",
	"bigquery.datasets.getIamPolicy",
	"bigquery.datasets.update",
	"bigquery.datasets.updateTag",
	"bigquery.jobs.create",
	"bigquery.jobs.get",
	"bigquery.jobs.list",
	"bigquery.tables.create",
	"bigquery.tables.delete",
	"bigquery.tables.get",
	"bigquery.tables.getData",
	"bigquery.tables.list",
	"bigquery.tables.update",
	"bigquery.tables.updateData",
	"bigquery.tables.export",

	// ---- Secret Manager ----
	"secretmanager.secrets.create",
	"secretmanager.secrets.delete",
	"secretmanager.secrets.get",
	"secretmanager.secrets.getIamPolicy",
	"secretmanager.secrets.list",
	"secretmanager.secrets.setIamPolicy",
	"secretmanager.secrets.update",
	"secretmanager.versions.access",
	"secretmanager.versions.add",
	"secretmanager.versions.destroy",
	"secretmanager.versions.get",
	"secretmanager.versions.list",

	// ---- Cloud SQL ----
	"cloudsql.instances.connect",
	"cloudsql.instances.create",
	"cloudsql.instances.delete",
	"cloudsql.instances.export",
	"cloudsql.instances.get",
	"cloudsql.instances.list",
	"cloudsql.instances.update",
	"cloudsql.databases.get",
	"cloudsql.databases.list",
	"cloudsql.users.create",
	"cloudsql.users.delete",
	"cloudsql.users.list",
	"cloudsql.users.update",
	"cloudsql.backups.get",
	"cloudsql.backups.list",

	// ---- GKE / Container ----
	"container.clusters.create",
	"container.clusters.delete",
	"container.clusters.get",
	"container.clusters.getCredentials",
	"container.clusters.list",
	"container.clusters.update",
	"container.pods.exec",
	"container.pods.get",
	"container.pods.list",
	"container.secrets.get",
	"container.secrets.list",
	"container.serviceAccounts.get",
	"container.roles.bind",
	"container.clusterRoles.bind",
	"container.namespaces.get",
	"container.namespaces.list",

	// ---- Logging ----
	"logging.logEntries.list",
	"logging.logs.delete",
	"logging.logs.list",
	"logging.sinks.create",
	"logging.sinks.delete",
	"logging.sinks.get",
	"logging.sinks.list",
	"logging.sinks.update",
	"logging.privateLogEntries.list",

	// ---- KMS ----
	"cloudkms.cryptoKeys.create",
	"cloudkms.cryptoKeys.get",
	"cloudkms.cryptoKeys.getIamPolicy",
	"cloudkms.cryptoKeys.list",
	"cloudkms.cryptoKeys.setIamPolicy",
	"cloudkms.cryptoKeys.update",
	"cloudkms.cryptoKeyVersions.create",
	"cloudkms.cryptoKeyVersions.destroy",
	"cloudkms.cryptoKeyVersions.get",
	"cloudkms.cryptoKeyVersions.list",
	"cloudkms.cryptoKeyVersions.useToDecrypt",
	"cloudkms.cryptoKeyVersions.useToEncrypt",
	"cloudkms.cryptoKeyVersions.useToSign",
	"cloudkms.keyRings.get",
	"cloudkms.keyRings.list",

	// ---- Pub/Sub ----
	"pubsub.subscriptions.consume",
	"pubsub.subscriptions.create",
	"pubsub.subscriptions.delete",
	"pubsub.subscriptions.get",
	"pubsub.subscriptions.getIamPolicy",
	"pubsub.subscriptions.list",
	"pubsub.subscriptions.setIamPolicy",
	"pubsub.subscriptions.update",
	"pubsub.topics.create",
	"pubsub.topics.delete",
	"pubsub.topics.get",
	"pubsub.topics.getIamPolicy",
	"pubsub.topics.list",
	"pubsub.topics.publish",
	"pubsub.topics.setIamPolicy",
	"pubsub.topics.update",
}

// additionalPermissions contains extra permissions used when --all-permissions is set.
var additionalPermissions = []string{
	// Additional IAM permissions
	"iam.serviceAccounts.enable",
	"iam.serviceAccounts.disable",
	"iam.serviceAccounts.undelete",

	// Additional Compute permissions
	"compute.addresses.create",
	"compute.addresses.delete",
	"compute.addresses.get",
	"compute.addresses.list",
	"compute.backendServices.create",
	"compute.backendServices.get",
	"compute.backendServices.list",
	"compute.backendServices.update",
	"compute.globalOperations.get",
	"compute.globalOperations.list",
	"compute.healthChecks.create",
	"compute.healthChecks.get",
	"compute.healthChecks.list",
	"compute.instanceGroupManagers.create",
	"compute.instanceGroupManagers.get",
	"compute.instanceGroupManagers.list",
	"compute.instanceTemplates.create",
	"compute.instanceTemplates.get",
	"compute.instanceTemplates.list",
	"compute.machineTypes.get",
	"compute.machineTypes.list",
	"compute.regions.get",
	"compute.regions.list",
	"compute.routers.get",
	"compute.routers.list",
	"compute.routes.get",
	"compute.routes.list",
	"compute.sslCertificates.create",
	"compute.sslCertificates.get",
	"compute.sslCertificates.list",
	"compute.targetHttpProxies.create",
	"compute.targetHttpsProxies.create",
	"compute.urlMaps.create",
	"compute.urlMaps.get",
	"compute.urlMaps.list",
	"compute.vpnGateways.get",
	"compute.vpnGateways.list",
	"compute.vpnTunnels.get",
	"compute.vpnTunnels.list",
	"compute.zones.get",
	"compute.zones.list",

	// Additional Storage
	"storage.buckets.enableObjectRetention",

	// Additional Resource Manager
	"resourcemanager.projects.move",
	"resourcemanager.folders.delete",
	"resourcemanager.folders.move",
	"resourcemanager.folders.update",

	// Additional Cloud Functions (v2)
	"cloudfunctions.functions.invoke",

	// Additional Cloud Run
	"run.services.invoke",
	"run.jobs.delete",

	// Additional BigQuery
	"bigquery.datasets.setIamPolicy",
	"bigquery.tables.getIamPolicy",
	"bigquery.tables.setIamPolicy",
	"bigquery.transfers.get",
	"bigquery.transfers.update",

	// Additional Secret Manager
	"secretmanager.versions.enable",
	"secretmanager.versions.disable",

	// Additional Cloud SQL
	"cloudsql.instances.import",
	"cloudsql.instances.restart",
	"cloudsql.instances.startReplica",
	"cloudsql.instances.stopReplica",
	"cloudsql.instances.truncateLog",

	// Additional GKE
	"container.clusters.getMonitoring",
	"container.deployments.create",
	"container.deployments.get",
	"container.deployments.list",
	"container.deployments.update",
	"container.pods.create",
	"container.pods.delete",
	"container.pods.update",
	"container.secrets.create",
	"container.secrets.update",

	// Additional Logging
	"logging.logEntries.create",
	"logging.logMetrics.create",
	"logging.logMetrics.get",
	"logging.logMetrics.list",
	"logging.logMetrics.update",

	// Additional KMS
	"cloudkms.keyRings.create",
	"cloudkms.keyRings.getIamPolicy",
	"cloudkms.keyRings.setIamPolicy",
	"cloudkms.cryptoKeyVersions.useToVerify",
	"cloudkms.cryptoKeyVersions.viewPublicKey",
	"cloudkms.importJobs.create",
	"cloudkms.importJobs.get",
	"cloudkms.importJobs.list",

	// Additional Pub/Sub
	"pubsub.snapshots.create",
	"pubsub.snapshots.delete",
	"pubsub.snapshots.get",
	"pubsub.snapshots.list",

	// Dataproc
	"dataproc.clusters.create",
	"dataproc.clusters.delete",
	"dataproc.clusters.get",
	"dataproc.clusters.list",
	"dataproc.clusters.update",
	"dataproc.jobs.create",
	"dataproc.jobs.get",
	"dataproc.jobs.list",

	// Dataflow
	"dataflow.jobs.create",
	"dataflow.jobs.get",
	"dataflow.jobs.list",
	"dataflow.jobs.cancel",

	// App Engine
	"appengine.applications.get",
	"appengine.services.get",
	"appengine.services.list",
	"appengine.versions.create",
	"appengine.versions.get",
	"appengine.versions.list",

	// Cloud Build
	"cloudbuild.builds.create",
	"cloudbuild.builds.get",
	"cloudbuild.builds.list",

	// Container Registry / Artifact Registry
	"artifactregistry.repositories.get",
	"artifactregistry.repositories.list",
	"artifactregistry.repositories.downloadArtifacts",
	"artifactregistry.repositories.uploadArtifacts",

	// Service Usage
	"serviceusage.services.enable",
	"serviceusage.services.disable",
	"serviceusage.services.get",
	"serviceusage.services.list",

	// Deployment Manager
	"deploymentmanager.deployments.create",
	"deploymentmanager.deployments.delete",
	"deploymentmanager.deployments.get",
	"deploymentmanager.deployments.list",
	"deploymentmanager.deployments.update",

	// Composer (Airflow)
	"composer.environments.create",
	"composer.environments.delete",
	"composer.environments.get",
	"composer.environments.list",
	"composer.environments.update",

	// Source Repositories
	"source.repos.get",
	"source.repos.list",

	// DNS
	"dns.managedZones.create",
	"dns.managedZones.delete",
	"dns.managedZones.get",
	"dns.managedZones.list",
	"dns.managedZones.update",
	"dns.resourceRecordSets.create",
	"dns.resourceRecordSets.delete",
	"dns.resourceRecordSets.get",
	"dns.resourceRecordSets.list",
	"dns.resourceRecordSets.update",
}

// allPermissions combines curatedPermissions and additionalPermissions.
// Built via init to avoid package-level append calls.
var allPermissions []string
