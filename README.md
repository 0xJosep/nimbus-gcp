# Nimbus

A MITRE ATT&CK-aligned GCP pentesting framework written in Go. Single binary, cross-platform, zero dependencies.

```
  ███╗   ██╗██╗███╗   ███╗██████╗ ██╗   ██╗███████╗
  ████╗  ██║██║████╗ ████║██╔══██╗██║   ██║██╔════╝
  ██╔██╗ ██║██║██╔████╔██║██████╔╝██║   ██║███████╗
  ██║╚██╗██║██║██║╚██╔╝██║██╔══██╗██║   ██║╚════██║
  ██║ ╚████║██║██║ ╚═╝ ██║██████╔╝╚██████╔╝███████║
  ╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝╚═════╝  ╚═════╝ ╚══════╝
```

## Features

- **45 modules** across 10 MITRE ATT&CK tactics
- **Attack path engine** — directed graph with 20 embedded privesc techniques, auto-discovers escalation chains
- **CIS Benchmark** — 20 CIS GCP Foundation controls checked offline against collected data
- **Permission brute-forcing** — test 200+ IAM permissions concurrently against target projects
- **Delegation chain analysis** — maps multi-hop SA impersonation paths via BFS
- **Concurrent scanning** — goroutine-based parallel project scanning
- **Tab completion** — section-by-section dotted module name completion (`recon.[TAB]` → `recon.iam.[TAB]` → `recon.iam.list-principals`)
- **YAML playbooks** — chain modules into repeatable automated workflows
- **Structured findings** — every module generates severity-rated findings (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- **Report generation** — Markdown, JSON, Neo4j Cypher, and Graphviz DOT export
- **Dual mode** — interactive REPL shell or direct CLI for scripting and CI/CD
- **OAuth2 browser flow** — authenticate via browser with auto-refresh tokens
- **Cross-platform** — pure-Go SQLite (no CGO), builds for Linux, macOS, and Windows
- **Single binary** — no runtime dependencies, no Python, no pip
- **Session recording** — JSONL audit trail of all module executions
- **CI/CD** — GitHub Actions with Goreleaser for automated cross-platform releases

## Install

### Build and install to PATH

```bash
git clone https://github.com/0xJosep/nimbus-gcp.git
cd nimbus-gcp
make
```

This builds the binary and installs it to your PATH automatically:
- **Linux / macOS** — installs to `/usr/local/bin/nimbus`
- **Windows** — installs to `%USERPROFILE%\.nimbus\bin\nimbus.exe` and adds it to your user PATH

On Windows, restart your terminal after the first install for PATH to take effect.

Alternatively, use the install script (no `make` required):

```bash
bash install.sh
```

### Build only (no install)

```bash
make build
```

The binary will be at `build/nimbus`.

### Cross-compile

```bash
make build-all
```

Produces binaries for:
- `nimbus-linux-amd64`
- `nimbus-linux-arm64`
- `nimbus-darwin-amd64`
- `nimbus-darwin-arm64`
- `nimbus-windows-amd64.exe`

## Quick Start

### Interactive shell

```bash
nimbus
```

You'll be prompted to create a workspace and select credentials (ADC, service account key, OAuth browser login, raw token, or unauthenticated).

### Direct CLI

```bash
# List all modules
nimbus modules

# Filter by tactic
nimbus modules recon
nimbus modules privesc

# Run a module directly
nimbus run recon.iam.list-principals -p my-project

# Run with verbose output across multiple projects
nimbus run recon.compute.scan-instances -p proj1,proj2 -v

# Full enumeration of a project
nimbus run recon.all -p my-project

# Run a playbook
nimbus playbook playbooks/full-recon.yaml
```

### Tab Completion

Module names auto-complete section by section:

```
nimbus> rec[TAB]              → recon.
nimbus> recon.i[TAB]          → recon.iam.
nimbus> recon.iam.l[TAB]      → list-bindings  list-principals  list-roles
nimbus> run priv[TAB]         → privesc.
```

Flags, commands, and subcommands also complete with Tab.

## Modules

### Recon (20 modules)

| Module | Description |
|--------|-------------|
| `recon.all` | Run all recon modules (full enumeration) |
| `recon.iam.list-principals` | Discover service accounts and their key metadata |
| `recon.iam.list-roles` | List custom IAM roles, flag dangerous permissions |
| `recon.iam.list-bindings` | List IAM policy bindings, flag dangerous roles |
| `recon.iam.bruteforce-permissions` | Brute-force 200+ IAM permissions concurrently |
| `recon.compute.scan-instances` | Scan VM instances with SA and network details |
| `recon.compute.scan-metadata` | Check project-level SSH keys, serial port, OS Login |
| `recon.storage.probe-buckets` | Probe buckets for configuration and access settings |
| `recon.secrets.scan-secrets` | Discover secrets and optionally read values |
| `recon.functions.scan-functions` | Scan Cloud Functions for triggers, SAs, ingress |
| `recon.run.scan-services` | Scan Cloud Run services for ingress, auth, SA |
| `recon.gke.scan-clusters` | Scan GKE clusters for RBAC, network policy, node config |
| `recon.network.map-vpcs` | Map VPC networks, subnets, firewall rules, peering |
| `recon.resourcemanager.list-projects` | Discover all accessible projects in the org |
| `recon.bigquery.scan-datasets` | Scan BigQuery datasets, tables, access controls |
| `recon.cloudsql.scan-instances` | Scan Cloud SQL for auth, network, backup config |
| `recon.logging.scan-sinks` | Scan log sinks and audit logging configuration |
| `recon.dns.scan-zones` | Scan Cloud DNS zones and enumerate records |
| `recon.kms.scan-keyrings` | Scan KMS key rings, flag missing rotation |
| `recon.pubsub.scan-topics` | Scan Pub/Sub topics, flag insecure push endpoints |
| `recon.scheduler.scan-jobs` | Scan Cloud Scheduler jobs, flag HTTP targets |
| `recon.orgpolicy.scan-constraints` | Scan org policy constraints, flag missing enforcements |

### Privilege Escalation (5 modules)

| Module | Description |
|--------|-------------|
| `privesc.iam.escalate-sa-key-create` | Create a new key for a target service account |
| `privesc.iam.escalate-sa-impersonate` | Generate access token via SA impersonation |
| `privesc.iam.escalate-setiam-policy` | Modify project IAM policy to grant a role |
| `privesc.compute.escalate-startup-script` | Inject startup script on a VM for code execution |
| `privesc.functions.escalate-deploy` | Deploy a Cloud Function as a privileged SA |

### Credential Access (2 modules)

| Module | Description |
|--------|-------------|
| `credential.compute.dump-metadata-token` | Retrieve SA token from GCE metadata server |
| `credential.iam.steal-sa-keys` | List SA keys, flag user-managed keys |

### Persistence (2 modules)

| Module | Description |
|--------|-------------|
| `persist.iam.inject-binding` | Add IAM binding for persistent backdoor access |
| `persist.iam.inject-sa-key` | Create SA key for persistent access |

### Lateral Movement (1 module)

| Module | Description |
|--------|-------------|
| `lateral.compute.ssh-via-metadata` | Push SSH key to VM metadata for lateral movement |

### Exfiltration (3 modules)

| Module | Description |
|--------|-------------|
| `exfil.storage.siphon-objects` | Download objects from a bucket |
| `exfil.secrets.dump-values` | Bulk-read all accessible secret values |
| `exfil.bigquery.siphon-tables` | Download BigQuery table rows |

### Defense Evasion (3 modules)

| Module | Description |
|--------|-------------|
| `defense-evasion.logging.disable-sinks` | Disable log sinks to evade detection |
| `defense-evasion.logging.add-exclusion` | Add log exclusion filters (stealthier) |
| `defense-evasion.iam.remove-binding` | Remove IAM bindings (cleanup after persistence) |

### Initial Access (2 modules)

| Module | Description |
|--------|-------------|
| `initial-access.storage.bruteforce-buckets` | Brute-force bucket names for public access |
| `initial-access.functions.bruteforce-endpoints` | Brute-force Cloud Function HTTP endpoints |

### Analysis (4 modules)

| Module | Description |
|--------|-------------|
| `analyze.paths.attack-paths` | Build attack graph and find escalation chains |
| `analyze.iam.delegation-chains` | Map multi-hop SA impersonation chains |
| `analyze.compliance.cis-benchmark` | Run 20 CIS GCP Benchmark controls offline |
| `analyze.summary.workspace-overview` | Summary of all collected data and findings |

## Attack Path Engine

After running recon modules, nimbus automatically discovers privilege escalation chains:

```
nimbus> paths
[*] Building attack graph from collected data...
[*] Graph: 47 nodes, 83 edges
[!] Found 3 potential escalation technique(s)!

  [NIM-001] SA Key Creation (CRITICAL)
    Create a new key for any service account the identity has this permission on.
    Permissions: iam.serviceAccountKeys.create

  [NIM-006] Project IAM Policy Modification (CRITICAL)
    Modify the project-level IAM policy to grant yourself any role.
    Permissions: resourcemanager.projects.setIamPolicy
```

The engine embeds 20 known GCP privilege escalation techniques (NIM-001 through NIM-020) and matches them against discovered permissions.

Export the attack graph for visualization:

```
nimbus> report graph.cypher    # Neo4j Cypher format
nimbus> report graph.dot       # Graphviz DOT format
```

## CIS Benchmark

Run offline compliance checks against collected data:

```
nimbus> run analyze.compliance.cis-benchmark

  CHECK   STATUS  DESCRIPTION                              AFFECTED
  ------  ------  ---------------------------------------- --------
  1.1     FAIL    Avoid use of roles/owner                 user:admin@corp.com
  4.1     FAIL    Default SA should not be used             vm-prod, vm-staging
  6.1     FAIL    Cloud SQL should require SSL              db-prod
  3.6     FAIL    SSH should be restricted (no 0.0.0.0/0)  allow-ssh
  ...

  Summary: 12/20 passed, 6/20 failed, 2/20 not tested (no data)
```

## Permission Brute-Forcing

Test which IAM permissions your current identity has:

```
nimbus> run recon.iam.bruteforce-permissions -p my-project

[*] Testing 200 permissions in 2 batches across 1 project(s)...
[+] 23 permissions granted on my-project

  SERVICE        PERMISSION                              DANGEROUS
  -------------- --------------------------------------- ---------
  iam            iam.serviceAccountKeys.create            YES
  iam            iam.serviceAccounts.getAccessToken        YES
  compute        compute.instances.list                    -
  storage        storage.buckets.list                      -
  ...
```

Use `--all-permissions` to test the extended list of ~350 permissions.

## Auto-Flagging

Every recon module automatically generates findings for common misconfigurations:

- Default compute service account in use (HIGH)
- VMs with external IPs (MEDIUM)
- Firewall rules allowing 0.0.0.0/0 (HIGH)
- Cloud SQL with public IP and no SSL (CRITICAL)
- GKE clusters with legacy ABAC enabled (CRITICAL)
- Dangerous IAM roles: owner, editor, securityAdmin (CRITICAL/HIGH)
- Cloud Functions with ALLOW_ALL ingress (MEDIUM)
- Cloud Run services with unauthenticated access (HIGH)
- Disabled log export sinks (HIGH)
- Storage buckets without public access prevention (MEDIUM)
- KMS keys without rotation (MEDIUM)
- Pub/Sub push endpoints using HTTP (HIGH)
- Org policy constraints not enforced (HIGH)
- Project-wide SSH keys in metadata (HIGH)

## Playbooks

Define repeatable workflows in YAML:

```yaml
# playbooks/full-recon.yaml
name: full-recon
description: Complete reconnaissance of target GCP projects
steps:
  - module: recon.iam.list-principals
  - module: recon.iam.list-bindings
  - module: recon.iam.list-roles
  - module: recon.compute.scan-instances
  - module: recon.storage.probe-buckets
  - module: recon.secrets.scan-secrets
  - module: recon.gke.scan-clusters
```

```bash
nimbus playbook playbooks/full-recon.yaml
```

Or use the built-in `recon.all` module to run all recon modules at once:

```bash
nimbus run recon.all -p my-project
```

## Shell Commands

| Command | Description |
|---------|-------------|
| `modules [search]` | List or search modules by name, tactic, or service |
| `run <module> [flags]` | Execute a module |
| `creds [swap\|info]` | Manage credentials |
| `data [service]` | View enumerated resources |
| `findings [severity]` | View security findings |
| `paths [from <identity>]` | Analyze attack paths |
| `playbook <file.yaml>` | Run a playbook |
| `report <output.md>` | Generate a pentest report (md, json, cypher, dot) |
| `workspace` | Show current workspace info |

## Authentication

Nimbus supports 4 credential types:

| Type | Use Case |
|------|----------|
| **Application Default Credentials** | When you have `gcloud auth` configured |
| **Service Account Key** | JSON key file from a compromised SA |
| **OAuth2 Browser Login** | Opens a link, authenticates via Google, gets refresh token |
| **Raw Access Token** | Stolen token (e.g., from metadata server) |
| **None** | Unauthenticated modules (bucket brute-force, etc.) |

Multiple credential sets can be stored per workspace and swapped with `creds swap`.

## Architecture

```
cmd/nimbus/          Entry point (CLI + REPL)
internal/
  auth/              Credential management (ADC, SA key, OAuth browser flow, token)
  config/            Config file support (~/.nimbus/config.yaml)
  db/                SQLite storage (workspaces, sessions, resources, findings, permissions, role_bindings)
  graph/             Attack path engine (directed graph, BFS pathfinder, privesc analyzer, Neo4j/DOT export)
  module/            Module interface, registry, concurrent runner, project prompt
  output/            Terminal output, report generation, JSON output
  playbook/          YAML playbook parser
  privesc/           Embedded privilege escalation knowledge base (20 techniques)
  session/           Session recording (JSONL audit trail)
  shell/             Interactive REPL with tab completion
  workspace/         Engagement isolation
modules/
  recon/             Discovery and enumeration (20 modules)
  privesc/           Privilege escalation (5 modules)
  credential/        Credential access (2 modules)
  persist/           Persistence (2 modules)
  lateral/           Lateral movement (1 module)
  exfil/             Data exfiltration (3 modules)
  initial_access/    Unauthenticated attacks (2 modules)
  defense_evasion/   Detection avoidance (3 modules)
  analyze/           Post-collection analysis (4 modules)
```

## Adding a Module

Drop a file in `modules/<tactic>/<service>/` and implement the `Module` interface:

```go
package iam

import "github.com/user/nimbus/internal/module"

func init() {
    module.Register(&MyModule{})
}

type MyModule struct{}

func (m *MyModule) Info() module.Info {
    return module.Info{
        Name:         "recon.iam.my-module",
        Tactic:       module.TacticRecon,
        Service:      "iam",
        Description:  "Does something useful",
        RequiresAuth: true,
        Concurrent:   true,
    }
}

func (m *MyModule) Run(ctx module.RunContext) error {
    // Use module.EnsureProjects(&ctx) for project selection.
    // Use ctx.Session for GCP auth.
    // Use ctx.Store to persist data.
    // Use ctx.Findings to emit findings.
    return nil
}
```

No registration files, no config. Build and the module is available.

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Always obtain proper authorization before testing any GCP environment you do not own.

## License

MIT
