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

- **24 modules** across 8 MITRE ATT&CK tactics (recon, privesc, credential, persist, lateral, exfil, defense-evasion, initial-access)
- **Attack path engine** — builds a directed graph from enumerated data and overlays 20 known GCP privilege escalation techniques to discover escalation chains automatically
- **Concurrent scanning** — goroutine-based parallel project scanning across all modules
- **YAML playbooks** — chain modules into repeatable automated workflows
- **Structured findings** — every module generates severity-rated findings (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- **Report generation** — export findings as Markdown or JSON pentest reports
- **Dual mode** — interactive REPL shell or direct CLI for scripting and CI/CD
- **Cross-platform** — pure-Go SQLite (no CGO), builds for Linux, macOS, and Windows from any platform
- **Single binary** — no runtime dependencies, no Python, no pip

## Install

### From source

```bash
git clone https://github.com/0xJosep/nimbus-gcp.git
cd nimbus-gcp
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

You'll be prompted to create a workspace and select credentials (ADC, service account key, OAuth token, or unauthenticated).

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

# Run a playbook
nimbus playbook playbooks/full-recon.yaml
```

## Modules

### Recon (12 modules)

| Module | Description |
|--------|-------------|
| `recon.iam.list-principals` | Discover service accounts and their key metadata |
| `recon.iam.list-bindings` | List IAM policy bindings and flag dangerous roles |
| `recon.compute.scan-instances` | Scan VM instances with SA and network details |
| `recon.storage.probe-buckets` | Probe buckets for configuration and access settings |
| `recon.secrets.scan-secrets` | Discover secrets and optionally read values |
| `recon.functions.scan-functions` | Scan Cloud Functions for triggers, SAs, ingress |
| `recon.gke.scan-clusters` | Scan GKE clusters for RBAC, network policy, node config |
| `recon.network.map-vpcs` | Map VPC networks, subnets, firewall rules, peering |
| `recon.resourcemanager.list-projects` | Discover all accessible projects in the org |
| `recon.bigquery.scan-datasets` | Scan BigQuery datasets, tables, access controls |
| `recon.cloudsql.scan-instances` | Scan Cloud SQL for auth, network, backup config |
| `recon.logging.scan-sinks` | Scan log sinks and audit logging configuration |

### Privilege Escalation (4 modules)

| Module | Description |
|--------|-------------|
| `privesc.iam.escalate-sa-key-create` | Create a new key for a target service account |
| `privesc.iam.escalate-sa-impersonate` | Generate access token via SA impersonation |
| `privesc.iam.escalate-setiam-policy` | Modify project IAM policy to grant a role |
| `privesc.compute.escalate-startup-script` | Inject startup script on a VM for code execution |

### Other Tactics (8 modules)

| Module | Description |
|--------|-------------|
| `credential.compute.dump-metadata-token` | Retrieve SA token from GCE metadata server |
| `persist.iam.inject-binding` | Add IAM binding for persistent backdoor access |
| `lateral.compute.ssh-via-metadata` | Push SSH key to VM metadata for lateral movement |
| `exfil.storage.siphon-objects` | Download objects from a bucket |
| `initial-access.storage.bruteforce-buckets` | Brute-force bucket names for public access |
| `defense-evasion.logging.disable-sinks` | Disable log sinks to evade detection |
| `analyze.paths.attack-paths` | Build attack graph and find escalation chains |
| `analyze.summary.workspace-overview` | Summary of all collected data and findings |

## Attack Path Engine

After running recon modules, nimbus can automatically discover privilege escalation chains:

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

## Auto-Flagging

Every recon module automatically generates findings for common misconfigurations:

- Default compute service account in use (HIGH)
- VMs with external IPs (MEDIUM)
- Firewall rules allowing 0.0.0.0/0 (HIGH)
- Cloud SQL with public IP and no SSL (CRITICAL)
- GKE clusters with legacy ABAC enabled (CRITICAL)
- Dangerous IAM roles: owner, editor, securityAdmin (CRITICAL/HIGH)
- Cloud Functions with ALLOW_ALL ingress (MEDIUM)
- Disabled log export sinks (HIGH)
- Storage buckets without public access prevention (MEDIUM)

## Playbooks

Define repeatable workflows in YAML:

```yaml
# playbooks/full-recon.yaml
name: full-recon
description: Complete reconnaissance of target GCP projects
steps:
  - module: recon.iam.list-principals
  - module: recon.iam.list-bindings
  - module: recon.compute.scan-instances
  - module: recon.storage.probe-buckets
```

```bash
nimbus playbook playbooks/full-recon.yaml
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
| `report <output.md>` | Generate a pentest report |
| `workspace` | Show current workspace info |

## Authentication

Nimbus supports 4 credential types:

| Type | Use Case |
|------|----------|
| **Application Default Credentials** | When you have `gcloud auth` configured |
| **Service Account Key** | JSON key file from a compromised SA |
| **OAuth2 Access Token** | Stolen token (e.g., from metadata server) |
| **None** | Unauthenticated modules (bucket brute-force, etc.) |

Multiple credential sets can be stored per workspace and swapped with `creds swap`.

## Architecture

```
cmd/nimbus/          Entry point (CLI + REPL)
internal/
  auth/              Credential management (ADC, SA key, OAuth, none)
  db/                SQLite storage (workspaces, sessions, resources, findings, permissions, role_bindings)
  graph/             Attack path engine (directed graph, BFS pathfinder, privesc analyzer)
  module/            Module interface, registry, concurrent runner
  output/            Terminal output, report generation
  playbook/          YAML playbook parser
  privesc/           Embedded privilege escalation knowledge base (20 techniques)
  shell/             Interactive REPL
  workspace/         Engagement isolation
modules/
  recon/             Discovery and enumeration
  privesc/           Privilege escalation
  credential/        Credential access
  persist/           Persistence
  lateral/           Lateral movement
  exfil/             Data exfiltration
  initial_access/    Unauthenticated attacks
  defense_evasion/   Detection avoidance
  analyze/           Post-collection analysis
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
    // Your code here. Use ctx.Session for GCP auth,
    // ctx.Store to persist data, ctx.Findings to emit findings.
    return nil
}
```

No registration files, no config. Build and the module is available.

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Always obtain proper authorization before testing any GCP environment you do not own.

## License

MIT
