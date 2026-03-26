package module

import (
	"context"

	"github.com/user/nimbus/internal/auth"
	"github.com/user/nimbus/internal/db"
)

// Tactic aligns to MITRE ATT&CK for Cloud tactics.
type Tactic string

const (
	TacticRecon          Tactic = "recon"
	TacticCredential     Tactic = "credential"
	TacticPrivesc        Tactic = "privesc"
	TacticPersist        Tactic = "persist"
	TacticLateral        Tactic = "lateral"
	TacticExfil          Tactic = "exfil"
	TacticImpact         Tactic = "impact"
	TacticDefenseEvasion Tactic = "defense-evasion"
	TacticInitialAccess  Tactic = "initial-access"
	TacticAnalyze        Tactic = "analyze"
)

// Severity indicates the risk level of a finding.
type Severity string

const (
	SevCritical Severity = "CRITICAL"
	SevHigh     Severity = "HIGH"
	SevMedium   Severity = "MEDIUM"
	SevLow      Severity = "LOW"
	SevInfo     Severity = "INFO"
)

// Info describes a module's metadata.
type Info struct {
	// Name is the unique dotted identifier, e.g. "recon.iam.list-principals".
	Name string
	// Tactic is the MITRE ATT&CK tactic this module implements.
	Tactic Tactic
	// Service is the GCP service this module targets.
	Service string
	// Description is a short human-readable description.
	Description string
	// RequiresAuth indicates whether the module needs valid credentials.
	RequiresAuth bool
	// Concurrent indicates whether the module supports parallel project scanning.
	Concurrent bool
	// AttackID is an optional MITRE ATT&CK technique ID (e.g. "T1078.004").
	AttackID string
}

// Finding represents a structured result from a module execution.
type Finding struct {
	Module      string
	Severity    Severity
	Title       string
	Description string
	Resource    string
	Project     string
	Data        map[string]any
}

// RunContext provides everything a module needs to execute.
type RunContext struct {
	Ctx         context.Context
	Session     *auth.Session
	Store       *db.Store
	Workspace   int64
	Projects    []string
	Flags       map[string]string
	Verbose     bool
	Concurrency int
	Findings    chan<- Finding
}

// Module is the interface every nimbus module must implement.
type Module interface {
	// Info returns the module's metadata.
	Info() Info
	// Run executes the module.
	Run(ctx RunContext) error
}
