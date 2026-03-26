package session

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Entry represents a single recorded module execution.
type Entry struct {
	Timestamp  time.Time `json:"timestamp"`
	Module     string    `json:"module"`
	Projects   []string  `json:"projects"`
	DurationMs int64     `json:"duration_ms"`
	Findings   int       `json:"findings"`
	Error      string    `json:"error"`
}

// Recorder logs module executions to a JSONL audit file.
type Recorder struct {
	WorkspaceDir string
}

// NewRecorder creates a Recorder for the given workspace directory name.
func NewRecorder(workspaceDir string) *Recorder {
	return &Recorder{WorkspaceDir: workspaceDir}
}

// auditPath returns the path to the audit file for this workspace.
func (r *Recorder) auditPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(homeDir, ".nimbus", "sessions", r.WorkspaceDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "audit.jsonl"), nil
}

// Record appends an entry to the audit log.
func (r *Recorder) Record(entry Entry) error {
	path, err := r.auditPath()
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	_, err = f.Write(append(data, '\n'))
	return err
}

// List reads all entries from the audit log for the given workspace directory.
func List(workspaceDir string) ([]Entry, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(homeDir, ".nimbus", "sessions", workspaceDir, "audit.jsonl")

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return entries, err
	}
	return entries, nil
}
