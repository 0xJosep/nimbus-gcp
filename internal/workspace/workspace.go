package workspace

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/user/nimbus/internal/db"
)

// Workspace represents an isolated engagement context.
type Workspace struct {
	ID   int64
	Name string
}

// Manager handles workspace creation and selection.
type Manager struct {
	store *db.Store
}

// NewManager creates a new workspace manager.
func NewManager(store *db.Store) *Manager {
	return &Manager{store: store}
}

// SelectOrCreate prompts the user to select an existing workspace or create a new one.
func (m *Manager) SelectOrCreate() (*Workspace, error) {
	workspaces, err := m.list()
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(os.Stdin)

	if len(workspaces) == 0 {
		fmt.Print("\nNo workspaces found. Enter a name for your new workspace: ")
		name, _ := reader.ReadString('\n')
		name = strings.TrimSpace(name)
		if name == "" {
			name = "default"
		}
		return m.create(name)
	}

	fmt.Println("\nExisting workspaces:")
	for i, ws := range workspaces {
		fmt.Printf("  [%d] %s\n", i+1, ws.Name)
	}
	fmt.Printf("  [%d] Create new workspace\n", len(workspaces)+1)
	fmt.Print("\nSelect workspace: ")

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	choice, err := strconv.Atoi(input)
	if err != nil || choice < 1 || choice > len(workspaces)+1 {
		fmt.Println("Invalid choice, using first workspace.")
		return &workspaces[0], nil
	}

	if choice <= len(workspaces) {
		ws := &workspaces[choice-1]
		fmt.Printf("Using workspace: %s\n", ws.Name)
		return ws, nil
	}

	fmt.Print("Enter name for new workspace: ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)
	if name == "" {
		name = "default"
	}
	return m.create(name)
}

func (m *Manager) list() ([]Workspace, error) {
	rows, err := m.store.DB.Query("SELECT id, name FROM workspaces ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var workspaces []Workspace
	for rows.Next() {
		var ws Workspace
		if err := rows.Scan(&ws.ID, &ws.Name); err != nil {
			return nil, err
		}
		workspaces = append(workspaces, ws)
	}
	return workspaces, rows.Err()
}

func (m *Manager) create(name string) (*Workspace, error) {
	res, err := m.store.DB.Exec("INSERT INTO workspaces (name) VALUES (?)", name)
	if err != nil {
		return nil, fmt.Errorf("create workspace %q: %w", name, err)
	}
	id, _ := res.LastInsertId()
	fmt.Printf("Created workspace: %s\n", name)
	return &Workspace{ID: id, Name: name}, nil
}
