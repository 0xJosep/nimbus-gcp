package graph

import "fmt"

// NodeType classifies graph nodes.
type NodeType string

const (
	NodeIdentity   NodeType = "identity"
	NodeRole       NodeType = "role"
	NodePermission NodeType = "permission"
	NodeResource   NodeType = "resource"
)

// EdgeType classifies relationships between nodes.
type EdgeType string

const (
	EdgeHasBinding  EdgeType = "has_binding"
	EdgeGrants      EdgeType = "grants"
	EdgeAllows      EdgeType = "allows"
	EdgeCanEscalate EdgeType = "can_escalate"
	EdgeAttachedTo  EdgeType = "attached_to"
)

// Node represents an entity in the GCP access graph.
type Node struct {
	ID       string
	Type     NodeType
	Label    string
	Project  string
	Metadata map[string]any
}

// Edge represents a relationship between two nodes.
type Edge struct {
	From      string
	To        string
	Type      EdgeType
	Label     string
	Technique string // Privesc technique ID if applicable.
	Metadata  map[string]any
}

// Graph is a directed graph modeling GCP access relationships.
type Graph struct {
	Nodes map[string]*Node
	Edges []*Edge

	// Adjacency lists for fast traversal.
	outEdges map[string][]*Edge
	inEdges  map[string][]*Edge
}

// New creates an empty graph.
func New() *Graph {
	return &Graph{
		Nodes:    make(map[string]*Node),
		outEdges: make(map[string][]*Edge),
		inEdges:  make(map[string][]*Edge),
	}
}

// AddNode adds a node to the graph. If it already exists, it's a no-op.
func (g *Graph) AddNode(n *Node) {
	if _, exists := g.Nodes[n.ID]; !exists {
		g.Nodes[n.ID] = n
	}
}

// AddEdge adds a directed edge to the graph.
func (g *Graph) AddEdge(e *Edge) {
	g.Edges = append(g.Edges, e)
	g.outEdges[e.From] = append(g.outEdges[e.From], e)
	g.inEdges[e.To] = append(g.inEdges[e.To], e)
}

// OutEdges returns all outgoing edges from a node.
func (g *Graph) OutEdges(nodeID string) []*Edge {
	return g.outEdges[nodeID]
}

// InEdges returns all incoming edges to a node.
func (g *Graph) InEdges(nodeID string) []*Edge {
	return g.inEdges[nodeID]
}

// Path represents a chain of edges from source to target.
type Path struct {
	Edges    []*Edge
	Nodes    []string
	Severity string
}

// String returns a human-readable representation of the path.
func (p *Path) String() string {
	if len(p.Nodes) == 0 {
		return "(empty path)"
	}
	result := p.Nodes[0]
	for i, e := range p.Edges {
		technique := ""
		if e.Technique != "" {
			technique = fmt.Sprintf(" [%s]", e.Technique)
		}
		result += fmt.Sprintf(" --%s%s--> %s", e.Type, technique, p.Nodes[i+1])
	}
	return result
}

// IdentityNodes returns all nodes of type identity.
func (g *Graph) IdentityNodes() []*Node {
	var nodes []*Node
	for _, n := range g.Nodes {
		if n.Type == NodeIdentity {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// Stats returns a summary of the graph.
func (g *Graph) Stats() map[string]int {
	stats := map[string]int{
		"nodes": len(g.Nodes),
		"edges": len(g.Edges),
	}
	for _, n := range g.Nodes {
		key := fmt.Sprintf("nodes_%s", n.Type)
		stats[key]++
	}
	for _, e := range g.Edges {
		key := fmt.Sprintf("edges_%s", e.Type)
		stats[key]++
	}
	return stats
}
