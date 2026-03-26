package graph

import (
	"fmt"
	"os"
	"strings"
)

// escapeCypher escapes a string for use in a Cypher property value.
func escapeCypher(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return s
}

// ExportCypher writes Cypher CREATE statements representing the graph to a file.
func ExportCypher(g *Graph, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write node CREATE statements.
	for _, node := range g.Nodes {
		var stmt string
		esc := escapeCypher
		switch node.Type {
		case NodeIdentity:
			stmt = fmt.Sprintf(
				`CREATE (n:Identity {id: "%s", label: "%s", project: "%s"})`,
				esc(node.ID), esc(node.Label), esc(node.Project),
			)
		case NodeRole:
			stmt = fmt.Sprintf(
				`CREATE (n:Role {id: "%s", label: "%s"})`,
				esc(node.ID), esc(node.Label),
			)
		case NodeResource:
			resourceType := ""
			if node.Metadata != nil {
				if t, ok := node.Metadata["type"].(string); ok {
					resourceType = t
				}
			}
			stmt = fmt.Sprintf(
				`CREATE (n:Resource {id: "%s", label: "%s", type: "%s"})`,
				esc(node.ID), esc(node.Label), esc(resourceType),
			)
		default:
			stmt = fmt.Sprintf(
				`CREATE (n:Node {id: "%s", label: "%s", type: "%s"})`,
				esc(node.ID), esc(node.Label), esc(string(node.Type)),
			)
		}
		fmt.Fprintln(f, stmt)
	}

	// Write edge MATCH/CREATE statements.
	for _, edge := range g.Edges {
		relType := edgeTypeToRelType(edge.Type)
		stmt := fmt.Sprintf(
			`MATCH (a {id: "%s"}), (b {id: "%s"}) CREATE (a)-[:%s]->(b)`,
			escapeCypher(edge.From), escapeCypher(edge.To), relType,
		)
		fmt.Fprintln(f, stmt)
	}

	return nil
}

// edgeTypeToRelType converts an EdgeType to a Cypher relationship type.
func edgeTypeToRelType(t EdgeType) string {
	switch t {
	case EdgeHasBinding:
		return "HAS_BINDING"
	case EdgeGrants:
		return "GRANTS"
	case EdgeAllows:
		return "ALLOWS"
	case EdgeCanEscalate:
		return "CAN_ESCALATE"
	case EdgeAttachedTo:
		return "ATTACHED_TO"
	default:
		return strings.ToUpper(strings.ReplaceAll(string(t), " ", "_"))
	}
}

// escapeDOTLabel escapes a string for use in a DOT label.
func escapeDOTLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// ExportDOT writes the graph in Graphviz DOT format to a file.
func ExportDOT(g *Graph, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintln(f, "digraph nimbus {")
	fmt.Fprintln(f, "  rankdir=LR;")
	fmt.Fprintln(f, "  node [shape=box, style=filled];")
	fmt.Fprintln(f, "")

	// Write nodes with type-specific styling.
	for _, node := range g.Nodes {
		color := "white"
		shape := "box"
		switch node.Type {
		case NodeIdentity:
			color = "#AED6F1"
			shape = "ellipse"
		case NodeRole:
			color = "#A9DFBF"
			shape = "box"
		case NodeResource:
			color = "#F9E79F"
			shape = "box3d"
		case NodePermission:
			color = "#FADBD8"
			shape = "note"
		}
		label := node.Label
		if label == "" {
			label = node.ID
		}
		fmt.Fprintf(f, "  \"%s\" [label=\"%s\", shape=%s, fillcolor=\"%s\"];\n",
			escapeDOTLabel(node.ID), escapeDOTLabel(label), shape, color)
	}

	fmt.Fprintln(f, "")

	// Write edges.
	for _, edge := range g.Edges {
		label := string(edge.Type)
		if edge.Technique != "" {
			label = fmt.Sprintf("%s\\n[%s]", edge.Type, edge.Technique)
		}
		color := "black"
		if edge.Type == EdgeCanEscalate {
			color = "red"
		}
		fmt.Fprintf(f, "  \"%s\" -> \"%s\" [label=\"%s\", color=%s];\n",
			escapeDOTLabel(edge.From), escapeDOTLabel(edge.To), escapeDOTLabel(label), color)
	}

	fmt.Fprintln(f, "}")

	return nil
}
