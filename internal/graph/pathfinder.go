package graph

// FindPaths performs BFS from a source node and returns all paths up to maxDepth.
func (g *Graph) FindPaths(sourceID string, maxDepth int) []Path {
	if maxDepth <= 0 {
		maxDepth = 6
	}

	type state struct {
		nodeID string
		path   Path
	}

	var results []Path
	visited := make(map[string]bool)
	queue := []state{{nodeID: sourceID, path: Path{Nodes: []string{sourceID}}}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if len(current.path.Edges) >= maxDepth {
			continue
		}

		for _, edge := range g.OutEdges(current.nodeID) {
			if visited[current.nodeID+"->"+edge.To] {
				continue
			}
			visited[current.nodeID+"->"+edge.To] = true

			newPath := Path{
				Edges:    make([]*Edge, len(current.path.Edges)+1),
				Nodes:    make([]string, len(current.path.Nodes)+1),
				Severity: current.path.Severity,
			}
			copy(newPath.Edges, current.path.Edges)
			copy(newPath.Nodes, current.path.Nodes)
			newPath.Edges[len(current.path.Edges)] = edge
			newPath.Nodes[len(current.path.Nodes)] = edge.To

			if edge.Type == EdgeCanEscalate {
				if newPath.Severity == "" {
					newPath.Severity = "HIGH"
				}
				results = append(results, newPath)
			}

			queue = append(queue, state{nodeID: edge.To, path: newPath})
		}
	}
	return results
}

// FindPathsTo finds all paths from any identity to a specific target node.
func (g *Graph) FindPathsTo(targetID string, maxDepth int) []Path {
	var results []Path
	for _, node := range g.IdentityNodes() {
		paths := g.FindPaths(node.ID, maxDepth)
		for _, p := range paths {
			// Check if any node in the path leads to the target.
			for _, n := range p.Nodes {
				if n == targetID {
					results = append(results, p)
					break
				}
			}
		}
	}
	return results
}

// FindEscalationPaths returns all paths that contain a can_escalate edge.
func (g *Graph) FindEscalationPaths(maxDepth int) []Path {
	var results []Path
	for _, node := range g.IdentityNodes() {
		paths := g.FindPaths(node.ID, maxDepth)
		results = append(results, paths...)
	}
	return results
}
