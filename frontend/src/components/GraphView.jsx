import cytoscape from 'cytoscape';
import fcose from 'cytoscape-fcose';
import CytoscapeComponent from 'react-cytoscapejs';

cytoscape.use(fcose);

const riskColor = score => score <= 3 ? '#22c55e' : score <= 6 ? '#f59e0b' : '#ef4444';

export default function GraphView({ graph, path = [] }) {
  const elements = graph ? CytoscapeComponent.normalizeElements({
    nodes: graph.nodes.map(node => ({ data: { ...node, id: node.id || node.label } })),
    edges: graph.edges.map((edge, index) => ({ data: { id: `e-${index}`, source: edge.source, target: edge.target } }))
  }) : [];
  const pathEdges = new Set(path.slice(0, -1).map((node, i) => `${node}->${path[i + 1]}`));
  return (
    <CytoscapeComponent
      elements={elements}
      className="graph"
      layout={{ name: 'fcose', animate: true, fit: true, padding: 24 }}
      stylesheet={[
        { selector: 'node', style: { label: 'data(label)', 'background-color': ele => riskColor(ele.data('risk_score') || 0), color: '#111827', 'font-size': 11, 'text-valign': 'bottom', 'text-margin-y': 7, width: 34, height: 34, 'border-width': ele => ele.data('has_taint') || ele.data('has_sql_issue') ? 4 : 1, 'border-color': ele => ele.data('has_sql_issue') ? '#3b82f6' : ele.data('has_taint') ? '#7c3aed' : '#e5e7eb' } },
        { selector: 'edge', style: { width: ele => pathEdges.has(`${ele.data('source')}->${ele.data('target')}`) ? 5 : 2, 'line-color': ele => pathEdges.has(`${ele.data('source')}->${ele.data('target')}`) ? '#f97316' : '#6b7280', 'target-arrow-shape': 'triangle', 'target-arrow-color': ele => pathEdges.has(`${ele.data('source')}->${ele.data('target')}`) ? '#f97316' : '#6b7280', 'curve-style': 'bezier' } }
      ]}
    />
  );
}
