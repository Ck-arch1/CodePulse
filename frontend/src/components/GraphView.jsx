import cytoscape from 'cytoscape';
import fcose from 'cytoscape-fcose';
import CytoscapeComponent from 'react-cytoscapejs';

cytoscape.use(fcose);

const riskColor = score => score <= 3 ? '#22c55e' : score <= 6 ? '#f59e0b' : '#ef4444';
const nodeBorder = ele => {
  const type = ele.data('node_type');
  if (type === 'source') return '#0ea5e9';
  if (type === 'tainted') return '#7c3aed';
  if (type === 'sink') return '#ef4444';
  if (ele.data('blast_radius') > 1) return '#f97316';
  return '#e5e7eb';
};

export default function GraphView({ graph }) {
  const elements = graph ? CytoscapeComponent.normalizeElements({
    nodes: graph.nodes,
    edges: graph.edges.map((edge, index) => ({ data: { id: `e-${index}`, ...edge.data } }))
  }) : [];

  return (
    <CytoscapeComponent
      elements={elements}
      className="graph"
      layout={{ name: 'fcose', animate: true, fit: true, padding: 24 }}
      stylesheet={[
        { selector: 'node', style: { label: 'data(label)', 'background-color': ele => riskColor(ele.data('risk') || 0), color: '#111827', 'font-size': 11, 'text-valign': 'bottom', 'text-margin-y': 7, width: 38, height: 38, 'border-width': ele => ele.data('node_type') !== 'normal' || ele.data('blast_radius') > 1 ? 4 : 1, 'border-color': nodeBorder } },
        { selector: 'edge', style: { width: ele => ele.data('risky') ? 4 : 2, 'line-color': ele => ele.data('risky') ? '#dc2626' : '#6b7280', 'target-arrow-shape': 'triangle', 'target-arrow-color': ele => ele.data('risky') ? '#dc2626' : '#6b7280', 'curve-style': 'bezier' } }
      ]}
    />
  );
}
