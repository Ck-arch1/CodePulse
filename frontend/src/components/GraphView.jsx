import cytoscape from 'cytoscape';
import fcose from 'cytoscape-fcose';
import { useMemo, useState } from 'react';
import CytoscapeComponent from 'react-cytoscapejs';

cytoscape.use(fcose);

const MAX_VISIBLE_NODES = 220;
const MAX_VISIBLE_EDGES = 320;
const riskColor = score => score <= 3 ? '#22c55e' : score <= 6 ? '#f59e0b' : '#ef4444';
const nodeBorder = ele => {
  const type = ele.data('node_type');
  if (type === 'source') return '#0ea5e9';
  if (type === 'tainted') return '#7c3aed';
  if (type === 'sink') return '#ef4444';
  if (type === 'dependency') return '#14b8a6';
  if (ele.data('blast_radius') > 1) return '#f97316';
  return '#e5e7eb';
};

export default function GraphView({ graph }) {
  const [hideLowRisk, setHideLowRisk] = useState(false);
  const [taintedOnly, setTaintedOnly] = useState(false);
  const [criticalOnly, setCriticalOnly] = useState(false);
  const [collapseIsolated, setCollapseIsolated] = useState(true);
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes.filter(Boolean) : [];
  const edges = Array.isArray(graph?.edges) ? graph.edges.filter(Boolean) : [];
  const oversized = nodes.length > MAX_VISIBLE_NODES || edges.length > MAX_VISIBLE_EDGES;
  const elements = useMemo(() => {
    const riskyEdges = edges.filter(edge => Boolean(edge?.data?.risky));
    const connected = new Set(edges.flatMap(edge => [edge?.data?.source, edge?.data?.target]).filter(Boolean));
    const visibleNodes = nodes.filter(node => {
      const data = node?.data || {};
      if (!data.id) return false;
      if (collapseIsolated && !connected.has(data.id) && data.node_type === 'normal') return false;
      if (hideLowRisk && Number(data.risk || 0) <= 1 && data.node_type === 'normal') return false;
      if (taintedOnly && !['source', 'sink', 'tainted'].includes(data.node_type)) return false;
      if (criticalOnly && Number(data.risk || 0) < 8 && data.node_type !== 'sink') return false;
      return true;
    }).slice(0, MAX_VISIBLE_NODES);
    const visibleIds = new Set(visibleNodes.map(node => node.data.id));
    const visibleEdges = (taintedOnly ? riskyEdges : edges)
      .filter(edge => visibleIds.has(edge?.data?.source) && visibleIds.has(edge?.data?.target))
      .slice(0, MAX_VISIBLE_EDGES)
      .map((edge, index) => ({ data: { id: `e-${index}`, ...(edge.data || {}) } }));
    return CytoscapeComponent.normalizeElements({ nodes: visibleNodes, edges: visibleEdges });
  }, [nodes, edges, hideLowRisk, taintedOnly, criticalOnly, collapseIsolated]);
  const layout = elements.length > 300
    ? { name: 'breadthfirst', animate: false, fit: true, padding: 24, directed: true }
    : { name: 'fcose', animate: false, randomize: false, fit: true, padding: 24, quality: 'draft' };

  return (
    <>
      <div className="graph-toolbar">
        <label><input type="checkbox" checked={hideLowRisk} onChange={event => setHideLowRisk(event.target.checked)} /> hide low risk</label>
        <label><input type="checkbox" checked={taintedOnly} onChange={event => setTaintedOnly(event.target.checked)} /> tainted paths</label>
        <label><input type="checkbox" checked={criticalOnly} onChange={event => setCriticalOnly(event.target.checked)} /> critical only</label>
        <label><input type="checkbox" checked={collapseIsolated} onChange={event => setCollapseIsolated(event.target.checked)} /> collapse isolated</label>
      </div>
      <div className="graph-legend">
        <span><i className="legend-source" /> source</span>
        <span><i className="legend-sink" /> sink</span>
        <span><i className="legend-tainted" /> tainted</span>
        <span><i className="legend-blast" /> blast radius</span>
        <span><i className="legend-dependency" /> dependency</span>
      </div>
      {oversized && (
        <div className="graph-warning">
          Rendering capped at {MAX_VISIBLE_NODES} nodes and {MAX_VISIBLE_EDGES} edges. Use filters to inspect risky paths.
        </div>
      )}
      {elements.length === 0 ? <div className="empty-graph">No graph relationships to render.</div> : (
        <CytoscapeComponent
          elements={elements}
          className="graph"
          layout={layout}
          stylesheet={[
            { selector: 'node', style: { label: elements.length > 180 ? '' : 'data(label)', 'background-color': ele => ele.data('node_type') === 'dependency' ? '#ccfbf1' : riskColor(ele.data('risk') || 0), color: '#111827', 'font-size': 11, 'text-valign': 'bottom', 'text-margin-y': 7, width: ele => ele.data('blast_radius') > 1 ? 46 : 38, height: ele => ele.data('blast_radius') > 1 ? 46 : 38, 'border-width': ele => ele.data('node_type') !== 'normal' || ele.data('blast_radius') > 1 ? 4 : 1, 'border-color': nodeBorder } },
            { selector: 'edge', style: { width: ele => ele.data('risky') ? 4 : 2, 'line-color': ele => ele.data('risky') ? '#dc2626' : '#6b7280', 'target-arrow-shape': 'triangle', 'target-arrow-color': ele => ele.data('risky') ? '#dc2626' : '#6b7280', 'curve-style': 'bezier' } }
          ]}
          cy={cy => {
            cy.maxZoom(2.5);
            cy.minZoom(0.15);
          }}
        />
      )}
    </>
  );
}
