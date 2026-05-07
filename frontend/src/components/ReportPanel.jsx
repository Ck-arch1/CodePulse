export default function ReportPanel({ report }) {
  const stats = report?.stats;
  if (!stats) return <section className="panel"><h2>Risk Report</h2><p>Awaiting scan.</p></section>;
  return (
    <section className="panel">
      <h2>Risk Report</h2>
      <div className="metric-grid">
        <div><strong>{stats.total_findings}</strong><span>Findings</span></div>
        <div><strong>{stats.taint_path_count}</strong><span>Taint paths</span></div>
      </div>
      <h3>Severity</h3>
      {Object.entries(stats.severity_counts).map(([sev, count]) => <p key={sev}>{sev}: {count}</p>)}
      <h3>Top Risk</h3>
      {stats.top_risky_functions.map(item => <p key={item.name}>{item.name}: {item.score}/10</p>)}
    </section>
  );
}
