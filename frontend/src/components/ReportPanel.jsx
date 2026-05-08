export default function ReportPanel({ report }) {
  if (!report) return <section className="panel"><h2>Risk Report</h2><p>Upload a Python file to run the mock analysis.</p></section>;
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  const categoryCounts = findings.reduce((acc, finding) => {
    const category = finding?.category || 'uncategorized';
    acc[category] = (acc[category] || 0) + 1;
    return acc;
  }, {});
  const confidenceBuckets = findings.reduce((acc, finding) => {
    const confidence = Number(finding?.confidence || 0);
    const bucket = confidence >= 0.9 ? 'high' : confidence >= 0.6 ? 'medium' : 'low';
    acc[bucket] += 1;
    return acc;
  }, { high: 0, medium: 0, low: 0 });

  return (
    <section className="panel">
      <h2>Risk Report</h2>
      <div className="metric-grid">
        <div><strong>{report?.risk_score ?? 0}</strong><span>Risk score</span></div>
        <div><strong>{findings.length}</strong><span>Findings</span></div>
      </div>
      {report?.analysis_mode && <p>{report?.language || 'source'} · {report.analysis_mode}</p>}
      {report?.truncated && <p className="warning-text">Analysis output was truncated for stability.</p>}
      {report?.repo_summary && (
        <>
          <h3>Repository Summary</h3>
          <div className="composition-list">
            <div><span>Analyzed files</span><strong>{report.repo_summary.analyzed_files || 0}</strong></div>
            <div><span>Total findings</span><strong>{report.repo_summary.total_findings || 0}</strong></div>
          </div>
          <h3>Languages</h3>
          <div className="chip-row">
            {Object.entries(report.repo_summary.language_distribution || {}).map(([key, value]) => <span className="chip" key={key}>{key}: {value}</span>)}
          </div>
          {report.repo_summary.critical_files?.length > 0 && (
            <>
              <h3>Critical Files</h3>
              {report.repo_summary.critical_files.slice(0, 5).map(item => (
                <div className="flow-row" key={item.file}><strong>{item.file}</strong><span>risk {item.risk_score}</span></div>
              ))}
            </>
          )}
          {report.repo_summary.top_risky_dependencies?.length > 0 && (
            <>
              <h3>Dependencies</h3>
              <div className="chip-row">
                {report.repo_summary.top_risky_dependencies.slice(0, 8).map(item => <span className="chip" key={item.dependency}>{item.dependency}: {item.count}</span>)}
              </div>
            </>
          )}
        </>
      )}
      {report?.risk_composition && (
        <>
          <h3>Risk Composition</h3>
          <div className="composition-list">
            {Object.entries(report.risk_composition).map(([key, value]) => (
              <div key={key}>
                <span>{key}</span>
                <strong>{value}</strong>
              </div>
            ))}
          </div>
        </>
      )}
      <h3>Categories</h3>
      <div className="chip-row">{Object.entries(categoryCounts).map(([key, value]) => <span className="chip" key={key}>{key}: {value}</span>)}</div>
      <h3>Confidence</h3>
      <div className="chip-row">
        <span className="chip confidence">high: {confidenceBuckets.high}</span>
        <span className="chip">medium: {confidenceBuckets.medium}</span>
        <span className="chip">low: {confidenceBuckets.low}</span>
      </div>
      {typeof report?.blast_radius === 'number' && <p>Blast radius: {report.blast_radius}</p>}
      {report?.taint_flows?.length > 0 && (
        <>
          <h3>Taint Flows</h3>
          {report.taint_flows.map((flow, index) => {
            const isPath = Array.isArray(flow);
            return (
            <div className="flow-row" key={`${isPath ? flow.join('-') : `${flow.source}-${flow.sink}`}-${index}`}>
              <strong>{isPath ? flow.join(' -> ') : `${flow.source} -> ${flow.sink}`}</strong>
              {!isPath && <span>line {flow.line}</span>}
              {!isPath && flow.cause_chain?.length > 0 && <small>{flow.cause_chain.join(' -> ')}</small>}
            </div>
          )})}
        </>
      )}
    </section>
  );
}
