export default function ReportPanel({ report }) {
  if (!report) return <section className="panel"><h2>Risk Report</h2><p>Upload a Python file to run the mock analysis.</p></section>;

  return (
    <section className="panel">
      <h2>Risk Report</h2>
      <div className="metric-grid">
        <div><strong>{report.risk_score}</strong><span>Risk score</span></div>
        <div><strong>{report.findings.length}</strong><span>Findings</span></div>
      </div>
      {report.analysis_mode && <p>{report.language} · {report.analysis_mode}</p>}
      {report.risk_composition && (
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
      {typeof report.blast_radius === 'number' && <p>Blast radius: {report.blast_radius}</p>}
      {report.taint_flows?.length > 0 && (
        <>
          <h3>Taint Flows</h3>
          {report.taint_flows.map((flow, index) => (
            <div className="flow-row" key={`${flow.source}-${flow.sink}-${index}`}>
              <strong>{flow.source}{' -> '}{flow.sink}</strong>
              <span>line {flow.line}</span>
              {flow.cause_chain?.length > 0 && <small>{flow.cause_chain.join(' -> ')}</small>}
            </div>
          ))}
        </>
      )}
    </section>
  );
}
