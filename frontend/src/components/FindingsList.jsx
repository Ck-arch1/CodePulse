const severityClass = severity => `severity ${severity.toLowerCase()}`;

export default function FindingsList({ findings }) {
  return (
    <section className="panel">
      <h2>Findings</h2>
      <div className="findings-list">
        {findings.length === 0 && <p>No findings yet.</p>}
        {findings.map((f, index) => (
          <div key={f.id || `${f.message || f.title}-${f.line}-${index}`} className="finding">
            <div className="finding-badges">
              <span className={severityClass(f.severity || f.type)}>{f.severity || f.type}</span>
              <span className="chip">{f.category || 'uncategorized'}</span>
              <span className="chip">{f.evidence?.analysis_type || f.tool || 'analysis'}</span>
              <span className="chip confidence">confidence {Math.round((f.confidence || 0) * 100)}%</span>
            </div>
            <strong>{f.title || f.message}</strong>
            {f.function && <small>{f.function}</small>}
            <small>line {f.line}</small>
            {f.cause_chain?.length > 0 && <div className="cause-chain">{f.cause_chain.map((step, stepIndex) => <span key={`${step}-${stepIndex}`}>{step}</span>)}</div>}
            {f.explanation && <span className="finding-explanation">{f.explanation}</span>}
          </div>
        ))}
      </div>
    </section>
  );
}
