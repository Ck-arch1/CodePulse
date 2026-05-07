const severityClass = severity => `severity ${severity.toLowerCase()}`;

export default function FindingsList({ findings, onSelect, selectedId, explanation }) {
  return (
    <section className="panel">
      <h2>Findings</h2>
      <div className="findings-list">
        {findings.map(f => (
          <button key={f.id} className={`finding ${selectedId === f.id ? 'active' : ''}`} onClick={() => onSelect(f)}>
            <span className={severityClass(f.severity)}>{f.severity}</span>
            <strong>{f.type}</strong>
            <small>{f.function_name} · line {f.line_number}</small>
            <span>{f.message}</span>
          </button>
        ))}
      </div>
      <div className="explanation">{explanation || 'Select a finding for a streamed local LLM explanation.'}</div>
    </section>
  );
}
