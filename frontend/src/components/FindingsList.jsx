import { useState } from 'react';

const severityClass = severity => `severity ${severity.toLowerCase()}`;

export default function FindingsList({ findings }) {
  const [expanded, setExpanded] = useState(null);
  const safeFindings = Array.isArray(findings) ? findings : [];
  const keyOccurrences = new Map();
  const stableKeyFor = finding => {
    if (finding?.id) return String(finding.id);
    const line = finding?.line ?? finding?.line_number ?? 'n/a';
    const fn = finding?.function ?? finding?.function_name ?? 'module';
    const type = finding?.category ?? finding?.type ?? finding?.severity ?? 'finding';
    const message = finding?.message ?? finding?.title ?? 'untitled';
    const base = `${type}|${fn}|${line}|${message}`;
    const occurrence = keyOccurrences.get(base) || 0;
    keyOccurrences.set(base, occurrence + 1);
    return `${base}|${occurrence}`;
  };
  return (
    <section className="panel">
      <h2>Findings</h2>
      <div className="findings-list">
        {safeFindings.length === 0 && <p>No findings yet.</p>}
        {safeFindings.map(f => {
          const id = stableKeyFor(f);
          const confidence = Math.round(Number(f?.confidence || 0) * 100);
          const isOpen = expanded === id;
          return (
          <button key={id} className="finding" onClick={() => setExpanded(isOpen ? null : id)} type="button">
            <div className="finding-badges">
              <span className={severityClass(f?.severity || f?.type || 'low')}>{f?.severity || f?.type || 'low'}</span>
              <span className="chip">{f?.category || 'uncategorized'}</span>
              <span className="chip">{f?.evidence?.analysis_type || f?.tool || 'analysis'}</span>
              <span className="chip confidence">confidence {confidence}%</span>
            </div>
            <div className="confidence-bar"><span style={{ width: `${confidence}%` }} /></div>
            <strong>{f?.title || f?.message || 'Finding'}</strong>
            {f?.function && <small>{f.function}</small>}
            <small>line {f?.line || f?.line_number || 'n/a'}</small>
            {f?.cause_chain?.length > 0 && <div className="cause-chain">{f.cause_chain.map((step, stepIndex) => <span key={`${step}-${stepIndex}`}>{step}</span>)}</div>}
            {isOpen && (
              <div className="remediation-panel">
                {f?.explanation && <span className="finding-explanation">{f.explanation}</span>}
                {f?.recommendation && <strong>Remediation: {f.recommendation}</strong>}
              </div>
            )}
          </button>
        )})}
      </div>
    </section>
  );
}
