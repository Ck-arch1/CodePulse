import Editor from '@monaco-editor/react';

export default function CodePanel({ code, findings, selectedFinding }) {
  const markers = findings.map(f => ({ startLineNumber: f.line_number, endLineNumber: f.line_number, startColumn: 1, endColumn: 120, message: f.message, severity: 8 }));
  return (
    <section className="code-panel">
      <Editor height="100%" language="python" theme="vs-dark" value={code || '# Upload a Python file to inspect it'} options={{ readOnly: true, minimap: { enabled: false }, fontSize: 13 }} onMount={(editor, monaco) => monaco.editor.setModelMarkers(editor.getModel(), 'codepulse', markers)} />
      {selectedFinding && <div className="line-chip">Line {selectedFinding.line_number}: {selectedFinding.type}</div>}
    </section>
  );
}
