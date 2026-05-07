import Editor from '@monaco-editor/react';
import { useEffect, useMemo, useRef } from 'react';

export default function CodePanel({ code, findings }) {
  const editorRef = useRef(null);
  const monacoRef = useRef(null);
  const markers = useMemo(() => findings.map(f => ({ startLineNumber: f.line, endLineNumber: f.line, startColumn: 1, endColumn: 120, message: f.message || f.title, severity: 4 })), [findings]);

  useEffect(() => {
    const model = editorRef.current?.getModel();
    if (model && monacoRef.current) {
      monacoRef.current.editor.setModelMarkers(model, 'codepulse', markers);
    }
  }, [markers, code]);

  return (
    <section className="code-panel">
      <Editor
        height="100%"
        language="python"
        theme="vs-dark"
        value={code || '# Upload a Python file to inspect it'}
        options={{ readOnly: true, minimap: { enabled: false }, fontSize: 13 }}
        onMount={(editor, monaco) => {
          editorRef.current = editor;
          monacoRef.current = monaco;
          monaco.editor.setModelMarkers(editor.getModel(), 'codepulse', markers);
        }}
      />
    </section>
  );
}
