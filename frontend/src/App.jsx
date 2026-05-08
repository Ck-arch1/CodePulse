import { useState } from 'react';
import { Activity } from 'lucide-react';
import { analyzeFile, uploadFile, uploadRepo } from './api/endpoints';
import UploadZone from './components/UploadZone';
import GraphView from './components/GraphView';
import CodePanel from './components/CodePanel';
import FindingsList from './components/FindingsList';
import ReportPanel from './components/ReportPanel';
import StatsBar from './components/StatsBar';

export default function App() {
  const [report, setReport] = useState(null);
  const [code, setCode] = useState('');
  const [fileMeta, setFileMeta] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleFile(input) {
    const files = Array.isArray(input) ? input : [input];
    const file = files[0];
    if (!file) return;
    setLoading(true);
    setError('');
    setReport(null);
    const isRepo = files.length > 1 || file.name.toLowerCase().endsWith('.zip');
    const buffer = isRepo ? null : await file.arrayBuffer();
    const source = isRepo ? `Repository upload: ${files.map(item => item.name).join(', ')}` : new TextDecoder('utf-8', { fatal: false }).decode(buffer);
    const lines = source.split(/\r\n|\r|\n/);
    const preview = lines.length > 4000 ? `${lines.slice(0, 4000).join('\n')}\n\n# CodePulse preview truncated after 4000 lines for editor responsiveness.` : source;
    setCode(source);
    setFileMeta({
      name: file.name,
      language: isRepo ? 'REPOSITORY' : file.name.split('.').pop()?.toUpperCase() || 'Source',
      lines: lines.length,
      previewed: preview.length !== source.length
    });
    setCode(preview);
    try {
      const isPython = file.name.toLowerCase().endsWith('.py');
      const nextReport = await (isRepo ? uploadRepo(files) : isPython ? analyzeFile(file) : uploadFile(file));
      if (!nextReport?.scan_id) {
        setError('Analysis completed, but no scan ID was returned. Some follow-up views may be unavailable.');
      }
      setReport(nextReport || { findings: [], graph: { nodes: [], edges: [] }, warnings: [{ reason: 'Malformed backend response was handled safely.' }] });
    } catch (err) {
      const detail = err.response?.data?.detail;
      setError(detail?.error || detail || err.response?.data?.error || 'Upload failed. Check that the backend is running.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand"><Activity size={22} /> <span>CodePulse</span></div>
      </header>
      <UploadZone onFile={handleFile} loading={loading} />
      {error && <div className="error-banner">{error}</div>}
      {report?.warnings?.length > 0 && (
        <div className="warning-banner">
          {report.warnings.map((warning, index) => <span key={`${warning.reason}-${index}`}>{warning.reason}</span>)}
        </div>
      )}
      {fileMeta && <StatsBar fileMeta={fileMeta} />}
      <section className="workspace">
        <div className="graph-pane">
          <GraphView graph={report?.graph} />
        </div>
        <CodePanel code={code} findings={report?.findings || []} />
        <aside className="side-panel">
          <ReportPanel report={report} />
          <FindingsList findings={report?.findings || []} />
        </aside>
      </section>
    </main>
  );
}
