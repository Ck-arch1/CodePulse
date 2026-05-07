import { useState } from 'react';
import { Activity } from 'lucide-react';
import { uploadFile } from './api/endpoints';
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

  async function handleFile(file) {
    setLoading(true);
    setError('');
    setReport(null);
    const source = await file.text();
    setCode(source);
    setFileMeta({
      name: file.name,
      language: 'Python',
      lines: source.split(/\r\n|\r|\n/).length
    });
    try {
      setReport(await uploadFile(file));
    } catch (err) {
      setError(err.response?.data?.detail || 'Upload failed. Check that the backend is running.');
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
