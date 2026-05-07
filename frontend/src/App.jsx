import { useMemo, useState } from 'react';
import { Activity, Download } from 'lucide-react';
import { analyzeFile, explainFinding } from './api/endpoints';
import UploadZone from './components/UploadZone';
import GraphView from './components/GraphView';
import CodePanel from './components/CodePanel';
import FindingsList from './components/FindingsList';
import ReportPanel from './components/ReportPanel';
import StatsBar from './components/StatsBar';
import VulnHighlight from './components/VulnHighlight';

export default function App() {
  const [report, setReport] = useState(null);
  const [code, setCode] = useState('');
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [explanation, setExplanation] = useState('');
  const [loading, setLoading] = useState(false);
  const highlightedPath = useMemo(() => report?.taint_paths?.[0] || [], [report]);

  async function handleFile(file) {
    setLoading(true);
    setSelectedFinding(null);
    setExplanation('');
    setCode(await file.text());
    try {
      setReport(await analyzeFile(file));
    } finally {
      setLoading(false);
    }
  }

  async function handleExplain(finding) {
    setSelectedFinding(finding);
    setExplanation('');
    await explainFinding(finding.id, token => setExplanation(prev => prev + token));
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand"><Activity size={22} /> <span>CodePulse</span></div>
        <a className="icon-button" href="http://localhost:8000/report" target="_blank" rel="noreferrer" title="Download HTML report"><Download size={18} /></a>
      </header>
      <UploadZone onFile={handleFile} loading={loading} />
      {report && <StatsBar report={report} />}
      <section className="workspace">
        <div className="graph-pane">
          <GraphView graph={report?.graph} scores={report?.scores || {}} path={highlightedPath} />
          <VulnHighlight path={highlightedPath} />
        </div>
        <CodePanel code={code} findings={report?.findings || []} selectedFinding={selectedFinding} />
        <aside className="side-panel">
          <ReportPanel report={report} />
          <FindingsList findings={report?.findings || []} onSelect={handleExplain} selectedId={selectedFinding?.id} explanation={explanation} />
        </aside>
      </section>
    </main>
  );
}
