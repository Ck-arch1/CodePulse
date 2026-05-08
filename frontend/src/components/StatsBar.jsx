export default function StatsBar({ fileMeta }) {
  if (!fileMeta) return null;
  return (
    <section className="stats-bar">
      <span>{fileMeta.name || 'source file'}</span>
      <span>{fileMeta.language || 'Source'}</span>
      <span>{fileMeta.lines || 0} lines</span>
      {fileMeta.previewed && <span>editor preview truncated</span>}
    </section>
  );
}
