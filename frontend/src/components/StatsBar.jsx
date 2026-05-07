export default function StatsBar({ fileMeta }) {
  return (
    <section className="stats-bar">
      <span>{fileMeta.name}</span>
      <span>{fileMeta.language}</span>
      <span>{fileMeta.lines} lines</span>
    </section>
  );
}
