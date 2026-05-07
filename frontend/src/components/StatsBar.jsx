export default function StatsBar({ report }) {
  return (
    <section className="stats-bar">
      <span>{report.file_name}</span>
      <span>{report.language}</span>
      <span>{report.lines_of_code} LOC</span>
      <span>{report.scan_time_ms} ms</span>
    </section>
  );
}
