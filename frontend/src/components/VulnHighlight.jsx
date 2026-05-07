export default function VulnHighlight({ path }) {
  return <div className="path-strip">{path?.length ? `Highlighted propagation path: ${path.join(' -> ')}` : 'No taint propagation path highlighted yet.'}</div>;
}
