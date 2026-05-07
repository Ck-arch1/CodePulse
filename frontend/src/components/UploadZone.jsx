import { UploadCloud } from 'lucide-react';
import { useRef, useState } from 'react';

export default function UploadZone({ onFile, loading }) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const pick = file => file?.name.endsWith('.py') && onFile(file);
  return (
    <section className={`upload-zone ${dragging ? 'dragging' : ''}`} onDragOver={e => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={e => { e.preventDefault(); setDragging(false); pick(e.dataTransfer.files[0]); }}>
      <button onClick={() => inputRef.current?.click()} disabled={loading}><UploadCloud size={18} /> {loading ? 'Scanning...' : 'Upload Python file'}</button>
      <input ref={inputRef} type="file" accept=".py" hidden onChange={e => pick(e.target.files[0])} />
    </section>
  );
}
