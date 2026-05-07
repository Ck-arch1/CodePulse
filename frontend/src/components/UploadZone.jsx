import { UploadCloud } from 'lucide-react';
import { useRef, useState } from 'react';

export default function UploadZone({ onFile, loading }) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const supportedExtensions = ['.py', '.cpp', '.cc', '.cxx', '.c', '.java', '.js', '.ts', '.cs', '.go', '.rs'];
  const pick = file => {
    const name = file?.name.toLowerCase() || '';
    if (supportedExtensions.some(extension => name.endsWith(extension))) {
      onFile(file);
    }
  };
  return (
    <section className={`upload-zone ${dragging ? 'dragging' : ''}`} onDragOver={e => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={e => { e.preventDefault(); setDragging(false); pick(e.dataTransfer.files[0]); }}>
      <button onClick={() => inputRef.current?.click()} disabled={loading}><UploadCloud size={18} /> {loading ? 'Scanning...' : 'Upload source file'}</button>
      <input ref={inputRef} type="file" accept=".py,.cpp,.cc,.cxx,.c,.java,.js,.ts,.cs,.go,.rs" hidden onChange={e => pick(e.target.files[0])} />
    </section>
  );
}
