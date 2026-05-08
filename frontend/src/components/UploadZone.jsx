import { UploadCloud } from 'lucide-react';
import { useRef, useState } from 'react';

export default function UploadZone({ onFile, loading }) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const [rejection, setRejection] = useState('');
  const supportedExtensions = ['.py', '.cpp', '.cc', '.cxx', '.c', '.java', '.js', '.ts', '.cs', '.go', '.rs', '.zip'];
  const pick = fileList => {
    const files = Array.from(fileList || []).filter(Boolean);
    if (files.length === 0) return;
    const unsupported = files.find(file => !supportedExtensions.some(extension => file.name.toLowerCase().endsWith(extension)));
    if (!unsupported) {
      setRejection('');
      onFile(files.length === 1 ? files[0] : files);
      return;
    }
    setRejection(`Unsupported file type. Supported: ${supportedExtensions.join(', ')}`);
    if (inputRef.current) inputRef.current.value = '';
  };
  return (
    <section className={`upload-zone ${dragging ? 'dragging' : ''}`} onDragOver={e => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={e => { e.preventDefault(); setDragging(false); pick(e.dataTransfer.files); }}>
      <button onClick={() => inputRef.current?.click()} disabled={loading}><UploadCloud size={18} /> {loading ? 'Scanning...' : 'Upload source file'}</button>
      {rejection && <span className="upload-rejection">{rejection}</span>}
      <input ref={inputRef} type="file" accept=".py,.cpp,.cc,.cxx,.c,.java,.js,.ts,.cs,.go,.rs,.zip" multiple hidden onChange={e => pick(e.target.files)} />
    </section>
  );
}
