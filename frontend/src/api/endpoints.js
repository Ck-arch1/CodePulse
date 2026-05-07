import { apiClient } from './apiClient';

export async function analyzeFile(file) {
  const form = new FormData();
  form.append('file', file);
  const { data } = await apiClient.post('/analyze', form, { headers: { 'Content-Type': 'multipart/form-data' } });
  return data;
}

export async function getFindings() {
  const { data } = await apiClient.get('/findings');
  return data;
}

export async function getFileContent() {
  const { data } = await apiClient.get('/file-content');
  return data;
}

export async function explainFinding(findingId, onToken) {
  const response = await fetch('http://localhost:8000/explain', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ finding_id: findingId })
  });
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const chunks = buffer.split('\n\n');
    buffer = chunks.pop() || '';
    chunks.forEach(chunk => {
      if (chunk.startsWith('data: ')) onToken(chunk.slice(6));
    });
  }
}
