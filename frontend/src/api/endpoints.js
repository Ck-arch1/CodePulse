import { apiClient } from './apiClient';

export async function analyzeFile(file) {
  const form = new FormData();
  form.append('file', file);
  const { data } = await apiClient.post('/analyze', form, { headers: { 'Content-Type': 'multipart/form-data' } });
  return data;
}

export async function uploadFile(file) {
  const form = new FormData();
  form.append('file', file);
  const { data } = await apiClient.post('/upload', form, { headers: { 'Content-Type': 'multipart/form-data' } });
  return data;
}

export async function uploadRepo(files) {
  const form = new FormData();
  files.forEach(file => form.append('files', file));
  const { data } = await apiClient.post('/upload-repo', form, { headers: { 'Content-Type': 'multipart/form-data' } });
  return data;
}

export async function getFindings() {
  const { data } = await apiClient.get('/findings');
  return data;
}

export async function getFindingsForScan(scanId) {
  const { data } = await apiClient.get(`/findings/${encodeURIComponent(scanId)}`);
  return data;
}

export async function getGraphForScan(scanId) {
  const { data } = await apiClient.get(`/graph/${encodeURIComponent(scanId)}`);
  return data;
}

export async function getFileContent(scanId) {
  const { data } = await apiClient.get(scanId ? `/file-content/${encodeURIComponent(scanId)}` : '/file-content');
  return data;
}

export async function explainFinding(scanId, findingId, onToken) {
  if (!scanId) {
    onToken('Explanation unavailable because this scan has expired or no scan ID was returned.');
    return;
  }
  const response = await fetch(`http://localhost:8000/explain/${encodeURIComponent(scanId)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ finding_id: findingId })
  });
  if (!response.ok || !response.body) {
    onToken('LLM explanation temporarily unavailable.');
    return;
  }
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
