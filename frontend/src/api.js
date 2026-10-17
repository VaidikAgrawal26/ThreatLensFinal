export const TOKEN_KEY = 'threatlens_access_token';
export const BASE = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');

function errorMessage(payload, status, path) {
  const detail = payload?.detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) return detail.map(item => item.msg || JSON.stringify(item)).join('; ');
  if (detail && typeof detail === 'object') return JSON.stringify(detail);
  return `HTTP ${status} for ${path}`;
}

export async function api(path, options = {}) {
  if (!path.startsWith('/')) throw new Error('API paths must begin with /.');
  const headers = new Headers(options.headers || {});
  const token = window.localStorage.getItem(TOKEN_KEY);
  if (token && !headers.has('Authorization')) headers.set('Authorization', `Bearer ${token}`);
  if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  let response;
  try {
    response = await fetch(`${BASE}${path}`, { ...options, headers, credentials: 'omit' });
  } catch (error) {
    throw new Error(`Cannot reach API at ${BASE}. Check the API service and allowed frontend origin. ${error.message || ''}`.trim());
  }

  if (response.status === 204) return null;
  const contentType = response.headers.get('content-type') || '';
  let payload;
  try {
    payload = contentType.includes('json') ? await response.json() : await response.text();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    if (response.status === 401 && token) {
      window.localStorage.removeItem(TOKEN_KEY);
      window.dispatchEvent(new CustomEvent('threatlens:session-expired'));
    }
    throw new Error(errorMessage(payload, response.status, path));
  }
  return payload;
}

export async function apiDownload(path, filename) {
  const headers = new Headers();
  const token = window.localStorage.getItem(TOKEN_KEY);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  let response;
  try {
    response = await fetch(`${BASE}${path}`, { headers, credentials: 'omit' });
  } catch (error) {
    throw new Error(`Cannot reach API at ${BASE}. ${error.message || ''}`.trim());
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(errorMessage(payload, response.status, path));
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
