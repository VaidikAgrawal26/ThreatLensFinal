const BASE = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8001').replace(/\/$/, '');
export async function api(path, options = {}) {
  let response;
  const headers = new Headers(options.headers || {});
  const token = window.localStorage.getItem('threatlens_access_token');
  if (token && !headers.has('Authorization')) headers.set('Authorization', `Bearer ${token}`);
  if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) headers.set('Content-Type','application/json');
  try { response = await fetch(`${BASE}${path}`, {...options, headers}); }
  catch (error) { throw new Error(`Cannot reach API at ${BASE}. Check that FastAPI is running and CORS allows the current frontend origin. ${error.message || ''}`.trim()); }
  const contentType = response.headers.get('content-type') || '';
  const data = contentType.includes('json') ? await response.json() : await response.text();
  if (!response.ok) throw new Error(data?.detail || `HTTP ${response.status} for ${path}`);
  return data;
}
export { BASE };
