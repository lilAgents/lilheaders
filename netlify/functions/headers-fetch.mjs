// lilHeaders fetcher.
// Reads a live page's response headers server-side (browsers can't read
// cross-origin response headers) and returns them with the final URL.

const MAX_HOPS = 5;
const TIMEOUT_MS = 9000;

// Block local / private / link-local targets (basic SSRF guard), checked on
// every hop since a public URL can redirect to a private one.
function isBlockedHost(hostname) {
  const h = (hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;
  if (h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80')) return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 0 || a === 127 || a === 10) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  return false;
}

const json = (statusCode, obj) => ({
  statusCode,
  headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  body: JSON.stringify(obj),
});

export const handler = async (event) => {
  const raw = (event.queryStringParameters && event.queryStringParameters.url || '').trim();
  if (!raw) return json(400, { error: 'Enter a URL to scan.' });
  const start = /^https?:\/\//i.test(raw) ? raw : 'https://' + raw;

  let u;
  try { u = new URL(start); } catch { return json(400, { error: 'That does not look like a valid URL.' }); }
  if (!/^https?:$/.test(u.protocol)) return json(400, { error: 'Only http and https URLs can be scanned.' });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let current = u.toString();
  let resp = null;

  try {
    for (let i = 0; i < MAX_HOPS; i++) {
      const host = (() => { try { return new URL(current).hostname; } catch { return ''; } })();
      if (isBlockedHost(host)) { clearTimeout(timer); return json(400, { error: 'For safety, local and private addresses cannot be scanned.' }); }
      let r;
      try {
        r = await fetch(current, {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'user-agent': 'Mozilla/5.0 (compatible; lilHeaders/1.0; +https://lilheaders.netlify.app)',
            accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
          },
        });
      } catch (e) {
        clearTimeout(timer);
        if (e && e.name === 'AbortError') return json(504, { error: 'The page took too long to respond.' });
        return json(502, { error: 'Could not reach that URL. Check the link and try again.' });
      }
      const loc = r.headers.get('location');
      if (r.status >= 300 && r.status < 400 && loc) {
        try { current = new URL(loc, current).toString(); } catch { current = loc; }
        continue;
      }
      resp = r;
      break;
    }
  } finally {
    clearTimeout(timer);
  }

  if (!resp) return json(502, { error: 'Too many redirects while loading that page.' });

  const headers = {};
  resp.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });

  return json(200, { url: current, status: resp.status, headers });
};
