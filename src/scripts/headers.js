// lilHeaders: scan a site's live response headers via the /headers-fetch
// Netlify function, grade them in plain English, and generate a ready-to-paste
// baseline config for Netlify, Apache, Nginx, or Vercel.

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

/* ---------- theme (OS-aware, matches the family) ---------- */
const MOON_SVG = '<svg viewBox="0 0 24 24" width="17" height="17" aria-hidden="true"><path fill="currentColor" d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>';
const SUN_SVG = '<svg viewBox="0 0 24 24" width="17" height="17" aria-hidden="true"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6l1.4 1.4M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4l1.4-1.4M18 6l1.4-1.4"/></g></svg>';

function setThemeIcon(btn, theme) {
  if (theme === 'dark') { btn.innerHTML = SUN_SVG; btn.setAttribute('aria-label', 'Switch to light mode'); }
  else { btn.innerHTML = MOON_SVG; btn.setAttribute('aria-label', 'Switch to dark mode'); }
}
function initTheme() {
  const btn = $('#ui-theme-btn');
  const current = () => (document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light');
  setThemeIcon(btn, current());
  btn.addEventListener('click', () => {
    const next = current() === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('lilheaders-theme', next); } catch (e) { /* storage may be unavailable; safe to ignore */ }
    setThemeIcon(btn, next);
  });
}

/* ---------- helpers ---------- */
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/* ---------- checks ---------- */
function buildChecks(finalUrl, h, cert) {
  const c = [];
  const isHttps = finalUrl.startsWith('https://');

  // HTTPS itself
  if (!isHttps) c.push({ k: 'err', t: 'Site served over plain HTTP', m: 'Everything else is secondary until the site is on HTTPS.', rec: null });

  // TLS certificate
  if (isHttps && cert) {
    if (cert.authorized === false) {
      c.push({ k: 'err', t: 'Certificate problem', m: `The certificate chain did not validate (${cert.authError || 'unknown error'}). Browsers may be showing visitors a warning page.`, rec: null });
    } else if (cert.daysLeft <= 7) {
      c.push({ k: 'err', t: `Certificate expires in ${cert.daysLeft} day${cert.daysLeft === 1 ? '' : 's'}`, m: `Valid until ${cert.validTo}. When it lapses, every visitor gets a full-page security warning. Renew immediately.`, rec: null });
    } else if (cert.daysLeft <= 21) {
      c.push({ k: 'warn', t: `Certificate expires in ${cert.daysLeft} days`, m: `Valid until ${cert.validTo}. Most hosts auto-renew around the 30-day mark; confirm it is on track.`, rec: null });
    } else {
      c.push({ k: 'ok', t: `Certificate valid for ${cert.daysLeft} more days`, m: `Issued by ${cert.issuer || 'an unknown CA'}, valid until ${cert.validTo}.${cert.altNames > 1 ? ` Covers ${cert.altNames} hostnames.` : ''}`, rec: null });
    }
  }

  // HSTS
  const hsts = h['strict-transport-security'];
  if (!isHttps) {
    // skip HSTS grading on http
  } else if (!hsts) {
    c.push({ k: 'warn', t: 'No Strict-Transport-Security', m: 'HSTS tells browsers to never try plain HTTP again, closing the downgrade window on the first visit. Add it with a max-age of at least six months.', rec: null });
  } else {
    const age = Number((hsts.match(/max-age\s*=\s*(\d+)/i) || [])[1] || 0);
    const subs = /includesubdomains/i.test(hsts);
    if (age < 15552000) c.push({ k: 'warn', t: 'HSTS max-age is short', m: `max-age is ${age.toLocaleString()} seconds. Browsers and preload lists want at least six months (15552000), ideally a year.`, rec: hsts });
    else c.push({ k: 'ok', t: `HSTS set${subs ? ' with includeSubDomains' : ''}`, m: 'Browsers will refuse to load this site over plain HTTP.', rec: hsts });
  }

  // CSP
  const csp = h['content-security-policy'];
  if (!csp) {
    c.push({ k: 'warn', t: 'No Content-Security-Policy', m: 'CSP limits what scripts and embeds can run, which is the main defense against injected scripts. It is site-specific, so build it carefully rather than copying one.', rec: null });
  } else {
    const flags = [];
    if (/unsafe-inline/i.test(csp)) flags.push("allows 'unsafe-inline'");
    if (/unsafe-eval/i.test(csp)) flags.push("allows 'unsafe-eval'");
    if (/default-src\s+[^;]*\*/i.test(csp)) flags.push('wildcard default-src');
    if (flags.length) c.push({ k: 'ok', t: 'CSP set (with loose spots)', m: `A policy is in place, though it ${flags.join(', ')}, which weakens it. Common in practice; tighten when you can.`, rec: csp.slice(0, 300) + (csp.length > 300 ? ' …' : '') });
    else c.push({ k: 'ok', t: 'Content-Security-Policy set', m: 'A policy is in place without the usual loose spots.', rec: csp.slice(0, 300) + (csp.length > 300 ? ' …' : '') });
  }

  // Clickjacking
  const xfo = h['x-frame-options'];
  const frameAnc = csp && /frame-ancestors/i.test(csp);
  if (frameAnc) c.push({ k: 'ok', t: 'Clickjacking protected (frame-ancestors)', m: 'The CSP controls who may embed this site in a frame.', rec: null });
  else if (xfo) c.push({ k: 'ok', t: `X-Frame-Options: ${xfo.toUpperCase()}`, m: 'Other sites cannot quietly embed this site in a frame and trick clicks.', rec: null });
  else c.push({ k: 'warn', t: 'No clickjacking protection', m: 'Without X-Frame-Options or CSP frame-ancestors, any site can embed this one in an invisible frame. Add X-Frame-Options: SAMEORIGIN.', rec: null });

  // MIME sniffing
  const xcto = h['x-content-type-options'];
  if (xcto && /nosniff/i.test(xcto)) c.push({ k: 'ok', t: 'X-Content-Type-Options: nosniff', m: 'Browsers will not second-guess file types, which blocks a class of content-confusion attacks.', rec: null });
  else c.push({ k: 'warn', t: 'No X-Content-Type-Options', m: 'Without nosniff, browsers may guess file types and can be tricked into running something as script. One line fixes it.', rec: null });

  // Referrer policy
  const ref = h['referrer-policy'];
  if (ref) c.push({ k: 'ok', t: `Referrer-Policy: ${ref}`, m: 'Outbound links will not leak full URLs from this site.', rec: null });
  else c.push({ k: 'warn', t: 'No Referrer-Policy', m: 'Links to other sites can leak full URLs, including query strings. strict-origin-when-cross-origin is the sensible default.', rec: null });

  // Permissions policy
  const perm = h['permissions-policy'];
  if (perm) c.push({ k: 'ok', t: 'Permissions-Policy set', m: 'Browser features like camera and location are explicitly limited.', rec: perm.slice(0, 200) });
  else c.push({ k: 'info', t: 'No Permissions-Policy (optional)', m: 'Lets you switch off browser features (camera, mic, geolocation) the site never uses. Nice hardening, not critical.', rec: null });

  // Disclosure
  const xpb = h['x-powered-by'];
  if (xpb) c.push({ k: 'warn', t: `X-Powered-By: ${xpb}`, m: 'Advertises the stack to attackers for zero benefit. Remove it.', rec: null });
  const server = h['server'];
  if (server && /\d/.test(server)) c.push({ k: 'info', t: `Server header reveals a version (${server})`, m: 'Version numbers make it easier to match known exploits. Most servers can hide this.', rec: null });

  // Obsolete
  if (h['x-xss-protection']) c.push({ k: 'info', t: 'X-XSS-Protection is obsolete', m: 'Modern browsers ignore it, and historically it created bugs of its own. Safe to remove; CSP replaced it.', rec: null });

  return c;
}

/* ---------- builder ---------- */
const BASELINE = [
  ['Strict-Transport-Security', 'max-age=31536000; includeSubDomains'],
  ['X-Content-Type-Options', 'nosniff'],
  ['X-Frame-Options', 'SAMEORIGIN'],
  ['Referrer-Policy', 'strict-origin-when-cross-origin'],
  ['Permissions-Policy', 'camera=(), microphone=(), geolocation=()'],
];

const FORMATS = {
  toml: {
    file: 'netlify.toml',
    gen: () => `[[headers]]\n  for = "/*"\n  [headers.values]\n${BASELINE.map(([k, v]) => `    ${k} = "${v}"`).join('\n')}`,
  },
  headers: {
    file: '_headers',
    gen: () => `/*\n${BASELINE.map(([k, v]) => `  ${k}: ${v}`).join('\n')}`,
  },
  apache: {
    file: '.htaccess',
    gen: () => BASELINE.map(([k, v]) => `Header always set ${k} "${v}"`).join('\n'),
  },
  nginx: {
    file: 'security-headers.conf',
    gen: () => BASELINE.map(([k, v]) => `add_header ${k} "${v}" always;`).join('\n'),
  },
  vercel: {
    file: 'vercel.json',
    gen: () => JSON.stringify({ headers: [{ source: '/(.*)', headers: BASELINE.map(([k, v]) => ({ key: k, value: v })) }] }, null, 2),
  },
};

const state = { format: 'toml' };

function renderBuilder() {
  $('#code').textContent = FORMATS[state.format].gen();
}

/* ---------- render ---------- */
const ICON = {
  err: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6M9 9l6 6"/></svg>',
  warn: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.8 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.8a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 17h.01"/></svg>',
  ok: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>',
  info: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>',
};

function checkCard(c) {
  const rec = c.rec ? `<pre class="rec"><code>${esc(c.rec)}</code></pre>` : '';
  return `<div class="check check--${c.k}">
    <span class="check-ic">${ICON[c.k]}</span>
    <div class="check-body">
      <div class="check-t">${esc(c.t)}</div>
      <div class="check-m">${esc(c.m)}</div>
      ${rec}
    </div>
  </div>`;
}

function note(kind, msg) {
  return `<div class="t-note t-note--${kind}">${esc(msg)}</div>`;
}

function summaryHtml(domain, all) {
  const n = { err: 0, warn: 0, ok: 0, info: 0 };
  all.forEach((c) => { n[c.k]++; });
  let verdict;
  if (n.err) verdict = `${domain} has ${n.err} serious issue${n.err > 1 ? 's' : ''}.`;
  else if (n.warn) verdict = `${domain} is missing ${n.warn} header${n.warn > 1 ? 's' : ''} worth adding.`;
  else verdict = `${domain} sends a solid set of security headers. Nice.`;
  return `<div class="t-head">
    <div class="t-summary">${esc(verdict)}</div>
    <div class="insp-pills">
      <span class="pill pill--err">${n.err}</span>
      <span class="pill pill--warn">${n.warn}</span>
      <span class="pill pill--ok">${n.ok}</span>
    </div>
  </div>`;
}

function setLoading(target) {
  $('#results').innerHTML = `<div class="t-loading"><span class="spin" aria-hidden="true"></span> Reading response headers from ${esc(target)}&hellip;</div>`;
}

/* ---------- run ---------- */
async function run() {
  const raw = $('#f-url').value.trim();
  if (!raw) { $('#f-url').focus(); return; }
  const btn = $('#check-btn');
  btn.disabled = true;
  setLoading(raw);
  try {
    const res = await fetch('/.netlify/functions/headers-fetch?url=' + encodeURIComponent(raw), { headers: { accept: 'application/json' } });
    const d = await res.json();
    if (d.error) { $('#results').innerHTML = note('err', d.error); return; }
    const domain = (() => { try { return new URL(d.url).hostname.replace(/^www\./, ''); } catch { return raw; } })();
    const checks = buildChecks(d.url, d.headers || {}, d.cert || null);
    $('#results').innerHTML = summaryHtml(domain, checks) + `<div class="dsec"><div class="dsec-h">Headers on ${esc(d.url)}</div>${checks.map(checkCard).join('')}</div>`;
  } catch (e) {
    $('#results').innerHTML = note('err', 'Could not reach the scanner. If you are running locally without Netlify, the scan function is unavailable.');
  } finally {
    btn.disabled = false;
  }
}

/* ---------- copy / download ---------- */
function flash(btn, label) {
  const prev = btn.textContent;
  btn.textContent = label;
  btn.classList.add('btn--done');
  setTimeout(() => { btn.textContent = prev; btn.classList.remove('btn--done'); }, 1100);
}
function fallbackCopy(text, done) {
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); } catch (e) { /* storage may be unavailable; safe to ignore */ }
  document.body.removeChild(ta); done();
}

function initHeaders() {
  initTheme();
  renderBuilder();

  $('#check-form').addEventListener('submit', (e) => { e.preventDefault(); run(); });
  $$('.ex').forEach((b) => b.addEventListener('click', () => { $('#f-url').value = b.dataset.ex; run(); }));

  $$('[data-format]').forEach((b) => b.addEventListener('click', () => {
    state.format = b.dataset.format;
    $$('[data-format]').forEach((x) => x.classList.toggle('is-active', x === b));
    renderBuilder();
  }));

  $('#copy-btn').addEventListener('click', (e) => {
    const btn = e.currentTarget;
    const text = $('#code').textContent;
    const done = () => flash(btn, 'Copied');
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
    else fallbackCopy(text, done);
  });
  $('#dl-btn').addEventListener('click', (e) => {
    const btn = e.currentTarget;
    const text = $('#code').textContent;
    const blob = new Blob([text + '\n'], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = FORMATS[state.format].file;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
    flash(btn, 'Saved');
  });
}

export { initHeaders };
