/**
 * Production proxy for the MITRE CWE API.
 *
 * WHY THIS FILE EXISTS:
 * `vite.config.js` defines a `server.proxy` rule for `/api/mitre` - but that
 * proxy only runs inside the Vite *dev server*. It does not exist in the
 * production build (`vite build`) or on static hosting; there is no Node
 * process there to proxy through. Without this file, every `/api/mitre/...`
 * request in production would 404, and a direct browser fetch to
 * `https://cwe-api.mitre.org` will very likely be blocked by CORS - so live
 * lookups would silently fall back to the synthesized placeholder for any
 * CWE not already in the local cache.
 *
 * This file fills that gap as a Vercel serverless function (Vercel
 * auto-detects any file under /api as a function - no extra config needed).
 * It mirrors the dev proxy's behavior 1:1: `/api/mitre/api/v1/cwe/weakness/89`
 * -> `https://cwe-api.mitre.org/api/v1/cwe/weakness/89`.
 *
 * Deploying elsewhere (Netlify, Cloudflare Pages, a plain Node server, etc.)?
 * Port this same forwarding logic to that platform's function format - the
 * client code in src/services/cweService.js does not need to change either
 * way, since it always calls the same-origin `/api/mitre/...` path first.
 */

const MITRE_API_BASE = 'https://cwe-api.mitre.org';

export default async function handler(req, res) {
  const segments = Array.isArray(req.query.path) ? req.query.path : [req.query.path].filter(Boolean);
  const upstreamPath = segments.map(encodeURIComponent).join('/');

  const queryString = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  const upstreamUrl = `${MITRE_API_BASE}/${upstreamPath}${queryString}`;

  try {
    const upstreamResponse = await fetch(upstreamUrl, {
      method: 'GET',
      headers: { Accept: 'application/json' }
    });

    const body = await upstreamResponse.text();

    res.status(upstreamResponse.status);
    res.setHeader('Content-Type', upstreamResponse.headers.get('content-type') || 'application/json');
    // Short edge cache: CWE specifications change on MITRE's own release cadence, not per-request.
    res.setHeader('Cache-Control', 'public, max-age=300, s-maxage=3600, stale-while-revalidate=86400');
    res.send(body);
  } catch (err) {
    res.status(502).json({
      error: 'MITRE_PROXY_UNREACHABLE',
      message: 'The MITRE CWE API could not be reached from the production proxy.',
      detail: err instanceof Error ? err.message : String(err)
    });
  }
}
