// workers-api/worker.js
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    // Strictly no HTML here. Everything returns JSON or text.
    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type,Authorization',
          'Vary': 'Origin',
        },
      });
    }

    // PROBE 1: /api/__who
    if (method === 'GET' && path === '/api/__who') {
      return new Response(
        `api-worker env=${env.ENV_NAME || 'unknown'} ts=${new Date().toISOString()}`,
        { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } }
      );
    }

    // PROBE 2: /api/config (return the same shape frontend expects)
    if (method === 'GET' && path === '/api/config') {
      const enabled = String(env.TURNSTILE_ENABLED || '').toLowerCase() === 'true';
      const siteKey = env.TURNSTILE_SITE_KEY || '';
      return new Response(JSON.stringify({ turnstile: { enabled, siteKey } }), {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'cache-control': 'no-store, no-cache, must-revalidate',
        },
      });
    }

    return new Response(JSON.stringify({ success: false, error: 'Not found' }), {
      status: 404,
      headers: { 'content-type': 'application/json' },
    });
  }
};