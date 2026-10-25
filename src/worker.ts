interface Env {
  ASSETS: { fetch(request: Request): Promise<Response> }
}

const jsonHeaders = {
  'content-type': 'application/json; charset=utf-8',
  'x-content-type-options': 'nosniff',
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)
    const match = url.pathname.match(/^\/api\/ubuntu\/cves\/(CVE-\d{4}-\d{4,7})\.json$/i)

    if (match) {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
          status: 405,
          headers: { ...jsonHeaders, allow: 'GET, HEAD' },
        })
      }

      try {
        const cveId = match[1].toUpperCase()
        const upstream = await fetch(`https://ubuntu.com/security/cves/${cveId}.json`, {
          headers: { accept: 'application/json' },
        })
        return new Response(upstream.body, {
          status: upstream.status,
          headers: {
            ...jsonHeaders,
            'cache-control': upstream.ok ? 'public, max-age=300' : 'no-store',
          },
        })
      } catch {
        return new Response(JSON.stringify({ error: 'Ubuntu Security is temporarily unavailable' }), {
          status: 502,
          headers: { ...jsonHeaders, 'cache-control': 'no-store' },
        })
      }
    }

    return env.ASSETS.fetch(request)
  },
}
