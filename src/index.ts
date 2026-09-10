// src/index.ts — Cloudflare Worker entry point.
//
// Stateless: no session, no storage. Every request is authenticated with a
// single shared bearer token, then handed to the MCP handler, which dispatches
// to the tools in tools.ts. Those talk to Neon as `app_user` with the identity
// GUC set, so Postgres RLS authorizes everything.

import { createMcpHandler } from 'mcp-handler';

import type { Env } from './db';
import { registerTools } from './tools';

/** Constant-time string compare so the token can't be guessed by timing. */
function tokensMatch(provided: string, expected: string): boolean {
  if (provided.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < provided.length; i += 1) {
    diff |= provided.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return diff === 0;
}

function unauthorized(): Response {
  return Response.json(
    { ok: false, error: 'unauthorized' },
    { status: 401, headers: { 'WWW-Authenticate': 'Bearer' } },
  );
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    // Unauthenticated liveness probe — reveals nothing.
    if (url.pathname === '/health') {
      return Response.json({ ok: true, service: 'os-mcp' });
    }

    // Fail CLOSED when the token isn't provisioned, so a mis-deployed Worker
    // rejects rather than opens.
    if (!env.MCP_AUTH_TOKEN) return unauthorized();
    if (!env.DATABASE_URL) {
      return Response.json(
        { ok: false, error: 'DATABASE_URL is not configured' },
        { status: 500 },
      );
    }

    // Accept `Authorization: Bearer <token>` or `x-api-key: <token>`.
    const bearer = (req.headers.get('authorization') ?? '').replace(/^Bearer\s+/i, '');
    const provided = bearer || req.headers.get('x-api-key') || '';
    if (!tokensMatch(provided, env.MCP_AUTH_TOKEN)) return unauthorized();

    // The handler is built per request because Workers only expose `env` here.
    const handler = createMcpHandler(
      (server) => registerTools(server as never, env),
      {},
      { basePath: '' },
    );

    return handler(req);
  },
};
