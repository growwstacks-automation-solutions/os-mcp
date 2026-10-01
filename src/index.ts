// src/index.ts — Cloudflare Worker entry point.
//
// Stateless: no session, no storage. Every request is authenticated with a
// single shared bearer token, then handed to the MCP handler, which dispatches
// to the tools in tools.ts. Those talk to Neon as `app_user` with the identity
// GUC set, so Postgres RLS authorizes everything.

import { createMcpHandler } from 'mcp-handler';

import type { Env } from './db';
import { registerTools } from './tools';
import { MAX_FILE_BYTES, storeAttachment, validateContent, verifyUpload } from './uploads';

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

/**
 * PUT /upload/<token> — receive the raw bytes, check them, store them.
 * Nothing is written unless EVERY check passes, so there is no such thing as a
 * half-uploaded attachment: it is stored whole and verified, or not at all.
 */
async function handleUpload(req: Request, env: Env, token: string): Promise<Response> {
  const fail = (status: number, error: string) => Response.json({ ok: false, error }, { status });
  if (req.method !== 'PUT' && req.method !== 'POST') return fail(405, 'Use PUT with the raw file as the body.');

  let claims;
  try {
    claims = await verifyUpload(env, decodeURIComponent(token));
  } catch (e) {
    return fail(401, e instanceof Error ? e.message : 'Invalid upload token.');
  }

  // Refuse oversize BEFORE reading the body where the client says how big it is.
  const declared = Number(req.headers.get('content-length') ?? '0');
  if (declared > MAX_FILE_BYTES) return fail(413, `File is larger than the ${MAX_FILE_BYTES} byte limit.`);

  const bytes = new Uint8Array(await req.arrayBuffer());
  if (bytes.length === 0) return fail(400, 'The request body is empty (0 bytes). Send the file with --data-binary @file.');
  if (bytes.length > MAX_FILE_BYTES) return fail(413, `File is larger than the ${MAX_FILE_BYTES} byte limit.`);
  if (bytes.length !== claims.size) {
    return fail(400, `Size mismatch: start_attachment_upload declared ${claims.size} bytes but ${bytes.length} arrived. Nothing was stored.`);
  }
  const bad = validateContent(bytes, claims.mime);
  if (bad) return fail(422, `${bad} Nothing was stored.`);

  try {
    await storeAttachment(env, {
      id: claims.a,
      parentType: claims.pt,
      parentId: claims.pid,
      title: claims.title,
      mime: claims.mime,
      purpose: claims.purpose,
      bytes,
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    // The attachment id is the primary key, so a replayed URL lands here.
    if (/duplicate key|already exists|23505/i.test(msg)) {
      return fail(409, 'This upload link was already used. Call start_attachment_upload for a new one.');
    }
    return fail(500, msg.replace(/postgres(?:ql)?:\/\/[^\s"']*/gi, '[redacted]'));
  }
  return Response.json({
    ok: true,
    attachment_id: claims.a,
    size_bytes: bytes.length,
    next: 'Call finalize_attachment_upload with this attachment_id to confirm.',
  });
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

    // Raw file upload. Authenticated by the signed, expiring, single-use token in
    // the path (issued by start_attachment_upload), NOT the bearer token — the
    // caller is a sandbox that only holds this URL, never the MCP secret.
    const upload = url.pathname.match(/^\/upload\/([^/]+)$/);
    if (upload) return handleUpload(req, env, upload[1]);

    // Accept `Authorization: Bearer <token>` or `x-api-key: <token>`.
    const bearer = (req.headers.get('authorization') ?? '').replace(/^Bearer\s+/i, '');
    const provided = bearer || req.headers.get('x-api-key') || '';
    if (!tokensMatch(provided, env.MCP_AUTH_TOKEN)) return unauthorized();

    // The handler is built per request because Workers only expose `env` here.
    const handler = createMcpHandler(
      (server) => registerTools(server as never, env, url.origin),
      {},
      { basePath: '' },
    );

    return handler(req);
  },
};
