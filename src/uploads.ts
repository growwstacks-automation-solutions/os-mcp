// src/uploads.ts — file-attachment helpers shared by the MCP tools and the raw
// upload endpoint.
//
// WHY THIS EXISTS: an MCP tool call is text typed by the model. A 470 KB image
// is ~630,000 base64 characters, which a model cannot reproduce faithfully (it
// truncates, or sends a shell command in place of the data). So large files go
// by a different route: the tool hands back a short-lived signed URL, and the
// caller's own sandbox PUTs the raw bytes to it. Everything here exists so that
// whichever route is used, a cut-off, empty or mislabelled file is REFUSED
// instead of being stored as a "successful" attachment.

import { asUser, asUserMany, actorUid, type Env } from './db';

/** Largest file accepted. Raise deliberately: the OS app serves these from Postgres. */
export const MAX_FILE_BYTES = 5 * 1024 * 1024;

/** Largest file the old inline-base64 route accepts. Beyond this, use the upload URL. */
export const MAX_INLINE_BYTES = 256 * 1024;

/** How long an upload URL stays valid. */
const UPLOAD_TTL_SECONDS = 15 * 60;

/** Types we can verify byte-for-byte. Anything else is refused on the upload route. */
export const ALLOWED_MIME = [
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'application/pdf',
] as const;

// ---------------------------------------------------------------------------
// Content validation
// ---------------------------------------------------------------------------

const startsWith = (b: Uint8Array, sig: number[]) => sig.every((v, i) => b[i] === v);
const ascii = (b: Uint8Array, from: number, to: number) =>
  String.fromCharCode(...b.subarray(from, to));

/**
 * Check the bytes really are a COMPLETE file of the declared type. Returns an
 * error message, or null when fine. Each type is checked at both ends: a
 * truncated upload keeps a valid header but loses its trailer, which is exactly
 * how the 141-byte "PNG" on T-6192 looked.
 */
export function validateContent(bytes: Uint8Array, mime: string): string | null {
  if (bytes.length === 0) return 'The file is empty (0 bytes).';
  switch (mime) {
    case 'image/png': {
      if (!startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) {
        return 'Not a PNG: the file does not start with the PNG signature.';
      }
      const n = bytes.length;
      if (n < 45 || ascii(bytes, n - 8, n - 4) !== 'IEND') {
        return 'The PNG is incomplete (it does not end with an IEND chunk) — the upload was cut off.';
      }
      return null;
    }
    case 'image/jpeg': {
      if (!startsWith(bytes, [0xff, 0xd8, 0xff])) return 'Not a JPEG: bad start marker.';
      // Allow trailing zero padding some encoders add after the EOI marker.
      let end = bytes.length;
      while (end > 2 && bytes[end - 1] === 0) end -= 1;
      if (bytes[end - 2] !== 0xff || bytes[end - 1] !== 0xd9) {
        return 'The JPEG is incomplete (no end-of-image marker) — the upload was cut off.';
      }
      return null;
    }
    case 'image/gif': {
      const head = ascii(bytes, 0, 6);
      if (head !== 'GIF87a' && head !== 'GIF89a') return 'Not a GIF: bad header.';
      if (bytes[bytes.length - 1] !== 0x3b) {
        return 'The GIF is incomplete (no trailer byte) — the upload was cut off.';
      }
      return null;
    }
    case 'image/webp': {
      if (bytes.length < 12 || ascii(bytes, 0, 4) !== 'RIFF' || ascii(bytes, 8, 12) !== 'WEBP') {
        return 'Not a WebP: bad RIFF header.';
      }
      const declared = new DataView(bytes.buffer, bytes.byteOffset).getUint32(4, true) + 8;
      if (declared !== bytes.length) {
        return `The WebP is incomplete: its header says ${declared} bytes but ${bytes.length} arrived.`;
      }
      return null;
    }
    case 'application/pdf': {
      if (ascii(bytes, 0, 5) !== '%PDF-') return 'Not a PDF: missing %PDF- header.';
      const tail = ascii(bytes, Math.max(0, bytes.length - 1024), bytes.length);
      if (!tail.includes('%%EOF')) {
        return 'The PDF is incomplete (no %%EOF marker) — the upload was cut off.';
      }
      return null;
    }
    default:
      return `Unsupported file type "${mime}". Allowed: ${ALLOWED_MIME.join(', ')}.`;
  }
}

/** Decode base64 STRICTLY. A shell command or truncated paste is not valid base64. */
export function decodeBase64Strict(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, '');
  if (clean.length === 0) throw new Error('file_base64 is empty.');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 !== 0) {
    throw new Error(
      'file_base64 is not valid base64 (it may be a shell command, a placeholder, or cut off). '
      + 'Do NOT type file contents yourself; use start_attachment_upload instead, or attach a link.',
    );
  }
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

export function toBase64(bytes: Uint8Array): string {
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

// ---------------------------------------------------------------------------
// Signed upload URLs (stateless: HMAC over the claims, keyed by MCP_AUTH_TOKEN)
// ---------------------------------------------------------------------------

export type UploadClaims = {
  /** attachment id — also makes the URL single-use (primary-key conflict on reuse) */
  a: string;
  pt: string;
  pid: string;
  title: string;
  mime: string;
  size: number;
  purpose: string | null;
  exp: number;
};

const enc = new TextEncoder();

const b64url = (bytes: Uint8Array) =>
  toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const fromB64url = (s: string) =>
  decodeBase64Strict(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));

async function hmac(env: Env, message: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(`os-mcp-upload:${env.MCP_AUTH_TOKEN}`),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(message)));
}

export async function signUpload(env: Env, claims: UploadClaims): Promise<string> {
  const payload = b64url(enc.encode(JSON.stringify(claims)));
  return `${payload}.${b64url(await hmac(env, payload))}`;
}

export async function verifyUpload(env: Env, token: string): Promise<UploadClaims> {
  const [payload, sig] = token.split('.');
  if (!payload || !sig) throw new Error('Malformed upload token.');
  const expected = b64url(await hmac(env, payload));
  if (expected.length !== sig.length) throw new Error('Invalid upload token.');
  let diff = 0;
  for (let i = 0; i < sig.length; i += 1) diff |= sig.charCodeAt(i) ^ expected.charCodeAt(i);
  if (diff !== 0) throw new Error('Invalid upload token.');
  const claims = JSON.parse(new TextDecoder().decode(fromB64url(payload))) as UploadClaims;
  if (!claims.exp || Date.now() / 1000 > claims.exp) {
    throw new Error('This upload link has expired. Call start_attachment_upload again.');
  }
  return claims;
}

export async function newUploadClaims(
  input: Omit<UploadClaims, 'a' | 'exp'>,
): Promise<UploadClaims> {
  return {
    ...input,
    a: crypto.randomUUID(),
    exp: Math.floor(Date.now() / 1000) + UPLOAD_TTL_SECONDS,
  };
}

// ---------------------------------------------------------------------------
// Storage — one row in attachments + one in attachment_blobs, same shape the OS
// app writes (url = /api/attachments/<id>) so the file opens in the app.
// ---------------------------------------------------------------------------

export async function storeAttachment(
  env: Env,
  p: {
    id: string;
    parentType: string;
    parentId: string;
    title: string;
    mime: string;
    purpose: string | null;
    bytes: Uint8Array;
  },
): Promise<void> {
  const b64 = toBase64(p.bytes);
  // TWO statements, one transaction: the blob's INSERT policy does
  // EXISTS (SELECT 1 FROM attachments …), which cannot see a row inserted by the
  // SAME statement. The final SELECT proves RLS let the whole thing through.
  const rows = await asUserMany(env, (sql) => [
    sql`
      INSERT INTO attachments (
        id, parent_type, parent_id, kind, title, url, mime_type, size_bytes, purpose, uploaded_by
      )
      VALUES (
        ${p.id}::uuid, ${p.parentType}::entity_type, ${p.parentId}::uuid, 'file'::attachment_kind,
        ${p.title}, ${`/api/attachments/${p.id}`}, ${p.mime}, ${p.bytes.length},
        ${p.purpose}, ${actorUid(env)}::uuid
      )
    `,
    sql`
      INSERT INTO attachment_blobs (attachment_id, data_base64)
      VALUES (${p.id}::uuid, ${b64})
    `,
    sql`SELECT id FROM attachments WHERE id = ${p.id}::uuid`,
  ]);
  if (rows.length === 0) {
    throw new Error('Not permitted to attach to that record, or the record does not exist.');
  }
}

/**
 * Read an attachment back and prove it is whole: the stored bytes decode, match
 * size_bytes, and pass the same content check. Used by finalize_attachment_upload.
 */
export async function verifyStored(env: Env, id: string) {
  const rows = await asUser<{
    id: string; title: string; mime_type: string | null; size_bytes: string | null;
    parent_type: string; parent_id: string; url: string; data_base64: string | null;
  }>(env, (sql) => sql`
    SELECT a.id, a.title, a.mime_type, a.size_bytes, a.parent_type::text AS parent_type,
           a.parent_id, a.url, b.data_base64
    FROM attachments a
    LEFT JOIN attachment_blobs b ON b.attachment_id = a.id
    WHERE a.id = ${id}::uuid AND a.archived_at IS NULL
  `);
  const r = rows[0];
  if (!r) return { ok: false as const, reason: 'No such attachment yet — the file has not been uploaded.' };
  if (!r.data_base64) return { ok: false as const, reason: 'The attachment has no stored file contents.' };
  const bytes = decodeBase64Strict(r.data_base64);
  if (Number(r.size_bytes) !== bytes.length) {
    return { ok: false as const, reason: `Stored size ${bytes.length} does not match recorded size ${r.size_bytes}.` };
  }
  const bad = validateContent(bytes, r.mime_type ?? '');
  if (bad) return { ok: false as const, reason: bad };
  return {
    ok: true as const,
    id: r.id,
    title: r.title,
    mime_type: r.mime_type,
    size_bytes: bytes.length,
    parent_type: r.parent_type,
    parent_id: r.parent_id,
    url: r.url,
  };
}
