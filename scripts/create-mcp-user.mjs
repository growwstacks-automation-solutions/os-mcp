// scripts/create-mcp-user.mjs — one-off: create the U-SYS-MCP attribution user.
//
// Run ONCE. Creates a dedicated admin account that the MCP acts as, so records
// it writes are audited to "MCP (System)" instead of "Slack Sync (System)"
// (the SYSTEM user from migration 0023, which the MCP otherwise borrows).
//
// This is a plain data INSERT — not a migration, and it does not touch the OS
// app repo. Idempotent: ON CONFLICT DO NOTHING.
//
//   node scripts/create-mcp-user.mjs
//
// Reads DATABASE_URL from .dev.vars. Runs as app_user, so RLS still authorizes
// the insert — the acting identity is the existing SYSTEM admin.

import { readFileSync } from 'node:fs';
import { neon } from '@neondatabase/serverless';

const MCP_USER_ID = '00000000-0000-0000-0000-0000000000fe';
const SYSTEM_USER_ID = '00000000-0000-0000-0000-0000000000ff';

function loadEnv() {
  const text = readFileSync(new URL('../.dev.vars', import.meta.url), 'utf8');
  const out = {};
  for (const line of text.split('\n')) {
    const m = line.match(/^\s*([A-Z_]+)\s*=\s*(.*)\s*$/);
    if (m) out[m[1]] = m[2].trim();
  }
  return out;
}

const env = loadEnv();
if (!env.DATABASE_URL) {
  console.error('DATABASE_URL missing from .dev.vars');
  process.exit(1);
}

const sql = neon(env.DATABASE_URL);

const res = await sql.transaction([
  sql`select set_config('app.current_user_id', ${SYSTEM_USER_ID}, true)`,
  sql`
    INSERT INTO users (id, display_id, full_name, email, role, status, created_at, updated_at)
    VALUES (
      ${MCP_USER_ID},
      'U-SYS-MCP',
      'MCP (System)',
      'system+mcp@growwstacks.com',
      'admin',
      'active',
      now(),
      now()
    )
    ON CONFLICT (id) DO NOTHING
  `,
  sql`SELECT id, display_id, full_name, email, role::text AS role, status::text AS status
      FROM users WHERE id = ${MCP_USER_ID}::uuid`,
]);

const row = res[2]?.[0];
if (!row) {
  console.error('Insert did not take effect — RLS likely refused it. Check the users_insert policy.');
  process.exit(1);
}

console.log('MCP attribution user ready:');
console.log(row);
console.log('\nNow set this in .dev.vars (and as a Worker secret for production):');
console.log(`GS_ACTOR_UID=${MCP_USER_ID}`);
