// src/db.ts — the ONLY file that touches Postgres.
//
// GrowwStacks OS enforces every permission inside the database via Row-Level
// Security. RLS reads the acting user from a per-transaction GUC, so each call
// must set `app.current_user_id` and run the real query IN THE SAME transaction.
// That is exactly what the OS app's lib/db.ts does; we mirror it.
//
// 🚨 DATABASE_URL MUST be the non-owner `app_user` role. No table in the OS
//    schema sets FORCE ROW LEVEL SECURITY, so a Neon OWNER connection bypasses
//    all 55 policies and the GUC below becomes decorative.

import {
  neon,
  type NeonQueryFunction,
  type NeonQueryPromise,
} from '@neondatabase/serverless';

export type Env = {
  DATABASE_URL: string;
  MCP_AUTH_TOKEN: string;
  GS_ACTOR_UID?: string;
};

/** The OS SYSTEM user (migrations/0023): role=admin, status=active, not archived. */
const DEFAULT_ACTOR_UID = '00000000-0000-0000-0000-0000000000ff';

// Both pinned to <false, false> (the client's default options), because
// sql.transaction() clamps its array argument to exactly those generics.
// NOT `ReturnType<SqlClient>` — that instantiates the call signature's own
// generics to their constraint (`boolean`), which then fails to assign.
type SqlClient = NeonQueryFunction<false, false>;
type NeonQuery = NeonQueryPromise<false, false>;

export function actorUid(env: Env): string {
  return env.GS_ACTOR_UID?.trim() || DEFAULT_ACTOR_UID;
}

/**
 * asUser — set the identity GUC and run ONE statement in the same transaction.
 * The Neon HTTP driver is stateless (each call is its own request), so batching
 * via sql.transaction is what keeps the GUC scoped and un-leakable.
 */
export async function asUser<T = Record<string, unknown>>(
  env: Env,
  build: (sql: SqlClient) => NeonQuery,
): Promise<T[]> {
  const sql: SqlClient = neon(env.DATABASE_URL);
  const res = await sql.transaction([
    sql`select set_config('app.current_user_id', ${actorUid(env)}, true)`,
    build(sql),
  ]);
  return res[1] as T[];
}

/**
 * asUserWithReason — like asUser, but ALSO sets the `app.audit_reason` GUC so the
 * fn_audit trigger records WHY on the same audit_log row. Required for every
 * archive ("delete") — the OS never hard-deletes and always demands a reason.
 * Transaction-scoped, so it cannot leak into another request's audit rows.
 */
export async function asUserWithReason<T = Record<string, unknown>>(
  env: Env,
  reason: string,
  build: (sql: SqlClient) => NeonQuery,
): Promise<T[]> {
  const sql: SqlClient = neon(env.DATABASE_URL);
  const res = await sql.transaction([
    sql`select set_config('app.current_user_id', ${actorUid(env)}, true)`,
    sql`select set_config('app.audit_reason', ${reason}, true)`,
    build(sql),
  ]);
  return res[2] as T[];
}

/**
 * asUserMany — several statements in ONE transaction; returns the LAST one's rows.
 *
 * Needed wherever a later statement's RLS policy must SEE a row written by an
 * earlier one — notably tasks, whose SELECT policy (fn_can_see) is
 * self-referential, so INSERT … RETURNING fails even for an admin. Insert, then
 * SELECT back as a separate statement.
 */
export async function asUserMany<T = Record<string, unknown>>(
  env: Env,
  build: (sql: SqlClient) => NeonQuery[],
): Promise<T[]> {
  const sql: SqlClient = neon(env.DATABASE_URL);
  const queries = build(sql);
  const res = await sql.transaction([
    sql`select set_config('app.current_user_id', ${actorUid(env)}, true)`,
    ...queries,
  ]);
  return res[res.length - 1] as T[];
}
