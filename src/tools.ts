// src/tools.ts — the MCP tool surface.
//
// Each tool reproduces the logic of the matching GrowwStacks OS server action
// (lib/actions/*.ts), because we talk to Neon directly instead of calling the
// app. Every statement is a Neon tagged template (parameterised) and every call
// goes through asUser/asUserMany so RLS authorizes it.
//
// Conventions taken from the OS schema — do NOT change:
//   * display_id is trigger-assigned — never set it.
//   * Spine caches (contact_id/company_id/project_id/milestone_id) are
//     trigger-maintained — never set them.
//   * "Delete" means archive-with-reason; no tool here deletes anything.

import { z } from 'zod';
import { asUser, asUserMany, asUserWithReason, actorUid, type Env } from './db';

// The MCP server object handed to us by createMcpHandler.
type ToolServer = {
  tool: (
    name: string,
    description: string,
    schema: Record<string, z.ZodTypeAny>,
    handler: (args: any) => Promise<unknown>,
  ) => void;
};

const ok = (data: unknown) => ({
  content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }],
});

const fail = (message: string) => ({
  content: [{ type: 'text' as const, text: `ERROR: ${message}` }],
  isError: true,
});

/**
 * redact — strip anything credential-shaped out of an error before it leaves the
 * Worker. The Neon driver puts the FULL connection string, password included,
 * into its "not a valid URL" message; returning that verbatim would hand the
 * database password to any caller. Belt and braces: also mask a bare
 * user:pass@host and any postgres URL wherever it appears.
 */
function redact(msg: string): string {
  return msg
    .replace(/postgres(?:ql)?:\/\/[^\s"']*/gi, '[connection string redacted]')
    .replace(/\/\/[^/\s:@]+:[^/\s@]+@/g, '//[credentials redacted]@');
}

/** Wrap a handler so a thrown DB/RLS error becomes a readable, safe tool error. */
function guard<T>(fn: (args: T) => Promise<unknown>) {
  return async (args: T) => {
    try {
      return ok(await fn(args));
    } catch (e) {
      const msg = redact(e instanceof Error ? e.message : String(e));
      if (/violates row-level security|42501/i.test(msg)) {
        return fail(`Refused by the database (RLS): ${msg}`);
      }
      return fail(msg);
    }
  };
}

// Small, stable enums worth pinning in the schema so the model must pick a real
// value (and the options show up in the tool definition). The larger, more
// volatile ones — task/project/payment status, deal stages — stay as strings
// backed by get_statuses, which reads them live from the database.
const CONTACT_STATUS = z.enum([
  'prospect',
  'active_client',
  'partner',
  'on_hold',
  'churned',
]);

const MILESTONE_STATUS = z.enum([
  'not_started',
  'in_progress',
  'in_review',
  'client_pending',
  'on_hold',
  'done',
]);

const PRIORITY = z.enum(['low', 'medium', 'high']);

// ---------------------------------------------------------------------------
// PERMITTED TASK CREATORS
//
// Only these people may be recorded as created_by. Enforced as a z.enum rather
// than a describe() note for two reasons:
//   1. The server REJECTS anything else, so a wrong creator cannot be written
//      whatever the model decides to send.
//   2. The JSON Schema then advertises exactly these ids, so the model sees a
//      closed two-way choice instead of a free uuid field it can fill from
//      whatever name happens to be lying around in its context.
//
// To add someone: add a line here and redeploy. Kept deliberately small - this
// is an attribution allowlist, not a permission system (RLS still does that).
// ---------------------------------------------------------------------------
const TASK_CREATORS: Record<string, string> = {
  'Faizal Khan': '00b5232b-2f84-4b7e-ae98-26ccf683e7c5',
  'Manish Mandot': '4e0d5b3b-fe89-485b-be6a-5909cf272d5c',
};

const CREATOR_IDS = Object.values(TASK_CREATORS) as [string, ...string[]];

/** "Faizal Khan = <id>; Manish Mandot = <id>" - inlined into the description. */
const CREATOR_HINT = Object.entries(TASK_CREATORS)
  .map(([name, id]) => `${name} = ${id}`)
  .join('; ');

// ---------------------------------------------------------------------------
// ASK-OR-SKIP
//
// The rule from the team: never assume a value, always ask — but let the user
// say "skip" and take a documented default.
//
// An OPTIONAL field lets the model quietly omit it, which is exactly the silent
// defaulting we're trying to stop. So these fields are REQUIRED but accept the
// literal "skip". The model must therefore make a conscious choice on every one:
// a real value it got from the user, or an explicit skip. It can never just
// leave the field out.
// ---------------------------------------------------------------------------
const SKIP = 'skip' as const;

/** Wrap a schema so it also accepts "skip", and say what skipping does. */
function askOrSkip<T extends z.ZodTypeAny>(inner: T, ifSkipped: string) {
  return z
    .union([inner, z.literal(SKIP)])
    .describe(
      `REQUIRED — ask the user. If they don't want to give one, pass "skip" (${ifSkipped}). Never invent a value.`,
    );
}

/** Unwrap an ask-or-skip value: "skip" (or absent) becomes null. */
function val<T>(v: T | typeof SKIP | undefined): T | null {
  return v === undefined || v === SKIP ? null : v;
}

/** Unwrap an ask-or-skip array: "skip" (or absent) becomes []. */
function arrVal(v: string[] | typeof SKIP | undefined): string[] {
  return v === undefined || v === SKIP ? [] : v;
}

/**
 * coerceArray — rescue an array argument that arrived as a STRING.
 *
 * Several MCP clients serialise array arguments as JSON text ("[\"uuid\"]"), or
 * send a single bare value, instead of a real JSON array. Zod then rejects it,
 * and for an ask-or-skip union the failure reads "expected array, received
 * string" AND "expected 'skip'" at once — the misleading dual error that made
 * create_task's assignee_ids / manager_ids unusable from a connector.
 *
 * This only WIDENS what parses. A real array is returned untouched and the
 * "skip" sentinel is passed straight through so the union's literal branch
 * still matches, so no input that works today behaves differently; inputs that
 * previously errored now succeed.
 */
function coerceArray(v: unknown): unknown {
  if (Array.isArray(v) || typeof v !== 'string') return v;
  const s = v.trim();
  // Empty and the sentinel are left alone for the union branches to handle.
  if (s === '' || s === SKIP) return v;
  if (s.startsWith('[')) {
    try {
      const parsed = JSON.parse(s);
      if (Array.isArray(parsed)) return parsed;
    } catch {
      // Malformed JSON — fall through and treat it as a delimited list.
    }
  }
  return s
    .split(',')
    .map((part) => part.trim().replace(/^["'[\s]+|["'\]\s]+$/g, '').trim())
    .filter((part) => part.length > 0);
}

/**
 * askOrSkipArray — askOrSkip for an ARRAY field. Identical contract and identical
 * advertised JSON Schema; it just tolerates a stringified array on the way in.
 */
function askOrSkipArray<T extends z.ZodTypeAny>(inner: T, ifSkipped: string) {
  return z
    .preprocess(coerceArray, z.union([inner, z.literal(SKIP)]))
    .describe(
      `REQUIRED — ask the user. If they don't want to give one, pass "skip" (${ifSkipped}). Never invent a value. A JSON array is expected; a single id or a comma-separated list is also accepted.`,
    );
}

/** An OPTIONAL array field, equally tolerant of stringified input. */
function optArray<T extends z.ZodTypeAny>(inner: T) {
  return z.preprocess(coerceArray, inner.optional());
}

// company_type (migration 0001). These are the business-facing words the team
// already uses — "Client" and "Past Client" ARE the enum values here. Note this
// is a DIFFERENT vocabulary from contact_status (prospect/active_client/…),
// which describes a PERSON. A company is the account; a contact is a human.
const COMPANY_TYPE = z.enum(['prospect', 'client', 'partner', 'past_client']);

const COMPANY_SIZE = z.enum(['1-10', '11-50', '50-200', '200+']);

/**
 * resolveIndustry — map an industry name onto the controlled `industries` list
 * (migration 0062). companies.industry is a trigger-maintained CACHE of the
 * chosen row's name, so we must set industry_id, not the text column. Unknown
 * names are rejected with the valid list rather than silently dropped.
 */
async function resolveIndustry(env: Env, name?: string): Promise<string | null> {
  if (!name) return null;
  const rows = await asUser<{ id: string; name: string }>(env, (sql) => sql`
    SELECT id, name FROM industries WHERE archived_at IS NULL
  `);
  const hit = rows.find((r) => r.name.toLowerCase() === name.trim().toLowerCase());
  if (!hit) {
    throw new Error(
      `Unknown industry "${name}". Valid options are: ${rows
        .map((r) => r.name)
        .sort()
        .join(', ')}`,
    );
  }
  return hit.id;
}

/**
 * normaliseApps — map free-text app names onto the project_app_catalog's
 * canonical casing. Unlike the OS UI, which silently drops unknown entries, we
 * REJECT them and name the valid options: a silent drop loses data the caller
 * believed it had set.
 */
async function normaliseApps(env: Env, requested: string[]): Promise<string[]> {
  if (requested.length === 0) return [];
  const valid = await asUser<{ name: string }>(env, (sql) => sql`
    SELECT name FROM project_app_catalog WHERE archived_at IS NULL
  `);
  const canonical = new Map(valid.map((v) => [v.name.toLowerCase(), v.name]));
  const out: string[] = [];
  const unknown: string[] = [];
  const seen = new Set<string>();
  for (const raw of requested) {
    const hit = canonical.get(String(raw).trim().toLowerCase());
    if (!hit) unknown.push(String(raw));
    else if (!seen.has(hit)) {
      seen.add(hit);
      out.push(hit);
    }
  }
  if (unknown.length > 0) {
    throw new Error(
      `Unknown app(s): ${unknown.join(', ')}. Valid options are: ${valid
        .map((v) => v.name)
        .sort()
        .join(', ')}`,
    );
  }
  return out;
}

/** Which optional fields the caller actually supplied (for the result summary). */
function changedFields(a: Record<string, unknown>, idKey: string): string[] {
  return Object.keys(a).filter(
    (k) => k !== idKey && k !== 'clear_fields' && a[k] !== undefined,
  );
}

export function registerTools(server: ToolServer, env: Env): void {
  // =========================================================================
  // 0. COMPANIES — the ACCOUNT. A contact is a person; a company is the
  //    organisation they belong to. The "create a company" intake (name,
  //    website, type, industry, size, location) lands here, NOT on a contact.
  // =========================================================================
  server.tool(
    'create_company',
    'Create a company (the client account). Ask the user for name and type first; website, industry, size and location are optional follow-ups.',
    {
      name: z.string().min(1).max(300).describe('REQUIRED. The company name.'),
      type: COMPANY_TYPE.describe(
        'REQUIRED. prospect | client | partner | past_client. ASK THE USER — do not guess.',
      ),
      website: askOrSkip(z.string().max(500), 'no website is recorded').describe(
        'REQUIRED — ask the user for the website link. Pass "skip" if they do not have one.',
      ),
      industry: askOrSkip(z.string().max(200), 'no industry is recorded').describe(
        'REQUIRED — ask the user for the industry, using a name from list_industries. Pass "skip" for none.',
      ),
      company_size: askOrSkip(COMPANY_SIZE, 'no size is recorded').describe(
        'REQUIRED — ask the user for the headcount band: 1-10, 11-50, 50-200 or 200+. Pass "skip" for none.',
      ),
      location: askOrSkip(z.string().max(300), 'no location is recorded').describe(
        'REQUIRED — ask the user for the location, e.g. "Indore, MP, India". Pass "skip" for none. Parsed into city/state/country.',
      ),
      account_owner_id: askOrSkip(z.string().uuid(), 'no account owner is set').describe(
        'REQUIRED — ask the user who owns this account, then use find_user. Pass "skip" for none.',
      ),
      about: z.string().max(5000).optional(),
    },
    guard(async (a: any) => {
      const industryId = await resolveIndustry(env, val<string>(a.industry) ?? undefined);
      // "Indore, MP, India" -> city / state / country, last part first so a
      // one-part answer lands in country rather than being dropped.
      const parts = (val<string>(a.location) ?? '')
        .split(',')
        .map((p) => p.trim())
        .filter(Boolean);
      const country = parts.length >= 1 ? parts[parts.length - 1] : null;
      const state = parts.length >= 3 ? parts[parts.length - 2] : null;
      const city = parts.length >= 2 ? parts[0] : null;
      const rows = await asUser(env, (sql) => sql`
        INSERT INTO companies (
          name, website, industry_id, company_size, city, state, country,
          type, about, account_owner_id
        )
        VALUES (
          ${a.name},
          ${val<string>(a.website)},
          ${industryId}::uuid,
          ${val<string>(a.company_size)}::company_size,
          ${city},
          ${state},
          ${country},
          ${a.type}::company_type,
          ${a.about ?? null},
          ${val<string>(a.account_owner_id)}
        )
        RETURNING *
      `);
      if (rows.length === 0) {
        throw new Error('Create not permitted (admin/pm only) or invalid input.');
      }
      return rows[0];
    }),
  );

  server.tool(
    'update_company',
    'Update fields on a company. Only what you pass changes.',
    {
      company_id: z.string().uuid(),
      name: z.string().min(1).max(300).optional(),
      type: COMPANY_TYPE.optional(),
      website: z.string().max(500).optional(),
      industry: z.string().max(200).optional().describe('See list_industries.'),
      company_size: COMPANY_SIZE.optional(),
      city: z.string().max(100).optional(),
      state: z.string().max(100).optional(),
      country: z.string().max(100).optional(),
      about: z.string().max(5000).optional(),
      account_owner_id: z.string().uuid().optional(),
      clear_fields: z
        .array(z.enum(['website', 'industry', 'company_size', 'city', 'state',
                       'country', 'about', 'account_owner_id']))
        .optional(),
    },
    guard(async (a: any) => {
      const given = changedFields(a, 'company_id');
      const clear: string[] = a.clear_fields ?? [];
      if (given.length === 0 && clear.length === 0) {
        throw new Error('Pass at least one field to change or clear.');
      }
      const industryId = await resolveIndustry(env, a.industry);
      const rows = await asUser(env, (sql) => sql`
        UPDATE companies SET
          name             = COALESCE(${a.name ?? null}, name),
          type             = COALESCE(${a.type ?? null}::company_type, type),
          website          = CASE WHEN 'website'          = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.website ?? null}, website) END,
          industry_id      = CASE WHEN 'industry'         = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${industryId}::uuid, industry_id) END,
          company_size     = CASE WHEN 'company_size'     = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.company_size ?? null}::company_size, company_size) END,
          city             = CASE WHEN 'city'             = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.city ?? null}, city) END,
          state            = CASE WHEN 'state'            = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.state ?? null}, state) END,
          country          = CASE WHEN 'country'          = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.country ?? null}, country) END,
          about            = CASE WHEN 'about'            = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.about ?? null}, about) END,
          account_owner_id = CASE WHEN 'account_owner_id' = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.account_owner_id ?? null}::uuid, account_owner_id) END,
          updated_at = now()
        WHERE id = ${a.company_id}::uuid AND archived_at IS NULL
        RETURNING id, display_id, name, type::text AS type, website, industry,
                  company_size::text AS company_size, city, state, country, account_owner_id
      `);
      if (rows.length === 0) throw new Error('Update not permitted or company not found.');
      return { updated: given, cleared: clear, company: rows[0] };
    }),
  );

  server.tool(
    'find_company',
    'Find companies by name, website or display id. Use before create_company to avoid duplicates.',
    {
      query: z.string().min(1).max(200),
      limit: z.number().int().min(1).max(100).default(20),
    },
    guard(async (a: any) => {
      const like = `%${a.query}%`;
      return asUser(env, (sql) => sql`
        SELECT c.id, c.display_id, c.name, c.type::text AS type, c.website,
               c.industry, c.company_size::text AS company_size,
               c.city, c.state, c.country, c.account_owner_id,
               u.full_name AS account_owner_name,
               (SELECT count(*)::int FROM contacts ct
                 WHERE ct.company_id = c.id AND ct.archived_at IS NULL) AS contact_count
        FROM companies c
        LEFT JOIN users u ON u.id = c.account_owner_id
        WHERE c.archived_at IS NULL
          AND (c.name ILIKE ${like} OR c.website ILIKE ${like} OR c.display_id ILIKE ${like})
        ORDER BY c.created_at DESC
        LIMIT ${a.limit ?? 20}
      `);
    }),
  );

  server.tool(
    'set_company_owner',
    'Set who owns a company account.',
    { company_id: z.string().uuid(), user_id: z.string().uuid() },
    guard(async (a: any) => {
      const rows = await asUser(env, (sql) => sql`
        UPDATE companies SET account_owner_id = ${a.user_id}::uuid, updated_at = now()
        WHERE id = ${a.company_id}::uuid AND archived_at IS NULL
        RETURNING id, display_id, name, account_owner_id
      `);
      if (rows.length === 0) throw new Error('Update not permitted or company not found.');
      return rows[0];
    }),
  );

  server.tool(
    'list_industries',
    'The controlled industry vocabulary. Call before create_company so you offer real options.',
    {},
    guard(async () =>
      asUser(env, (sql) => sql`
        SELECT id, name FROM industries WHERE archived_at IS NULL ORDER BY name
      `),
    ),
  );

  // =========================================================================
  // 1. CREATE CONTACT
  // =========================================================================
  server.tool(
    'create_contact',
    'Create a contact (the CRM hub record) and its ownership row. ASK THE USER for status and owner if they have not said — never guess them.',
    {
      full_name: z.string().min(1).max(300).describe('Required. Full name of the person.'),
      status: askOrSkip(CONTACT_STATUS, 'defaults to "prospect"').describe(
        'REQUIRED — ask the user: prospect, active_client, partner, on_hold or churned. Pass "skip" to default to "prospect". NOTE: this describes the PERSON; a COMPANY\'s type (prospect/client/partner/past_client) is set on create_company.',
      ),
      primary_owner_id: askOrSkip(
        z.string().uuid(),
        'the MCP system account ends up owning it, which is usually wrong',
      ).describe(
        'REQUIRED — ask the user who owns this contact, then use find_user. Pass "skip" only if they genuinely have no owner in mind.',
      ),
      company_id: askOrSkip(z.string().uuid(), 'the contact has no company').describe(
        'REQUIRED — ask which company this person belongs to, then use find_company. Pass "skip" for an individual with no company.',
      ),
      email: z.string().email().max(300).optional(),
      phone: z.string().max(50).optional(),
    },
    guard(async (a: any) => {
      const ownerId = val<string>(a.primary_owner_id) ?? actorUid(env);
      const rows = await asUser(env, (sql) => sql`
        WITH new_contact AS (
          INSERT INTO contacts (full_name, email, phone, company_id, status, primary_owner_id)
          VALUES (
            ${a.full_name},
            ${a.email ?? null},
            ${a.phone ?? null},
            ${val<string>(a.company_id)},
            COALESCE(${val<string>(a.status)}::contact_status, 'prospect'::contact_status),
            ${ownerId}
          )
          RETURNING *
        ), owner_row AS (
          INSERT INTO contact_owners (contact_id, user_id)
          SELECT id, ${ownerId}::uuid FROM new_contact
          ON CONFLICT (contact_id, user_id) DO NOTHING
        )
        SELECT * FROM new_contact
      `);
      return rows[0];
    }),
  );

  // =========================================================================
  // 2. CREATE DEAL
  // =========================================================================
  server.tool(
    'create_deal',
    'Create a deal on a contact, placed in a pipeline stage. Call list_pipelines first. ASK THE USER for stage, value and currency if not given — never guess them.',
    {
      name: z.string().min(1).max(300),
      contact_id: z.string().uuid().describe('Required. Use search_contacts to find it.'),
      pipeline_id: z.string().uuid().describe('Required. From list_pipelines.'),
      stage_id: z
        .string()
        .uuid()
        .describe(
          'REQUIRED. The pipeline stage the deal starts in, from list_pipelines. If the user has not said which stage, ASK THEM — do not default to the first stage.',
        ),
      deal_value: askOrSkip(z.number(), 'no value is recorded').describe(
        'REQUIRED — ask the user for the deal amount. Pass "skip" for none.',
      ),
      currency: askOrSkip(z.string().length(3), 'no currency is recorded').describe(
        'REQUIRED — ask the user for the 3-letter code, e.g. USD or INR. Pass "skip" for none.',
      ),
      initial_deal_amount: askOrSkip(z.number(), 'no initial amount is recorded').describe(
        'REQUIRED — ask the user for the initial amount. Pass "skip" for none.',
      ),
      lead_type: askOrSkip(z.string().max(200), 'no lead type is recorded').describe(
        'REQUIRED — ask the user, e.g. "Inbound" or "Referral". NEVER infer it. Pass "skip" if they do not know.',
      ),
      source: askOrSkip(z.string().max(200), 'no source is recorded').describe(
        'REQUIRED — ask the user where the lead came from, e.g. LinkedIn or Upwork. NEVER invent or infer it. Pass "skip" if they do not know.',
      ),
      primary_owner_id: askOrSkip(z.string().uuid(), 'the MCP system account owns it').describe(
        'REQUIRED — ask the user who owns this deal, then use find_user. Pass "skip" for none.',
      ),
      close_date: askOrSkip(z.string(), 'no closing date is set').describe(
        'REQUIRED — ask the user for the expected closing date (YYYY-MM-DD). Pass "skip" for none.',
      ),
      payment_type: z.string().optional(),
    },
    guard(async (a: any) => {
      // Resolve the stage: the caller's choice if it belongs to this pipeline,
      // else the pipeline's first live stage.
      const wanted = a.stage_id ?? null;
      const stageRows = await asUser<{ id: string }>(env, (sql) => sql`
        SELECT id FROM pipeline_stages
        WHERE pipeline_id = ${a.pipeline_id}::uuid AND archived_at IS NULL
          AND (${wanted}::uuid IS NULL OR id = ${wanted}::uuid)
        ORDER BY (id = ${wanted}::uuid) DESC, sort_order, created_at
        LIMIT 1
      `);
      const stageId = stageRows[0]?.id ?? null;
      if (wanted && stageId !== wanted) {
        throw new Error(
          `stage_id ${wanted} does not belong to pipeline_id ${a.pipeline_id} (or is archived)`,
        );
      }
      if (!stageId) {
        throw new Error('That pipeline has no stages. Add a stage before placing deals in it.');
      }

      const ownerId = val<string>(a.primary_owner_id) ?? actorUid(env);
      const rows = await asUser(env, (sql) => sql`
        WITH new_deal AS (
          INSERT INTO deals (
            name, contact_id, payment_type, deal_value, initial_deal_amount,
            currency, stage, close_date, primary_owner_id, pipeline_id, stage_id,
            lead_type, source
          )
          VALUES (
            ${a.name},
            ${a.contact_id}::uuid,
            ${a.payment_type ?? null}::payment_type,
            ${val<number>(a.deal_value)},
            ${val<number>(a.initial_deal_amount)},
            ${val<string>(a.currency)},
            -- Keep the legacy deal_stage enum in sync with the pipeline stage:
            -- use the stage's NAME when it is a valid enum label, else 'new'.
            COALESCE(
              (SELECT ps.name::deal_stage
                 FROM pipeline_stages ps
                 JOIN pg_enum e ON e.enumlabel = ps.name
                 JOIN pg_type t ON t.oid = e.enumtypid AND t.typname = 'deal_stage'
                WHERE ps.id = ${stageId}::uuid),
              'new'::deal_stage
            ),
            ${val<string>(a.close_date)}::date,
            ${ownerId},
            ${a.pipeline_id}::uuid,
            ${stageId}::uuid,
            ${val<string>(a.lead_type)},
            ${val<string>(a.source)}
          )
          -- Date columns as raw YYYY-MM-DD text (shadowing the * versions). The
          -- Neon driver otherwise returns a JS Date at UTC midnight, which reads
          -- as the PREVIOUS day in a +05:30 context.
          RETURNING *, to_char(close_date, 'YYYY-MM-DD') AS close_date
        ), owner_row AS (
          INSERT INTO deal_owners (deal_id, user_id)
          SELECT id, ${ownerId}::uuid FROM new_deal
          ON CONFLICT (deal_id, user_id) DO NOTHING
        )
        SELECT * FROM new_deal
      `);
      return rows[0];
    }),
  );

  // =========================================================================
  // 3. CREATE PROJECT
  // =========================================================================
  server.tool(
    'create_project',
    'Create a delivery project, optionally linked to a deal. ASK THE USER which apps the project uses — call list_apps for the valid vocabulary.',
    {
      name: z.string().min(1).max(300),
      deal_id: askOrSkip(z.string().uuid(), 'the project has no deal').describe(
        'REQUIRED — ask the user which deal this project belongs to, then use find_deal. Pass "skip" for an internal or pre-deal project.',
      ),
      contact_id: askOrSkip(z.string().uuid(), 'no client is linked').describe(
        'REQUIRED — ask the user who the client is, then use search_contacts. Pass "skip" for none. Ignored when deal_id is given: the client is trigger-cached from the deal.',
      ),
      status: askOrSkip(z.string(), 'defaults to "upcoming"').describe(
        'REQUIRED — ask the user. Real values from get_statuses("project"): upcoming, in_progress, client_pending, on_hold, payment_pending, handover, client_review, completed, internal, lost. Pass "skip" to default to "upcoming".',
      ),
      estimated_hours: askOrSkip(z.number(), 'no estimate is recorded').describe(
        'REQUIRED — ask the user for the estimated hours. Pass "skip" for none.',
      ),
      start_date: askOrSkip(z.string(), 'no start date is set').describe(
        'REQUIRED — ask the user for the start date (YYYY-MM-DD). Pass "skip" for none.',
      ),
      estimated_completion_date: askOrSkip(z.string(), 'no completion date is set').describe(
        'REQUIRED — ask the user for the estimated completion date (YYYY-MM-DD). Pass "skip" for none.',
      ),
      project_manager_id: z.string().uuid().optional().describe('Use find_user.'),
      apps: z
        .array(z.string())
        .optional()
        .describe('Apps/tools this project uses, from the list_apps catalog. Optional.'),
    },
    guard(async (a: any) => {
      // Normalise the app names to the catalog's canonical casing. Unlike the OS
      // UI, which silently drops unknown entries, we REJECT them and list what is
      // valid — a silent drop would lose data the caller thought it had set.
      const apps = await normaliseApps(env, Array.isArray(a.apps) ? a.apps : []);
      const dealId = val<string>(a.deal_id);
      const contactId = val<string>(a.contact_id);

      const rows = await asUser(env, (sql) => sql`
        INSERT INTO projects (
          name, deal_id, contact_id, status, start_date,
          estimated_completion_date, estimated_hours, project_manager_id, apps_used
        )
        VALUES (
          ${a.name},
          ${dealId},
          -- Only meaningful for a deal-less project; with a deal the spine
          -- trigger re-caches contact_id from it and overwrites this.
          ${dealId ? null : contactId}::uuid,
          COALESCE(${val<string>(a.status)}::project_status, 'upcoming'::project_status),
          ${val<string>(a.start_date)}::date,
          ${val<string>(a.estimated_completion_date)}::date,
          ${val<number>(a.estimated_hours)},
          ${a.project_manager_id ?? null},
          ${apps}::text[]
        )
        -- Dates as raw text — see the note in create_deal.
        RETURNING *,
          to_char(start_date, 'YYYY-MM-DD')                AS start_date,
          to_char(estimated_completion_date, 'YYYY-MM-DD') AS estimated_completion_date,
          to_char(actual_completion_date, 'YYYY-MM-DD')    AS actual_completion_date
      `);
      if (rows.length === 0) {
        throw new Error('Create not permitted (admin/pm only) or invalid input.');
      }
      return rows[0];
    }),
  );

  // =========================================================================
  // 4. CREATE TASK
  // =========================================================================
  server.tool(
    'create_task',
    'Create a task under a milestone (or a deal/payment). ASK THE USER for priority, project manager, assignee, start date, due date, estimated hours AND who is creating the task if any are missing — never guess them.',
    {
      title: z.string().min(1).max(300),
      parent_id: z.string().uuid().describe('Usually a milestone id — see find_milestone.'),
      parent_type: z.enum(['milestone', 'deal', 'payment']).default('milestone'),
      manager_ids: askOrSkipArray(
        z.array(z.string().uuid()).min(1),
        'no manager is recorded',
      ).describe(
        'REQUIRED — ask the user which project manager oversees this task, then use find_user. Pass "skip" for none. The first id also becomes the cached primary PM.',
      ),
      // status and priority are DIFFERENT fields. "High priority" is
      // priority=high — it is never a task_status value.
      status: askOrSkip(z.string(), 'defaults to "todo"').describe(
        'REQUIRED — ask the user. Real values from get_statuses("task"): todo, in_progress, client_review, client_pending, internal_action, qa_review, stuck, on_hold, done, … Pass "skip" to default to "todo". NOTE: "priority" is NOT a status — use the priority field.',
      ),
      priority: askOrSkip(PRIORITY, 'defaults to "medium"').describe(
        'REQUIRED — ask the user: low, medium or high. A separate field from status. Pass "skip" to default to "medium".',
      ),
      plan_due_date: askOrSkip(z.string(), 'no due date is set').describe(
        'REQUIRED — ask the user for the due date (YYYY-MM-DD). Pass "skip" for none.',
      ),
      estimated_hours: askOrSkip(z.number().min(0).max(100000), 'no estimate is recorded').describe(
        'REQUIRED — ask the user for the estimated hours. Pass "skip" for none.',
      ),
      requirement: askOrSkip(z.string().max(20000), 'the requirement box is left empty').describe(
        'REQUIRED — what actually needs doing, for the requirement box. If the user did not give it in the prompt, ASK THEM. Pass "skip" to leave it empty.',
      ),
      assignee_ids: askOrSkipArray(
        z.array(z.string().uuid()),
        'the task is created unassigned',
      ).describe(
        'REQUIRED — ask the user who will do the work, then use find_user. Pass "skip" to leave it unassigned.',
      ),
      start_date: askOrSkip(z.string(), 'no start date is set').describe(
        'REQUIRED — ask the user for the start date (YYYY-MM-DD). Pass "skip" for none.',
      ),
      // Attribution only. The MCP authenticates with ONE shared token and acts
      // under ONE identity (GS_ACTOR_UID), so the database cannot know which
      // human is calling — it has to be told.
      //
      // ask-or-skip, NOT optional: an optional field lets the model quietly omit
      // it, which is the silent defaulting this file exists to prevent. Every task
      // was landing on the MCP service account because nobody was ever asked.
      // Required-but-skippable forces a conscious choice on every create.
      //
      // Attribution ONLY: this sets created_by and never touches
      // app.current_user_id, so RLS authorizes the call exactly as before.
      // NO ask-or-skip here, deliberately. With a "skip" option the model took it
      // whenever it was unsure, and every such task landed on MCP (System) again -
      // the exact problem this field exists to fix. A closed two-value enum with no
      // escape means created_by is ALWAYS a real person, and the model has to ask
      // rather than quietly fall back.
      acting_user_id: z.enum(CREATOR_IDS).describe(
        `REQUIRED — who is creating this task. ONLY these two people are permitted: ${CREATOR_HINT}. There is NO skip and NO default. If the user has not said which of the two they are in THIS request, ASK THEM before calling this tool; if they named anyone else, tell them only these two are permitted and ask which to record. Do NOT infer it from earlier messages, from another task, from the assignee or from the manager, and do NOT call find_user for this field — the two ids above are the only accepted values.`,
      ),
    },
    guard(async (a: any) => {
      const taskId = crypto.randomUUID();
      const managerIds = arrVal(a.manager_ids);
      const assigneeIds = arrVal(a.assignee_ids);
      const status = val<string>(a.status);
      const priority = val<string>(a.priority);
      const startDate = val<string>(a.start_date);
      const dueDate = val<string>(a.plan_due_date);
      const estHours = val<number>(a.estimated_hours);
      const requirement = val<string>(a.requirement);
      // Attribution: the named human when the caller supplied one, otherwise the
      // service identity exactly as before.
      // Always supplied now (required enum, no skip); the fallback is belt-and-braces.
      const createdBy = a.acting_user_id ?? actorUid(env);

      // Insert WITHOUT RETURNING, then SELECT back in the same transaction: the
      // tasks SELECT policy (fn_can_see) is self-referential, so the new row is
      // invisible to RETURNING and the insert is rejected even for an admin.
      const rows = await asUserMany(env, (sql) => [
        sql`
          INSERT INTO tasks (
            id, title, parent_type, parent_id, status, priority, start_date, plan_due_date,
            estimated_hours, requirement, primary_pm_id, is_management, created_by
          )
          VALUES (
            ${taskId}::uuid,
            ${a.title},
            ${a.parent_type ?? 'milestone'}::entity_type,
            ${a.parent_id}::uuid,
            COALESCE(${status}::task_status, 'todo'::task_status),
            COALESCE(${priority}::priority, 'medium'::priority),
            ${startDate}::date,
            ${dueDate}::date,
            ${estHours},
            ${requirement},
            ${managerIds[0] ?? null}::uuid,
            false,
            ${createdBy}::uuid
          )
        `,
        ...managerIds.map(
          (id) => sql`
            INSERT INTO task_managers (task_id, user_id)
            VALUES (${taskId}::uuid, ${id}::uuid)
            ON CONFLICT (task_id, user_id) DO NOTHING
          `,
        ),
        ...assigneeIds.map(
          (id) => sql`
            INSERT INTO task_assignees (task_id, user_id)
            VALUES (${taskId}::uuid, ${id}::uuid)
            ON CONFLICT (task_id, user_id) DO NOTHING
          `,
        ),
        // Read the task back WITH its relations, so a create returns the same
        // full field feed as get_record and the caller never has to follow up
        // just to see who ended up attached.
        sql`SELECT t.*,
                   to_char(t.start_date, 'YYYY-MM-DD')           AS start_date,
                   to_char(t.plan_due_date, 'YYYY-MM-DD')        AS plan_due_date,
                   to_char(t.execution_start_date, 'YYYY-MM-DD') AS execution_start_date,
                   to_char(t.execution_end_date, 'YYYY-MM-DD')   AS execution_end_date,
                   cu.full_name AS created_by_name,
                   pm.full_name AS primary_pm_name,
                   COALESCE((
                     SELECT jsonb_agg(jsonb_build_object('user_id', u.id, 'name', u.full_name))
                     FROM task_assignees ta JOIN users u ON u.id = ta.user_id
                     WHERE ta.task_id = t.id
                   ), '[]'::jsonb) AS assignees,
                   COALESCE((
                     SELECT jsonb_agg(jsonb_build_object('user_id', u.id, 'name', u.full_name))
                     FROM task_managers tm JOIN users u ON u.id = tm.user_id
                     WHERE tm.task_id = t.id
                   ), '[]'::jsonb) AS managers
            FROM tasks t
            LEFT JOIN users cu ON cu.id = t.created_by
            LEFT JOIN users pm ON pm.id = t.primary_pm_id
            WHERE t.id = ${taskId}::uuid`,
      ]);
      if (rows.length === 0) throw new Error('Create not permitted or invalid input.');
      return rows[0];
    }),
  );

  // =========================================================================
  // 4b. CREATE MILESTONE
  // =========================================================================
  server.tool(
    'create_milestone',
    'Create ONE milestone under a project. A project can have many — call this once per milestone. ASK THE USER for the status if they have not said.',
    {
      name: z.string().min(1).max(300),
      project_id: z.string().uuid().describe('Required. Use find_project.'),
      status: askOrSkip(MILESTONE_STATUS, 'defaults to "not_started"').describe(
        'REQUIRED — ask the user: not_started, in_progress, in_review, client_pending, on_hold or done. Pass "skip" to default to "not_started".',
      ),
      estimated_hours: askOrSkip(z.number(), 'no estimate is recorded').describe(
        'REQUIRED — ask the user for the estimated hours. Pass "skip" for none.',
      ),
      target_date: z.string().optional().describe('YYYY-MM-DD. Optional.'),
      price: z.number().optional().describe('Milestones are billable line items. Optional.'),
      currency: z.string().max(3).optional(),
    },
    guard(async (a: any) => {
      const milestoneId = crypto.randomUUID();
      // Same self-referential SELECT policy problem as tasks: insert without
      // RETURNING, then read the row back in the same transaction.
      const rows = await asUserMany(env, (sql) => [
        sql`
          INSERT INTO milestones (
            id, name, project_id, status, target_date,
            estimated_hours, price, currency
          )
          VALUES (
            ${milestoneId}::uuid,
            ${a.name},
            ${a.project_id}::uuid,
            COALESCE(${val<string>(a.status)}::milestone_status, 'not_started'::milestone_status),
            ${a.target_date ?? null}::date,
            ${val<number>(a.estimated_hours)},
            ${a.price ?? null},
            ${a.currency ?? null}
          )
        `,
        sql`SELECT *,
                   to_char(start_date, 'YYYY-MM-DD')             AS start_date,
                   to_char(target_date, 'YYYY-MM-DD')            AS target_date,
                   to_char(actual_completion_date, 'YYYY-MM-DD') AS actual_completion_date
            FROM milestones WHERE id = ${milestoneId}::uuid`,
      ]);
      if (rows.length === 0) {
        throw new Error('Create not permitted (admin/pm only) or invalid input.');
      }
      return rows[0];
    }),
  );

  // =========================================================================
  // 5. GET STATUSES
  // =========================================================================
  server.tool(
    'get_statuses',
    'List the allowed status values for an entity. Deals use pipeline stages (rows); everything else uses a Postgres enum.',
    {
      entity: z.enum(['company', 'contact', 'deal', 'project', 'milestone', 'task', 'payment']),
    },
    guard(async (a: any) => {
      if (a.entity === 'deal') {
        const stages = await asUser(env, (sql) => sql`
          SELECT p.id AS pipeline_id, p.name AS pipeline_name,
                 s.id AS stage_id, s.name AS stage_name, s.sort_order
          FROM pipelines p
          JOIN pipeline_stages s ON s.pipeline_id = p.id AND s.archived_at IS NULL
          WHERE p.archived_at IS NULL
          ORDER BY p.name, s.sort_order
        `);
        return { entity: 'deal', kind: 'pipeline_stages', stages };
      }

      const enumName = {
        contact: 'contact_status',
        project: 'project_status',
        milestone: 'milestone_status',
        task: 'task_status',
        payment: 'payment_status',
      }[a.entity as 'contact' | 'project' | 'milestone' | 'task' | 'payment'];

      const rows = await asUser<{ value: string }>(env, (sql) => sql`
        SELECT e.enumlabel AS value
        FROM pg_enum e
        JOIN pg_type t ON t.oid = e.enumtypid
        WHERE t.typname = ${enumName}
        ORDER BY e.enumsortorder
      `);
      return {
        entity: a.entity,
        kind: 'enum',
        enum: enumName,
        values: rows.map((r) => r.value),
      };
    }),
  );

  // =========================================================================
  // 6. GET PAYMENTS
  // =========================================================================
  server.tool(
    'get_payments',
    'List payments with their deal, project, milestone and client context. All filters are optional.',
    {
      status: z.array(z.string()).optional(),
      deal_id: z.array(z.string().uuid()).optional(),
      project_id: z.array(z.string().uuid()).optional(),
      date_from: z.string().optional().describe('payment_date >= YYYY-MM-DD'),
      date_to: z.string().optional().describe('payment_date <= YYYY-MM-DD'),
      search: z
        .string()
        .max(200)
        .optional()
        .describe('Matches display_id, transaction_ref, deal/project/client name.'),
      limit: z.number().int().min(1).max(500).default(100),
    },
    guard(async (a: any) => {
      const statuses = a.status?.length ? a.status : null;
      const dealIds = a.deal_id?.length ? a.deal_id : null;
      const projectIds = a.project_id?.length ? a.project_id : null;
      const dateFrom = a.date_from ?? null;
      const dateTo = a.date_to ?? null;
      const search = a.search ? `%${a.search}%` : null;
      const limit = a.limit ?? 100;

      return asUser(env, (sql) => sql`
        SELECT p.*,
               -- Dates as raw text: the Neon driver otherwise parses them to a JS
               -- Date at UTC midnight, which renders a day early in IST.
               to_char(p.billing_date, 'YYYY-MM-DD') AS billing_date,
               to_char(p.payment_date, 'YYYY-MM-DD') AS payment_date,
               d.name  AS deal_name,      d.display_id  AS deal_display_id,
               m.name  AS milestone_name, m.display_id  AS milestone_display_id,
               pr.name AS project_name,   pr.display_id AS project_display_id,
               ct.full_name AS contact_name, ct.display_id AS contact_display_id
        FROM payments p
        LEFT JOIN deals d      ON d.id = p.deal_id
        LEFT JOIN milestones m ON m.id = p.milestone_id
        LEFT JOIN projects pr  ON pr.id = COALESCE(p.project_id, m.project_id)
        LEFT JOIN contacts ct  ON ct.id = p.contact_id
        WHERE p.archived_at IS NULL
          AND (${statuses}::text[] IS NULL OR p.status::text = ANY(${statuses}::text[]))
          AND (${dealIds}::uuid[] IS NULL OR p.deal_id = ANY(${dealIds}::uuid[]))
          AND (
            ${projectIds}::uuid[] IS NULL
            OR p.project_id = ANY(${projectIds}::uuid[])
            OR m.project_id = ANY(${projectIds}::uuid[])
          )
          AND (${dateFrom}::date IS NULL OR p.payment_date >= ${dateFrom}::date)
          AND (${dateTo}::date   IS NULL OR p.payment_date <= ${dateTo}::date)
          AND (
            ${search}::text IS NULL
            OR p.display_id ILIKE ${search}
            OR p.transaction_ref ILIKE ${search}
            OR d.name ILIKE ${search}
            OR pr.name ILIKE ${search}
            OR ct.full_name ILIKE ${search}
          )
        ORDER BY p.created_at DESC
        LIMIT ${limit}
      `);
    }),
  );

  // =========================================================================
  // 7. CREATE PAYMENT
  // =========================================================================
  server.tool(
    'create_payment',
    'Record a payment against a deal. If developers are given, their percent shares must total 100 (enforced by the database).',
    {
      deal_id: z.string().uuid().describe('Required. Use find_deal.'),
      amount: z.number(),
      currency: z.string().length(3),
      submitted_amount: z.number().describe('Required alongside amount.'),
      status: z.string().optional().describe('payment_status; defaults to "forecast".'),
      project_id: z.string().uuid().optional(),
      milestone_id: z.string().uuid().optional(),
      payment_type: z.string().optional(),
      payment_date: z.string().optional().describe('YYYY-MM-DD'),
      billing_date: z.string().optional().describe('YYYY-MM-DD'),
      transaction_ref: z.string().optional(),
      invoice_no: z.string().max(120).optional(),
      note: z.string().optional(),
      received_amount_inr: z.number().optional(),
      platform_name: z.string().optional(),
      billing_type: z.enum(['fixed', 'hourly']).optional(),
      hours_logged: z.number().optional(),
      hourly_rate: z.number().optional(),
      developers: z
        .array(
          z.object({
            user_id: z.string().uuid(),
            percent_share: z.number().min(0).max(100),
          }),
        )
        .optional()
        .describe('Percent shares must total exactly 100.'),
    },
    guard(async (a: any) => {
      const paymentId = crypto.randomUUID();

      // Dedupe by user_id (last wins), then check the 100% rule up front so the
      // caller gets a clear message instead of a raw trigger exception.
      const byUser = new Map<string, number>();
      for (const d of a.developers ?? []) byUser.set(d.user_id, d.percent_share);
      const developers = [...byUser.entries()].map(([user_id, percent_share]) => ({
        user_id,
        percent_share,
      }));
      if (developers.length > 0) {
        const total = developers.reduce((s, d) => s + d.percent_share, 0);
        if (Math.round(total * 100) !== 10000) {
          throw new Error(
            `Developer percentages must total 100% (got ${Math.round(total * 100) / 100}%).`,
          );
        }
      }

      const rows = await asUserMany(env, (sql) => [
        sql`
          INSERT INTO payments (
            id, deal_id, project_id, milestone_id,
            amount, currency, payment_type, payment_date, billing_date, transaction_ref,
            status, note, submitted_amount, received_amount_inr,
            platform_name, billing_type, hours_logged, hourly_rate, invoice_no, created_by
          )
          VALUES (
            ${paymentId}::uuid,
            ${a.deal_id}::uuid,
            ${a.project_id ?? null}::uuid,
            ${a.milestone_id ?? null}::uuid,
            ${a.amount},
            ${a.currency},
            ${a.payment_type ?? null}::payment_type,
            ${a.payment_date ?? null}::date,
            ${a.billing_date ?? null}::date,
            ${a.transaction_ref ?? null},
            COALESCE(${a.status ?? null}::payment_status, 'forecast'::payment_status),
            ${a.note ?? null},
            ${a.submitted_amount},
            ${a.received_amount_inr ?? null},
            ${a.platform_name ?? null},
            ${a.billing_type ?? 'fixed'},
            ${a.hours_logged ?? null},
            ${a.hourly_rate ?? null},
            ${a.invoice_no ?? null},
            ${actorUid(env)}::uuid
          )
        `,
        ...developers.map(
          (d) => sql`
            INSERT INTO payment_developers (payment_id, user_id, percent_share)
            VALUES (${paymentId}::uuid, ${d.user_id}::uuid, ${d.percent_share})
            ON CONFLICT (payment_id, user_id) DO NOTHING
          `,
        ),
        sql`SELECT *,
                   to_char(payment_date, 'YYYY-MM-DD') AS payment_date,
                   to_char(billing_date, 'YYYY-MM-DD') AS billing_date
            FROM payments WHERE id = ${paymentId}::uuid`,
      ]);
      if (rows.length === 0) throw new Error('Create not permitted or invalid input.');
      return rows[0];
    }),
  );

  // =========================================================================
  // 8. DEVELOPER AVAILABILITY
  // =========================================================================
  server.tool(
    'get_developer_availability',
    'Per-developer daily working hours, project allocations and remaining free capacity over a date range.',
    {
      date_from: z.string().describe('YYYY-MM-DD'),
      date_to: z.string().describe('YYYY-MM-DD'),
      user_id: z.string().uuid().optional().describe('Limit to one developer.'),
    },
    guard(async (a: any) => {
      const userId = a.user_id ?? null;
      const rows = await asUser<{
        user_id: string;
        user_name: string;
        user_email: string | null;
        projects_requested: number | string | null;
        date: string | null;
        working_hours: string | null;
        status: string | null;
        allocations: { project_id: string; project_name: string; hours: number }[] | null;
      }>(env, (sql) => sql`
        SELECT
          u.id                                        AS user_id,
          COALESCE(u.full_name, u.email, u.id::text)  AS user_name,
          u.email                                     AS user_email,
          u.projects_requested                        AS projects_requested,
          ua.date::text                               AS date,
          ua.working_hours::text                      AS working_hours,
          ua.status::text                             AS status,
          COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                     'project_id',   al.project_id,
                     'project_name', p.name,
                     'hours',        al.hours
                   ) ORDER BY p.name)
            FROM availability_allocations al
            JOIN projects p ON p.id = al.project_id
            WHERE al.availability_id = ua.id
          ), '[]'::jsonb)                             AS allocations
        FROM users u
        LEFT JOIN user_availability ua
               ON ua.user_id = u.id
              AND ua.date >= ${a.date_from}::date
              AND ua.date <= ${a.date_to}::date
        WHERE u.archived_at IS NULL
          AND u.status <> 'left_org'
          AND u.role = 'developer'
          AND (${userId}::uuid IS NULL OR u.id = ${userId}::uuid)
        ORDER BY user_name, ua.date
      `);

      // Fold the flat rows into one entry per developer.
      const byDev = new Map<string, any>();
      for (const r of rows) {
        let dev = byDev.get(r.user_id);
        if (!dev) {
          dev = {
            user_id: r.user_id,
            user_name: r.user_name,
            user_email: r.user_email,
            projects_requested: Number(r.projects_requested) || 0,
            days: [] as unknown[],
          };
          byDev.set(r.user_id, dev);
        }
        if (!r.date) continue; // developer with no availability rows in range

        const allocations = r.allocations ?? [];
        const allocated = allocations.reduce((s, x) => s + Number(x.hours), 0);
        // Half-day statuses halve the day; 'absent' is zero. NOTE: the OS UI
        // helper workingForStatus() uses fixed constants and does NOT zero out
        // 'absent' — see README, "Known differences from the OS app".
        const base = r.working_hours == null ? 8 : Number(r.working_hours);
        const working =
          r.status === 'absent'
            ? 0
            : r.status === 'first_half' || r.status === 'second_half'
              ? base / 2
              : base;

        dev.days.push({
          date: r.date,
          status: r.status,
          working_hours: working,
          allocated_hours: allocated,
          available_hours: Math.max(0, working - allocated),
          allocations,
        });
      }
      return [...byDev.values()];
    }),
  );

  // =========================================================================
  // FIELD EDITS
  // =========================================================================
  server.tool(
    'update_contact',
    'Update fields on an existing contact. Only the fields you pass are changed; anything omitted is left alone. Cannot blank a field out.',
    {
      contact_id: z.string().uuid(),
      full_name: z.string().min(1).max(300).optional(),
      email: z.string().email().max(300).optional(),
      phone: z.string().max(50).optional(),
      whatsapp: z.string().max(50).optional(),
      status: CONTACT_STATUS.optional(),
      company_id: z.string().uuid().optional(),
      job_title: z.string().max(200).optional(),
      country: z.string().max(100).optional(),
      city: z.string().max(100).optional(),
      state: z.string().max(100).optional(),
      timezone: z.string().max(100).optional(),
      about: z.string().max(5000).optional(),
      clear_fields: z
        .array(z.enum(['email', 'phone', 'whatsapp', 'company_id', 'job_title',
                       'country', 'city', 'state', 'timezone', 'about']))
        .optional()
        .describe('Fields to blank out. Use this to remove a value rather than change it.'),
    },
    guard(async (a: any) => {
      const given = changedFields(a, 'contact_id');
      const clear: string[] = a.clear_fields ?? [];
      if (given.length === 0 && clear.length === 0) {
        throw new Error('Pass at least one field to change or clear.');
      }
      // Per column: clear wins, else the new value, else keep what's there.
      // Column names are hard-coded literals; every value is parameterised.
      const rows = await asUser(env, (sql) => sql`
        UPDATE contacts SET
          full_name  = COALESCE(${a.full_name ?? null}, full_name),
          email      = CASE WHEN 'email'      = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.email ?? null}, email) END,
          phone      = CASE WHEN 'phone'      = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.phone ?? null}, phone) END,
          whatsapp   = CASE WHEN 'whatsapp'   = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.whatsapp ?? null}, whatsapp) END,
          status     = COALESCE(${a.status ?? null}::contact_status, status),
          company_id = CASE WHEN 'company_id' = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.company_id ?? null}::uuid, company_id) END,
          job_title  = CASE WHEN 'job_title'  = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.job_title ?? null}, job_title) END,
          country    = CASE WHEN 'country'    = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.country ?? null}, country) END,
          city       = CASE WHEN 'city'       = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.city ?? null}, city) END,
          state      = CASE WHEN 'state'      = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.state ?? null}, state) END,
          timezone   = CASE WHEN 'timezone'   = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.timezone ?? null}, timezone) END,
          about      = CASE WHEN 'about'      = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.about ?? null}, about) END,
          updated_at = now()
        WHERE id = ${a.contact_id}::uuid AND archived_at IS NULL
        RETURNING id, display_id, full_name, email, phone, whatsapp,
                  status::text AS status, job_title, company_id
      `);
      if (rows.length === 0) throw new Error('Update not permitted or contact not found.');
      return { updated: given, cleared: clear, contact: rows[0] };
    }),
  );

  server.tool(
    'update_deal',
    'Update fields on a deal. Only what you pass changes. To move a deal between pipeline stages use set_deal_stage instead.',
    {
      deal_id: z.string().uuid(),
      name: z.string().min(1).max(300).optional(),
      deal_value: z.number().optional(),
      initial_deal_amount: z.number().optional(),
      currency: z.string().length(3).optional(),
      payment_type: z.string().optional(),
      close_date: z.string().optional().describe('YYYY-MM-DD'),
      description: z.string().max(5000).optional(),
      lead_type: z.string().max(200).optional().describe('Do not invent — ask the user.'),
      source: z.string().max(200).optional().describe('Do not invent — ask the user.'),
      clear_fields: z
        .array(z.enum(['close_date', 'description', 'lead_type', 'source', 'payment_type',
                       'deal_value', 'initial_deal_amount']))
        .optional()
        .describe('Fields to blank out.'),
    },
    guard(async (a: any) => {
      const given = changedFields(a, 'deal_id');
      const clear: string[] = a.clear_fields ?? [];
      if (given.length === 0 && clear.length === 0) {
        throw new Error('Pass at least one field to change or clear.');
      }
      const rows = await asUser(env, (sql) => sql`
        UPDATE deals SET
          name                = COALESCE(${a.name ?? null}, name),
          deal_value          = CASE WHEN 'deal_value'          = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.deal_value ?? null}, deal_value) END,
          initial_deal_amount = CASE WHEN 'initial_deal_amount' = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.initial_deal_amount ?? null}, initial_deal_amount) END,
          currency            = COALESCE(${a.currency ?? null}, currency),
          payment_type        = CASE WHEN 'payment_type' = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.payment_type ?? null}::payment_type, payment_type) END,
          close_date          = CASE WHEN 'close_date'   = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.close_date ?? null}::date, close_date) END,
          description         = CASE WHEN 'description'  = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.description ?? null}, description) END,
          lead_type           = CASE WHEN 'lead_type'    = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.lead_type ?? null}, lead_type) END,
          source              = CASE WHEN 'source'       = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.source ?? null}, source) END,
          updated_at = now()
        WHERE id = ${a.deal_id}::uuid AND archived_at IS NULL
        RETURNING id, display_id, name, deal_value, currency,
                  to_char(close_date, 'YYYY-MM-DD') AS close_date,
                  stage::text AS stage, lead_type, source
      `);
      if (rows.length === 0) throw new Error('Update not permitted or deal not found.');
      return { updated: given, cleared: clear, deal: rows[0] };
    }),
  );

  server.tool(
    'update_project',
    'Update fields on a project. Only what you pass changes. For status use set_project_status (it enforces the on-hold reason).',
    {
      project_id: z.string().uuid(),
      name: z.string().min(1).max(300).optional(),
      apps: z.array(z.string()).optional().describe('Replaces the app list. See list_apps.'),
      start_date: z.string().optional().describe('YYYY-MM-DD'),
      estimated_completion_date: z.string().optional().describe('YYYY-MM-DD'),
      actual_completion_date: z.string().optional().describe('YYYY-MM-DD'),
      estimated_hours: z.number().optional(),
      project_manager_id: z.string().uuid().optional().describe('Use find_user.'),
      requirement: z.string().max(20000).optional(),
      overview: z.string().max(20000).optional(),
      clear_fields: z
        .array(z.enum(['start_date', 'estimated_completion_date', 'actual_completion_date',
                       'estimated_hours', 'project_manager_id', 'requirement', 'overview']))
        .optional(),
    },
    guard(async (a: any) => {
      const given = changedFields(a, 'project_id');
      const clear: string[] = a.clear_fields ?? [];
      if (given.length === 0 && clear.length === 0) {
        throw new Error('Pass at least one field to change or clear.');
      }
      // apps replaces wholesale when supplied; null leaves the column alone.
      const apps = a.apps === undefined ? null : await normaliseApps(env, a.apps);
      const rows = await asUser(env, (sql) => sql`
        UPDATE projects SET
          name                      = COALESCE(${a.name ?? null}, name),
          apps_used                 = COALESCE(${apps}::text[], apps_used),
          start_date                = CASE WHEN 'start_date'                = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.start_date ?? null}::date, start_date) END,
          estimated_completion_date = CASE WHEN 'estimated_completion_date' = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.estimated_completion_date ?? null}::date, estimated_completion_date) END,
          actual_completion_date    = CASE WHEN 'actual_completion_date'    = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.actual_completion_date ?? null}::date, actual_completion_date) END,
          estimated_hours           = CASE WHEN 'estimated_hours'           = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.estimated_hours ?? null}, estimated_hours) END,
          project_manager_id        = CASE WHEN 'project_manager_id'        = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.project_manager_id ?? null}::uuid, project_manager_id) END,
          requirement               = CASE WHEN 'requirement'               = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.requirement ?? null}, requirement) END,
          overview                  = CASE WHEN 'overview'                  = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.overview ?? null}, overview) END,
          updated_at = now()
        WHERE id = ${a.project_id}::uuid AND archived_at IS NULL
        RETURNING id, display_id, name, status::text AS status, apps_used,
                  to_char(start_date, 'YYYY-MM-DD') AS start_date,
                  to_char(estimated_completion_date, 'YYYY-MM-DD') AS estimated_completion_date,
                  estimated_hours, project_manager_id
      `);
      if (rows.length === 0) throw new Error('Update not permitted or project not found.');
      return { updated: given, cleared: clear, project: rows[0] };
    }),
  );

  server.tool(
    'update_milestone',
    'Update fields on a milestone. Only what you pass changes.',
    {
      milestone_id: z.string().uuid(),
      name: z.string().min(1).max(300).optional(),
      status: MILESTONE_STATUS.optional(),
      milestone_manager_id: z.string().uuid().optional().describe('Use find_user.'),
      start_date: z.string().optional().describe('YYYY-MM-DD'),
      target_date: z.string().optional().describe('YYYY-MM-DD'),
      actual_completion_date: z.string().optional().describe('YYYY-MM-DD'),
      estimated_hours: z.number().optional(),
      price: z.number().optional(),
      currency: z.string().max(3).optional(),
      clear_fields: z
        .array(z.enum(['milestone_manager_id', 'start_date', 'target_date',
                       'actual_completion_date', 'estimated_hours', 'price', 'currency']))
        .optional(),
    },
    guard(async (a: any) => {
      const given = changedFields(a, 'milestone_id');
      const clear: string[] = a.clear_fields ?? [];
      if (given.length === 0 && clear.length === 0) {
        throw new Error('Pass at least one field to change or clear.');
      }
      const rows = await asUser(env, (sql) => sql`
        UPDATE milestones SET
          name                   = COALESCE(${a.name ?? null}, name),
          status                 = COALESCE(${a.status ?? null}::milestone_status, status),
          milestone_manager_id   = CASE WHEN 'milestone_manager_id'   = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.milestone_manager_id ?? null}::uuid, milestone_manager_id) END,
          start_date             = CASE WHEN 'start_date'             = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.start_date ?? null}::date, start_date) END,
          target_date            = CASE WHEN 'target_date'            = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.target_date ?? null}::date, target_date) END,
          actual_completion_date = CASE WHEN 'actual_completion_date' = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.actual_completion_date ?? null}::date, actual_completion_date) END,
          estimated_hours        = CASE WHEN 'estimated_hours'        = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.estimated_hours ?? null}, estimated_hours) END,
          price                  = CASE WHEN 'price'                  = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.price ?? null}, price) END,
          currency               = CASE WHEN 'currency'               = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.currency ?? null}, currency) END,
          updated_at = now()
        WHERE id = ${a.milestone_id}::uuid AND archived_at IS NULL
        RETURNING id, display_id, name, status::text AS status,
                  to_char(target_date, 'YYYY-MM-DD') AS target_date,
                  estimated_hours, price, currency
      `);
      if (rows.length === 0) throw new Error('Update not permitted or milestone not found.');
      return { updated: given, cleared: clear, milestone: rows[0] };
    }),
  );

  server.tool(
    'update_task',
    'Update fields on a task. Only what you pass changes. For status use set_task_status; for people use the add/remove assignee and manager tools.',
    {
      task_id: z.string().uuid(),
      title: z.string().min(1).max(300).optional(),
      priority: PRIORITY.optional(),
      start_date: z.string().optional().describe('YYYY-MM-DD'),
      plan_due_date: z.string().optional().describe('YYYY-MM-DD'),
      execution_start_date: z.string().optional().describe('YYYY-MM-DD'),
      execution_end_date: z.string().optional().describe('YYYY-MM-DD'),
      estimated_hours: z.number().min(0).max(100000).optional(),
      time_reported_hours: z.number().optional(),
      delivery_state: z.enum(['not_delivered', 'delivered']).optional(),
      loom_url: z.string().max(1000).optional(),
      requirement: z.string().max(20000).optional(),
      details: z.string().max(20000).optional(),
      clear_fields: z
        .array(z.enum(['start_date', 'plan_due_date', 'execution_start_date',
                       'execution_end_date', 'estimated_hours', 'time_reported_hours',
                       'loom_url', 'requirement', 'details']))
        .optional(),
    },
    guard(async (a: any) => {
      const given = changedFields(a, 'task_id');
      const clear: string[] = a.clear_fields ?? [];
      if (given.length === 0 && clear.length === 0) {
        throw new Error('Pass at least one field to change or clear.');
      }
      const rows = await asUser(env, (sql) => sql`
        UPDATE tasks SET
          title                = COALESCE(${a.title ?? null}, title),
          priority             = COALESCE(${a.priority ?? null}::priority, priority),
          delivery_state       = COALESCE(${a.delivery_state ?? null}::task_delivery_state, delivery_state),
          start_date           = CASE WHEN 'start_date'           = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.start_date ?? null}::date, start_date) END,
          plan_due_date        = CASE WHEN 'plan_due_date'        = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.plan_due_date ?? null}::date, plan_due_date) END,
          execution_start_date = CASE WHEN 'execution_start_date' = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.execution_start_date ?? null}::date, execution_start_date) END,
          execution_end_date   = CASE WHEN 'execution_end_date'   = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.execution_end_date ?? null}::date, execution_end_date) END,
          estimated_hours      = CASE WHEN 'estimated_hours'      = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.estimated_hours ?? null}, estimated_hours) END,
          time_reported_hours  = CASE WHEN 'time_reported_hours'  = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.time_reported_hours ?? null}, time_reported_hours) END,
          loom_url             = CASE WHEN 'loom_url'             = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.loom_url ?? null}, loom_url) END,
          requirement          = CASE WHEN 'requirement'          = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.requirement ?? null}, requirement) END,
          details              = CASE WHEN 'details'              = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.details ?? null}, details) END,
          updated_at = now()
        WHERE id = ${a.task_id}::uuid AND archived_at IS NULL
        RETURNING id, display_id, title, status::text AS status, priority::text AS priority,
                  to_char(start_date, 'YYYY-MM-DD') AS start_date,
                  to_char(plan_due_date, 'YYYY-MM-DD') AS plan_due_date,
                  estimated_hours
      `);
      if (rows.length === 0) throw new Error('Update not permitted or task not found.');
      return { updated: given, cleared: clear, task: rows[0] };
    }),
  );

  server.tool(
    'update_payment',
    'Update fields on a payment. Only what you pass changes. For status use set_payment_status.',
    {
      payment_id: z.string().uuid(),
      amount: z.number().optional(),
      currency: z.string().length(3).optional(),
      submitted_amount: z.number().optional(),
      received_amount_inr: z.number().optional(),
      forecast: z.number().optional(),
      payment_type: z.string().optional(),
      payment_date: z.string().optional().describe('YYYY-MM-DD'),
      billing_date: z.string().optional().describe('YYYY-MM-DD'),
      transaction_ref: z.string().max(200).optional(),
      invoice_no: z.string().max(120).optional(),
      note: z.string().max(5000).optional(),
      platform_name: z.string().max(200).optional(),
      billing_type: z.enum(['fixed', 'hourly']).optional(),
      hours_logged: z.number().optional(),
      hourly_rate: z.number().optional(),
      screenshot_url: z.string().max(1000).optional(),
      clear_fields: z
        .array(z.enum(['payment_date', 'billing_date', 'transaction_ref', 'invoice_no',
                       'note', 'platform_name', 'hours_logged', 'hourly_rate',
                       'screenshot_url', 'forecast', 'received_amount_inr', 'payment_type']))
        .optional(),
    },
    guard(async (a: any) => {
      const given = changedFields(a, 'payment_id');
      const clear: string[] = a.clear_fields ?? [];
      if (given.length === 0 && clear.length === 0) {
        throw new Error('Pass at least one field to change or clear.');
      }
      const rows = await asUser(env, (sql) => sql`
        UPDATE payments SET
          amount              = COALESCE(${a.amount ?? null}, amount),
          currency            = COALESCE(${a.currency ?? null}, currency),
          submitted_amount    = COALESCE(${a.submitted_amount ?? null}, submitted_amount),
          billing_type        = COALESCE(${a.billing_type ?? null}, billing_type),
          received_amount_inr = CASE WHEN 'received_amount_inr' = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.received_amount_inr ?? null}, received_amount_inr) END,
          forecast            = CASE WHEN 'forecast'            = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.forecast ?? null}, forecast) END,
          payment_type        = CASE WHEN 'payment_type'        = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.payment_type ?? null}::payment_type, payment_type) END,
          payment_date        = CASE WHEN 'payment_date'        = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.payment_date ?? null}::date, payment_date) END,
          billing_date        = CASE WHEN 'billing_date'        = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.billing_date ?? null}::date, billing_date) END,
          transaction_ref     = CASE WHEN 'transaction_ref'     = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.transaction_ref ?? null}, transaction_ref) END,
          invoice_no          = CASE WHEN 'invoice_no'          = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.invoice_no ?? null}, invoice_no) END,
          note                = CASE WHEN 'note'                = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.note ?? null}, note) END,
          platform_name       = CASE WHEN 'platform_name'       = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.platform_name ?? null}, platform_name) END,
          hours_logged        = CASE WHEN 'hours_logged'        = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.hours_logged ?? null}, hours_logged) END,
          hourly_rate         = CASE WHEN 'hourly_rate'         = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.hourly_rate ?? null}, hourly_rate) END,
          screenshot_url      = CASE WHEN 'screenshot_url'      = ANY(${clear}::text[]) THEN NULL ELSE COALESCE(${a.screenshot_url ?? null}, screenshot_url) END,
          updated_at = now()
        WHERE id = ${a.payment_id}::uuid AND archived_at IS NULL
        RETURNING id, display_id, amount, currency, status::text AS status,
                  to_char(payment_date, 'YYYY-MM-DD') AS payment_date,
                  to_char(billing_date, 'YYYY-MM-DD') AS billing_date,
                  invoice_no, note
      `);
      if (rows.length === 0) throw new Error('Update not permitted or payment not found.');
      return { updated: given, cleared: clear, payment: rows[0] };
    }),
  );

  // =========================================================================
  // STATUS CHANGES
  // =========================================================================
  server.tool(
    'set_task_status',
    'Change a task\'s status. Use get_statuses("task") for the allowed values.',
    {
      task_id: z.string().uuid(),
      status: z.string().min(1),
    },
    guard(async (a: any) => {
      const rows = await asUser(env, (sql) => sql`
        UPDATE tasks
           SET status = ${a.status}::task_status, updated_at = now()
         WHERE id = ${a.task_id}::uuid AND archived_at IS NULL
        RETURNING id, display_id, title, status::text AS status
      `);
      if (rows.length === 0) throw new Error('Update not permitted or task not found.');
      return rows[0];
    }),
  );

  server.tool(
    'set_project_status',
    'Change a project\'s status. Moving to "on_hold" requires on_hold_reason.',
    {
      project_id: z.string().uuid(),
      status: z.string().min(1),
      on_hold_reason: z.string().optional().describe('Required when status is "on_hold".'),
    },
    guard(async (a: any) => {
      const reason = typeof a.on_hold_reason === 'string' ? a.on_hold_reason.trim() : '';
      if (a.status === 'on_hold' && reason === '') {
        throw new Error('A reason is required to put a project on hold.');
      }
      const rows = await asUser(env, (sql) => sql`
        UPDATE projects
           SET status = ${a.status}::project_status,
               on_hold_reason = ${a.status === 'on_hold' ? reason : null},
               updated_at = now()
         WHERE id = ${a.project_id}::uuid AND archived_at IS NULL
        RETURNING id, display_id, name, status::text AS status, on_hold_reason
      `);
      if (rows.length === 0) throw new Error('Update not permitted or project not found.');
      return rows[0];
    }),
  );

  server.tool(
    'set_payment_status',
    'Change a payment\'s status. "received" additionally requires amount and received_amount_inr to be filled in.',
    {
      payment_id: z.string().uuid(),
      status: z.string().min(1),
    },
    guard(async (a: any) => {
      // Mirrors assertReceivable: money-in figures must exist before a payment
      // can be marked received. The DB trigger trg_payment_received_admin is the
      // real gate; this is the clean message.
      if (a.status === 'received') {
        const rows = await asUser<{ amount: string | null; received_amount_inr: string | null }>(
          env,
          (sql) => sql`
            SELECT amount, received_amount_inr FROM payments
            WHERE id = ${a.payment_id}::uuid AND archived_at IS NULL
          `,
        );
        const p = rows[0];
        if (!p || !(Number(p.amount) > 0) || !(Number(p.received_amount_inr) > 0)) {
          throw new Error(
            'Set amount and received_amount_inr before marking this payment as received.',
          );
        }
      }
      const rows = await asUser(env, (sql) => sql`
        UPDATE payments
           SET status = ${a.status}::payment_status, updated_at = now()
         WHERE id = ${a.payment_id}::uuid AND archived_at IS NULL
        RETURNING id, display_id, amount, currency, status::text AS status
      `);
      if (rows.length === 0) throw new Error('Status change not permitted or payment not found.');
      return rows[0];
    }),
  );

  server.tool(
    'set_deal_stage',
    'Move a deal to another stage of its pipeline. Use list_pipelines for stage ids.',
    {
      deal_id: z.string().uuid(),
      stage_id: z.string().uuid(),
    },
    guard(async (a: any) => {
      const rows = await asUser(env, (sql) => sql`
        UPDATE deals d
           SET stage_id = ${a.stage_id}::uuid,
               -- Keep the legacy deal_stage enum in sync when the stage's NAME is
               -- a valid enum label; leave it alone for custom-pipeline stages.
               stage = COALESCE(
                 (SELECT ps.name::deal_stage
                    FROM pipeline_stages ps
                    JOIN pg_enum e ON e.enumlabel = ps.name
                    JOIN pg_type t ON t.oid = e.enumtypid AND t.typname = 'deal_stage'
                   WHERE ps.id = ${a.stage_id}::uuid),
                 d.stage
               ),
               updated_at = now()
         WHERE d.id = ${a.deal_id}::uuid
           AND d.archived_at IS NULL
           -- The stage must belong to THIS deal's pipeline.
           AND EXISTS (
             SELECT 1 FROM pipeline_stages ps
             WHERE ps.id = ${a.stage_id}::uuid
               AND ps.pipeline_id = d.pipeline_id
               AND ps.archived_at IS NULL
           )
        RETURNING id, display_id, name, stage::text AS stage, stage_id, pipeline_id
      `);
      if (rows.length === 0) {
        throw new Error(
          'Move not permitted, deal not found, or that stage does not belong to the deal\'s pipeline.',
        );
      }
      return rows[0];
    }),
  );

  // =========================================================================
  // READS
  // =========================================================================
  server.tool(
    'list_tasks',
    'List tasks with their project, milestone, client, assignees and managers. All filters optional.',
    {
      assignee_id: z.string().uuid().optional().describe('Tasks assigned to this user.'),
      manager_id: z.string().uuid().optional().describe('Tasks this user manages.'),
      created_by: z
        .string()
        .uuid()
        .optional()
        .describe('Tasks created by this user - use find_user. Matches the created_by column.'),
      project_id: z.string().uuid().optional(),
      milestone_id: z.string().uuid().optional(),
      status: optArray(z.array(z.string())),
      due_before: z.string().optional().describe('plan_due_date <= YYYY-MM-DD'),
      search: z.string().max(200).optional().describe('Matches title or display id.'),
      include_management: z.boolean().default(false).describe('Include management-stream tasks.'),
      full: z
        .boolean()
        .default(false)
        .describe(
          'Return the complete field feed per task (requirement, details, delivery state, execution dates, reported hours, loom url, spine ids and timestamps) instead of the summary columns. Off by default because requirement/details can be very large across many rows.',
        ),
      limit: z.number().int().min(1).max(500).default(100),
    },
    guard(async (a: any) => {
      const statuses = a.status?.length ? a.status : null;
      const full = a.full === true;
      const search = a.search ? `%${a.search}%` : null;
      return asUser(env, (sql) => sql`
        SELECT t.id, t.display_id, t.title,
               t.status::text AS status, t.priority::text AS priority,
               t.start_date::text AS start_date,
               t.plan_due_date::text AS plan_due_date,
               t.estimated_hours, t.is_management,
               -- Always present now: WHO created the task. The column existed
               -- on the row all along; this tool simply never selected it.
               t.created_by, cu.full_name AS created_by_name,
               -- The remainder of the feed, only when full=true. A CASE keeps
               -- this to ONE statement instead of branching the whole query.
               CASE WHEN ${full}::boolean THEN t.requirement END AS requirement,
               CASE WHEN ${full}::boolean THEN t.details END AS details,
               CASE WHEN ${full}::boolean THEN t.delivery_state::text END AS delivery_state,
               CASE WHEN ${full}::boolean THEN t.primary_pm_id END AS primary_pm_id,
               CASE WHEN ${full}::boolean THEN pm.full_name END AS primary_pm_name,
               CASE WHEN ${full}::boolean THEN t.execution_start_date::text END AS execution_start_date,
               CASE WHEN ${full}::boolean THEN t.execution_end_date::text END AS execution_end_date,
               CASE WHEN ${full}::boolean THEN t.time_reported_hours END AS time_reported_hours,
               CASE WHEN ${full}::boolean THEN t.loom_url END AS loom_url,
               CASE WHEN ${full}::boolean THEN t.ai_created END AS ai_created,
               CASE WHEN ${full}::boolean THEN t.parent_type::text END AS parent_type,
               CASE WHEN ${full}::boolean THEN t.parent_id END AS parent_id,
               CASE WHEN ${full}::boolean THEN t.contact_id END AS contact_id,
               CASE WHEN ${full}::boolean THEN t.company_id END AS company_id,
               CASE WHEN ${full}::boolean THEN t.status_changed_at END AS status_changed_at,
               CASE WHEN ${full}::boolean THEN t.created_at END AS created_at,
               CASE WHEN ${full}::boolean THEN t.updated_at END AS updated_at,
               p.id AS project_id, p.name AS project_name,
               m.id AS milestone_id, m.name AS milestone_name,
               c.full_name AS client_name,
               COALESCE((
                 SELECT jsonb_agg(jsonb_build_object('user_id', u.id, 'name', u.full_name))
                 FROM task_assignees ta JOIN users u ON u.id = ta.user_id
                 WHERE ta.task_id = t.id
               ), '[]'::jsonb) AS assignees,
               COALESCE((
                 SELECT jsonb_agg(jsonb_build_object('user_id', u.id, 'name', u.full_name))
                 FROM task_managers tm JOIN users u ON u.id = tm.user_id
                 WHERE tm.task_id = t.id
               ), '[]'::jsonb) AS managers
        FROM tasks t
        LEFT JOIN projects p   ON p.id = t.project_id
        LEFT JOIN milestones m ON m.id = t.milestone_id
        LEFT JOIN contacts c   ON c.id = t.contact_id
        LEFT JOIN users cu     ON cu.id = t.created_by
        LEFT JOIN users pm     ON pm.id = t.primary_pm_id
        WHERE t.archived_at IS NULL
          AND (${a.include_management === true}::boolean = true OR t.is_management = false)
          AND (${a.project_id ?? null}::uuid IS NULL OR t.project_id = ${a.project_id ?? null}::uuid)
          AND (${a.milestone_id ?? null}::uuid IS NULL OR t.milestone_id = ${a.milestone_id ?? null}::uuid)
          AND (${statuses}::text[] IS NULL OR t.status::text = ANY(${statuses}::text[]))
          AND (${a.due_before ?? null}::date IS NULL OR t.plan_due_date <= ${a.due_before ?? null}::date)
          AND (${search}::text IS NULL OR t.title ILIKE ${search} OR t.display_id ILIKE ${search})
          AND (
            ${a.assignee_id ?? null}::uuid IS NULL
            OR EXISTS (SELECT 1 FROM task_assignees ta
                       WHERE ta.task_id = t.id AND ta.user_id = ${a.assignee_id ?? null}::uuid)
          )
          AND (
            ${a.manager_id ?? null}::uuid IS NULL
            OR EXISTS (SELECT 1 FROM task_managers tm
                       WHERE tm.task_id = t.id AND tm.user_id = ${a.manager_id ?? null}::uuid)
          )
          AND (${a.created_by ?? null}::uuid IS NULL OR t.created_by = ${a.created_by ?? null}::uuid)
        ORDER BY t.plan_due_date NULLS LAST, t.created_at DESC
        LIMIT ${a.limit ?? 100}
      `);
    }),
  );

  server.tool(
    'get_record',
    'Fetch one record in full by id.',
    {
      entity: z.enum(['company', 'contact', 'deal', 'project', 'milestone', 'task', 'payment']),
      id: z.string().uuid(),
    },
    guard(async (a: any) => {
      const id = a.id;
      let rows: Record<string, unknown>[];
      switch (a.entity) {
        case 'company':
          rows = await asUser(env, (sql) => sql`
            SELECT c.*, u.full_name AS account_owner_name,
                   (SELECT count(*)::int FROM contacts ct
                     WHERE ct.company_id = c.id AND ct.archived_at IS NULL) AS contact_count
            FROM companies c LEFT JOIN users u ON u.id = c.account_owner_id
            WHERE c.id = ${id}::uuid`);
          break;
        case 'contact':
          rows = await asUser(env, (sql) => sql`
            SELECT c.*, co.name AS company_name
            FROM contacts c LEFT JOIN companies co ON co.id = c.company_id
            WHERE c.id = ${id}::uuid`);
          break;
        case 'deal':
          rows = await asUser(env, (sql) => sql`
            SELECT d.*, to_char(d.close_date, 'YYYY-MM-DD') AS close_date,
                   c.full_name AS contact_name, pl.name AS pipeline_name, ps.name AS stage_name
            FROM deals d
            LEFT JOIN contacts c        ON c.id = d.contact_id
            LEFT JOIN pipelines pl      ON pl.id = d.pipeline_id
            LEFT JOIN pipeline_stages ps ON ps.id = d.stage_id
            WHERE d.id = ${id}::uuid`);
          break;
        case 'project':
          rows = await asUser(env, (sql) => sql`
            SELECT p.*,
                   to_char(p.start_date, 'YYYY-MM-DD')                AS start_date,
                   to_char(p.estimated_completion_date, 'YYYY-MM-DD') AS estimated_completion_date,
                   to_char(p.actual_completion_date, 'YYYY-MM-DD')    AS actual_completion_date,
                   c.full_name AS client_name, d.name AS deal_name
            FROM projects p
            LEFT JOIN contacts c ON c.id = p.contact_id
            LEFT JOIN deals d    ON d.id = p.deal_id
            WHERE p.id = ${id}::uuid`);
          break;
        case 'milestone':
          rows = await asUser(env, (sql) => sql`
            SELECT m.*,
                   to_char(m.start_date, 'YYYY-MM-DD')             AS start_date,
                   to_char(m.target_date, 'YYYY-MM-DD')            AS target_date,
                   to_char(m.actual_completion_date, 'YYYY-MM-DD') AS actual_completion_date,
                   p.name AS project_name
            FROM milestones m LEFT JOIN projects p ON p.id = m.project_id
            WHERE m.id = ${id}::uuid`);
          break;
        case 'task':
          // t.* already carried created_by; what was missing is the creator's
          // NAME and the assignee/manager relations. A single task fetch is now
          // the complete feed, with no follow-up calls needed.
          rows = await asUser(env, (sql) => sql`
            SELECT t.*,
                   to_char(t.start_date, 'YYYY-MM-DD')           AS start_date,
                   to_char(t.plan_due_date, 'YYYY-MM-DD')        AS plan_due_date,
                   to_char(t.execution_start_date, 'YYYY-MM-DD') AS execution_start_date,
                   to_char(t.execution_end_date, 'YYYY-MM-DD')   AS execution_end_date,
                   p.name AS project_name, m.name AS milestone_name, c.full_name AS client_name,
                   cu.full_name AS created_by_name,
                   pm.full_name AS primary_pm_name,
                   COALESCE((
                     SELECT jsonb_agg(jsonb_build_object('user_id', u.id, 'name', u.full_name))
                     FROM task_assignees ta JOIN users u ON u.id = ta.user_id
                     WHERE ta.task_id = t.id
                   ), '[]'::jsonb) AS assignees,
                   COALESCE((
                     SELECT jsonb_agg(jsonb_build_object('user_id', u.id, 'name', u.full_name))
                     FROM task_managers tm JOIN users u ON u.id = tm.user_id
                     WHERE tm.task_id = t.id
                   ), '[]'::jsonb) AS managers
            FROM tasks t
            LEFT JOIN projects p   ON p.id = t.project_id
            LEFT JOIN milestones m ON m.id = t.milestone_id
            LEFT JOIN contacts c   ON c.id = t.contact_id
            LEFT JOIN users cu     ON cu.id = t.created_by
            LEFT JOIN users pm     ON pm.id = t.primary_pm_id
            WHERE t.id = ${id}::uuid`);
          break;
        default:
          rows = await asUser(env, (sql) => sql`
            SELECT p.*,
                   to_char(p.billing_date, 'YYYY-MM-DD') AS billing_date,
                   to_char(p.payment_date, 'YYYY-MM-DD') AS payment_date,
                   d.name AS deal_name, c.full_name AS contact_name
            FROM payments p
            LEFT JOIN deals d    ON d.id = p.deal_id
            LEFT JOIN contacts c ON c.id = p.contact_id
            WHERE p.id = ${id}::uuid`);
      }
      // Not-found and RLS-denied are deliberately indistinguishable.
      return rows[0] ?? null;
    }),
  );

  // =========================================================================
  // ARCHIVE — the OS never hard-deletes. "Delete" sets archived_at, and the
  // reason is written to the audit row via the app.audit_reason GUC.
  // =========================================================================
  server.tool(
    'archive_record',
    'Archive ("delete") a record. Nothing is ever hard-deleted; this sets archived_at and records the reason in the audit log. Archive children before parents.',
    {
      entity: z.enum(['company', 'contact', 'deal', 'project', 'milestone', 'task', 'payment']),
      id: z.string().uuid(),
      reason: z.string().trim().min(3).max(1000).describe('Required, 3-1000 chars. Goes on the audit row.'),
    },
    guard(async (a: any) => {
      const id = a.id;
      const why = String(a.reason).trim();
      let rows: Record<string, unknown>[];
      switch (a.entity) {
        case 'company':
          rows = await asUserWithReason(env, why, (sql) => sql`
            UPDATE companies SET archived_at = now(), updated_at = now()
            WHERE id = ${id}::uuid AND archived_at IS NULL
            RETURNING id, display_id, archived_at`);
          break;
        case 'contact':
          rows = await asUserWithReason(env, why, (sql) => sql`
            UPDATE contacts SET archived_at = now(), updated_at = now()
            WHERE id = ${id}::uuid AND archived_at IS NULL
            RETURNING id, display_id, archived_at`);
          break;
        case 'deal':
          rows = await asUserWithReason(env, why, (sql) => sql`
            UPDATE deals SET archived_at = now(), updated_at = now()
            WHERE id = ${id}::uuid AND archived_at IS NULL
            RETURNING id, display_id, archived_at`);
          break;
        case 'project':
          rows = await asUserWithReason(env, why, (sql) => sql`
            UPDATE projects SET archived_at = now(), updated_at = now()
            WHERE id = ${id}::uuid AND archived_at IS NULL
            RETURNING id, display_id, archived_at`);
          break;
        case 'milestone':
          rows = await asUserWithReason(env, why, (sql) => sql`
            UPDATE milestones SET archived_at = now(), updated_at = now()
            WHERE id = ${id}::uuid AND archived_at IS NULL
            RETURNING id, display_id, archived_at`);
          break;
        case 'task':
          rows = await asUserWithReason(env, why, (sql) => sql`
            UPDATE tasks SET archived_at = now(), updated_at = now()
            WHERE id = ${id}::uuid AND archived_at IS NULL
            RETURNING id, display_id, archived_at`);
          break;
        default:
          rows = await asUserWithReason(env, why, (sql) => sql`
            UPDATE payments SET archived_at = now(), updated_at = now()
            WHERE id = ${id}::uuid AND archived_at IS NULL
            RETURNING id, display_id, archived_at`);
      }
      if (rows.length === 0) {
        throw new Error('Archive not permitted, record not found, or already archived.');
      }
      return { archived: a.entity, ...rows[0] };
    }),
  );

  // =========================================================================
  // ASSIGNMENT — ownership is always a join table, never a single FK.
  // Removing a row from a join table is the ONE sanctioned DELETE in the OS.
  // =========================================================================
  server.tool(
    'add_task_assignee',
    'Assign a user to a task (who does the work). Idempotent.',
    { task_id: z.string().uuid(), user_id: z.string().uuid() },
    guard(async (a: any) => {
      const rows = await asUser(env, (sql) => sql`
        INSERT INTO task_assignees (task_id, user_id)
        VALUES (${a.task_id}::uuid, ${a.user_id}::uuid)
        ON CONFLICT (task_id, user_id) DO NOTHING
        RETURNING id, task_id, user_id, created_at`);
      return rows[0] ?? { already_assigned: true };
    }),
  );

  server.tool(
    'remove_task_assignee',
    'Unassign a user from a task.',
    { task_id: z.string().uuid(), user_id: z.string().uuid() },
    guard(async (a: any) => {
      const rows = await asUser(env, (sql) => sql`
        DELETE FROM task_assignees
        WHERE task_id = ${a.task_id}::uuid AND user_id = ${a.user_id}::uuid
        RETURNING id`);
      return { removed: rows.length > 0 };
    }),
  );

  server.tool(
    'add_task_manager',
    'Add a manager to a task (who oversees it). Idempotent.',
    { task_id: z.string().uuid(), user_id: z.string().uuid() },
    guard(async (a: any) => {
      const rows = await asUser(env, (sql) => sql`
        INSERT INTO task_managers (task_id, user_id)
        VALUES (${a.task_id}::uuid, ${a.user_id}::uuid)
        ON CONFLICT (task_id, user_id) DO NOTHING
        RETURNING id, task_id, user_id, created_at`);
      return rows[0] ?? { already_a_manager: true };
    }),
  );

  server.tool(
    'remove_task_manager',
    'Remove a manager from a task.',
    { task_id: z.string().uuid(), user_id: z.string().uuid() },
    guard(async (a: any) => {
      const rows = await asUser(env, (sql) => sql`
        DELETE FROM task_managers
        WHERE task_id = ${a.task_id}::uuid AND user_id = ${a.user_id}::uuid
        RETURNING id`);
      return { removed: rows.length > 0 };
    }),
  );

  server.tool(
    'add_project_member',
    'Add a user to a project team as pm or developer. Idempotent.',
    {
      project_id: z.string().uuid(),
      user_id: z.string().uuid(),
      role: z.enum(['pm', 'developer']),
    },
    guard(async (a: any) => {
      const rows = await asUser(env, (sql) => sql`
        INSERT INTO project_members (project_id, user_id, role)
        VALUES (${a.project_id}::uuid, ${a.user_id}::uuid, ${a.role}::user_role)
        ON CONFLICT (project_id, user_id) DO NOTHING
        RETURNING id, project_id, user_id, role::text AS role, created_at`);
      return rows[0] ?? { already_a_member: true };
    }),
  );

  server.tool(
    'remove_project_member',
    'Remove a user from a project team.',
    { project_id: z.string().uuid(), user_id: z.string().uuid() },
    guard(async (a: any) => {
      const rows = await asUser(env, (sql) => sql`
        DELETE FROM project_members
        WHERE project_id = ${a.project_id}::uuid AND user_id = ${a.user_id}::uuid
        RETURNING id`);
      return { removed: rows.length > 0 };
    }),
  );

  server.tool(
    'set_contact_owner',
    'Set who owns a contact. Writes the authoritative contact_owners join row and updates the cached header pointer.',
    { contact_id: z.string().uuid(), user_id: z.string().uuid() },
    guard(async (a: any) => {
      const rows = await asUserMany(env, (sql) => [
        sql`
          INSERT INTO contact_owners (contact_id, user_id)
          VALUES (${a.contact_id}::uuid, ${a.user_id}::uuid)
          ON CONFLICT (contact_id, user_id) DO NOTHING
        `,
        sql`
          UPDATE contacts SET primary_owner_id = ${a.user_id}::uuid, updated_at = now()
          WHERE id = ${a.contact_id}::uuid AND archived_at IS NULL
          RETURNING id, display_id, full_name, primary_owner_id
        `,
      ]);
      if (rows.length === 0) throw new Error('Update not permitted or contact not found.');
      return rows[0];
    }),
  );

  // =========================================================================
  // ATTACHMENTS — polymorphic (parent_type, parent_id), one table for every
  // entity. RLS gates the insert on fn_can_edit of the PARENT record.
  // =========================================================================
  server.tool(
    'add_attachment',
    'Attach a file or link to any record. For a file, pass file_base64 and the MCP stores the contents; for a link, just pass the url.',
    {
      parent_type: z.enum(['company', 'contact', 'deal', 'project', 'milestone', 'task', 'payment']),
      parent_id: z.string().uuid(),
      title: z.string().min(1).max(300).describe('Display name, e.g. "Signed contract.pdf".'),
      url: z
        .string()
        .max(2000)
        .optional()
        .describe('Required for a link. For an uploaded file this is a label such as the filename.'),
      file_base64: z
        .string()
        .optional()
        .describe('Base64 file contents. Supplying this makes it kind="file" and stores the bytes.'),
      mime_type: z.string().max(200).optional(),
      purpose: z
        .string()
        .max(200)
        .optional()
        .describe('Free-text tag, e.g. requirement, signed_contract, proof_of_payment.'),
    },
    guard(async (a: any) => {
      const isFile = typeof a.file_base64 === 'string' && a.file_base64.length > 0;
      if (!isFile && !a.url) {
        throw new Error('Pass url for a link, or file_base64 for a file.');
      }
      const attachmentId = crypto.randomUUID();
      const sizeBytes = isFile ? Math.floor((a.file_base64.length * 3) / 4) : null;

      // TWO statements, one transaction: the attachment_blobs INSERT policy does
      // `EXISTS (SELECT 1 FROM attachments …)`, which cannot see a row inserted
      // by the SAME statement. Splitting them makes the parent visible to the
      // blob's policy check while keeping both atomic.
      const queries = (sql: any) => {
        const out = [
          sql`
            INSERT INTO attachments (
              id, parent_type, parent_id, kind, title, url,
              mime_type, size_bytes, purpose, uploaded_by
            )
            VALUES (
              ${attachmentId}::uuid,
              ${a.parent_type}::entity_type,
              ${a.parent_id}::uuid,
              ${isFile ? 'file' : 'link'}::attachment_kind,
              ${a.title},
              ${a.url ?? a.title},
              ${a.mime_type ?? null},
              ${sizeBytes},
              ${a.purpose ?? null},
              ${actorUid(env)}::uuid
            )
          `,
        ];
        if (isFile) {
          out.push(sql`
            INSERT INTO attachment_blobs (attachment_id, data_base64)
            VALUES (${attachmentId}::uuid, ${a.file_base64})
          `);
        }
        out.push(sql`SELECT id FROM attachments WHERE id = ${attachmentId}::uuid`);
        return out;
      };

      const rows = await asUserMany(env, queries);
      if (rows.length === 0) {
        throw new Error('Not permitted to attach to that record, or the record does not exist.');
      }
      return {
        id: attachmentId,
        parent_type: a.parent_type,
        parent_id: a.parent_id,
        kind: isFile ? 'file' : 'link',
        title: a.title,
        size_bytes: sizeBytes,
      };
    }),
  );

  server.tool(
    'list_attachments',
    'List the files and links attached to a record.',
    {
      parent_type: z.enum(['company', 'contact', 'deal', 'project', 'milestone', 'task', 'payment']),
      parent_id: z.string().uuid(),
    },
    guard(async (a: any) =>
      // Deliberately does NOT return data_base64 — file contents are fetched
      // one at a time in the app, never dumped into a list response.
      asUser(env, (sql) => sql`
        SELECT at.id, at.kind::text AS kind, at.title, at.url, at.mime_type,
               at.size_bytes, at.purpose, at.created_at,
               u.full_name AS uploaded_by_name
        FROM attachments at
        LEFT JOIN users u ON u.id = at.uploaded_by
        WHERE at.parent_type = ${a.parent_type}::entity_type
          AND at.parent_id = ${a.parent_id}::uuid
          AND at.archived_at IS NULL
        ORDER BY at.created_at DESC
      `),
    ),
  );

  // =========================================================================
  // CREDENTIALS — METADATA ONLY.
  //
  // 🚨 There is deliberately NO tool that returns a credential secret.
  // `credentials.secret_ref` is encrypted at rest and the column is REVOKED
  // from every app role (migration 0005: REVOKE SELECT (secret_ref) … FROM
  // PUBLIC). Plaintext is readable only through the OS's reveal_credential
  // action, which runs as a service role and writes to credential_access_log
  // BEFORE decrypting. Exposing that here would need the service role — which
  // is exactly the escalation the design prevents — and would put client
  // passwords into chat transcripts. Metadata answers the real question
  // ("do we have access to their Shopify?") without ever holding a secret.
  // =========================================================================
  server.tool(
    'get_credentials',
    'List credential RECORDS for a client or project — label, login URL, username, whether we have access. Never returns passwords; reveal those in the OS app.',
    {
      parent_type: z.enum(['contact', 'project', 'milestone']),
      parent_id: z.string().uuid(),
    },
    guard(async (a: any) => {
      const rows = await asUser(env, (sql) => sql`
        SELECT c.id, c.label, c.login_url, c.username,
               c.two_factor_enabled, c.two_factor_destination,
               c.we_have_account_access, c.our_access_account,
               c.client_credentials_available, c.notes, c.created_at,
               ct.full_name AS contact_name, ct.display_id AS contact_display_id
        FROM credentials c
        LEFT JOIN contacts ct ON ct.id = c.contact_id
        WHERE c.archived_at IS NULL
          AND (
            (${a.parent_type}::text = 'contact' AND c.contact_id = ${a.parent_id}::uuid)
            OR EXISTS (
              SELECT 1 FROM credential_links cl
              WHERE cl.credential_id = c.id
                AND cl.parent_type = ${a.parent_type}::entity_type
                AND cl.parent_id = ${a.parent_id}::uuid
            )
          )
        ORDER BY c.label
      `);
      return {
        count: rows.length,
        note: 'Secrets are not available through this MCP by design. Reveal them in the GrowwStacks OS app, where the access is logged.',
        credentials: rows,
      };
    }),
  );

  // =========================================================================
  // LOOKUPS — supply the ids the create tools require.
  // =========================================================================
  server.tool(
    'list_pipelines',
    'List sales pipelines with their stages. Needed before create_deal.',
    {},
    guard(async () =>
      asUser(env, (sql) => sql`
        SELECT p.id AS pipeline_id, p.name AS pipeline_name,
               s.id AS stage_id, s.name AS stage_name, s.sort_order
        FROM pipelines p
        LEFT JOIN pipeline_stages s ON s.pipeline_id = p.id AND s.archived_at IS NULL
        WHERE p.archived_at IS NULL
        ORDER BY p.name, s.sort_order
      `),
    ),
  );

  server.tool(
    'list_apps',
    'The controlled vocabulary of apps/tools a project can be tagged with. Call before create_project so you offer the user real options.',
    {},
    guard(async () =>
      asUser(env, (sql) => sql`
        SELECT id, name FROM project_app_catalog
        WHERE archived_at IS NULL ORDER BY name
      `),
    ),
  );

  server.tool(
    'search_contacts',
    'Find contacts by name, email, display id or phone.',
    {
      query: z.string().min(1).max(200),
      limit: z.number().int().min(1).max(100).default(20),
    },
    guard(async (a: any) => {
      const like = `%${a.query}%`;
      // Digits-only suffix match so "9107333777" finds "+91 9107333777".
      // NOTE the doubled backslash: '\\D' in TS produces the SQL literal '\D'.
      const digits = String(a.query).replace(/\D/g, '');
      const phone = digits.length >= 7 ? digits : null;
      return asUser(env, (sql) => sql`
        SELECT c.id, c.display_id, c.full_name, c.email, c.phone,
               c.status::text AS status, co.name AS company_name
        FROM contacts c
        LEFT JOIN companies co ON co.id = c.company_id
        WHERE c.archived_at IS NULL
          AND (
            c.full_name ILIKE ${like}
            OR c.email ILIKE ${like}
            OR c.display_id ILIKE ${like}
            OR (
              ${phone}::text IS NOT NULL
              AND regexp_replace(COALESCE(c.phone, ''), '\\D', '', 'g') LIKE '%' || ${phone}::text
            )
          )
        ORDER BY c.created_at DESC
        LIMIT ${a.limit ?? 20}
      `);
    }),
  );

  server.tool(
    'find_user',
    'Find team members by name, email or role. Use it to get the user id for an owner, manager or assignee.',
    {
      query: z.string().max(200).optional().describe('Matches name, email or display id.'),
      role: z
        .string()
        .optional()
        .describe('Exact role filter, e.g. "developer", "pm", "sales", "admin", "finance".'),
      limit: z.number().int().min(1).max(200).default(50),
    },
    guard(async (a: any) => {
      const q = a.query ? `%${a.query}%` : null;
      const role = a.role ?? null;
      return asUser(env, (sql) => sql`
        SELECT u.id, u.display_id, u.full_name, u.email,
               u.role::text AS role, u.status::text AS status
        FROM users u
        WHERE u.archived_at IS NULL
          AND u.status <> 'left_org'
          AND (${role}::text IS NULL OR u.role::text = ${role}::text)
          AND (
            ${q}::text IS NULL
            OR u.full_name ILIKE ${q}
            OR u.email ILIKE ${q}
            OR u.display_id ILIKE ${q}
          )
        ORDER BY u.full_name
        LIMIT ${a.limit ?? 50}
      `);
    }),
  );

  server.tool(
    'find_deal',
    'Find deals by name or display id. Needed before create_payment.',
    {
      query: z.string().min(1).max(200),
      limit: z.number().int().min(1).max(100).default(20),
    },
    guard(async (a: any) => {
      const like = `%${a.query}%`;
      return asUser(env, (sql) => sql`
        SELECT d.id, d.display_id, d.name, d.stage::text AS stage,
               d.deal_value, d.currency, d.pipeline_id, d.stage_id,
               c.id AS contact_id, c.full_name AS contact_name
        FROM deals d
        LEFT JOIN contacts c ON c.id = d.contact_id
        WHERE d.archived_at IS NULL
          AND (d.name ILIKE ${like} OR d.display_id ILIKE ${like})
        ORDER BY d.created_at DESC
        LIMIT ${a.limit ?? 20}
      `);
    }),
  );

  server.tool(
    'find_project',
    'Find projects by name or display id.',
    {
      query: z.string().min(1).max(200),
      limit: z.number().int().min(1).max(100).default(20),
    },
    guard(async (a: any) => {
      const like = `%${a.query}%`;
      return asUser(env, (sql) => sql`
        SELECT p.id, p.display_id, p.name, p.status::text AS status,
               p.start_date::text AS start_date, p.deal_id,
               c.full_name AS client_name
        FROM projects p
        LEFT JOIN contacts c ON c.id = p.contact_id
        WHERE p.archived_at IS NULL
          AND (p.name ILIKE ${like} OR p.display_id ILIKE ${like})
        ORDER BY p.created_at DESC
        LIMIT ${a.limit ?? 20}
      `);
    }),
  );

  server.tool(
    'find_milestone',
    'Find milestones, optionally within one project. Needed before create_task (parent_id).',
    {
      query: z.string().max(200).optional(),
      project_id: z.string().uuid().optional(),
      limit: z.number().int().min(1).max(100).default(20),
    },
    guard(async (a: any) => {
      const q = a.query ? `%${a.query}%` : null;
      const projectId = a.project_id ?? null;
      return asUser(env, (sql) => sql`
        SELECT m.id, m.display_id, m.name, m.status::text AS status,
               m.project_id, p.name AS project_name
        FROM milestones m
        LEFT JOIN projects p ON p.id = m.project_id
        WHERE m.archived_at IS NULL
          AND (${projectId}::uuid IS NULL OR m.project_id = ${projectId}::uuid)
          AND (${q}::text IS NULL OR m.name ILIKE ${q} OR m.display_id ILIKE ${q})
        ORDER BY p.name, m.created_at
        LIMIT ${a.limit ?? 20}
      `);
    }),
  );
}
