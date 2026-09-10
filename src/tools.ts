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

/** Wrap a handler so a thrown DB/RLS error becomes a readable tool error. */
function guard<T>(fn: (args: T) => Promise<unknown>) {
  return async (args: T) => {
    try {
      return ok(await fn(args));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
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
  // 1. CREATE CONTACT
  // =========================================================================
  server.tool(
    'create_contact',
    'Create a contact (the CRM hub record) and its ownership row. ASK THE USER for status and owner if they have not said — never guess them.',
    {
      full_name: z.string().min(1).max(300).describe('Required. Full name of the person.'),
      status: CONTACT_STATUS.describe(
        'REQUIRED. The contact type. If the user has not said which, ASK THEM — do not default to prospect.',
      ),
      primary_owner_id: z
        .string()
        .uuid()
        .describe(
          'REQUIRED. The user who owns this contact. If the user has not named an owner, ASK THEM, then use find_user to get the id. Do not silently assign it to the MCP system account.',
        ),
      email: z.string().email().max(300).optional(),
      phone: z.string().max(50).optional(),
      company_id: z.string().uuid().optional().describe('Optional parent company.'),
    },
    guard(async (a: any) => {
      const ownerId = a.primary_owner_id ?? actorUid(env);
      const rows = await asUser(env, (sql) => sql`
        WITH new_contact AS (
          INSERT INTO contacts (full_name, email, phone, company_id, status, primary_owner_id)
          VALUES (
            ${a.full_name},
            ${a.email ?? null},
            ${a.phone ?? null},
            ${a.company_id ?? null},
            COALESCE(${a.status ?? null}::contact_status, 'prospect'::contact_status),
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
      deal_value: z
        .number()
        .describe('REQUIRED. The deal amount. If the user has not given one, ASK THEM.'),
      currency: z
        .string()
        .length(3)
        .describe('REQUIRED. 3-letter code, e.g. "USD" or "INR". If not given, ASK THE USER.'),
      source: z
        .string()
        .max(200)
        .optional()
        .describe(
          'Where the lead came from, e.g. "LinkedIn", "Upwork", "Referral". NEVER invent or infer this. Ask the user, and if they do not know, leave it out entirely.',
        ),
      initial_deal_amount: z.number().optional(),
      payment_type: z.string().optional(),
      close_date: z.string().optional().describe('YYYY-MM-DD'),
      lead_type: z.string().max(200).optional().describe('e.g. "Inbound", "Outbound". Do not invent.'),
      primary_owner_id: z.string().uuid().optional().describe('Deal owner; use find_user.'),
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

      const ownerId = a.primary_owner_id ?? actorUid(env);
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
            ${a.deal_value ?? null},
            ${a.initial_deal_amount ?? null},
            ${a.currency ?? null},
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
            ${a.close_date ?? null}::date,
            ${ownerId},
            ${a.pipeline_id}::uuid,
            ${stageId}::uuid,
            ${a.lead_type || null},
            ${a.source || null}
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
      apps: z
        .array(z.string())
        .describe(
          'REQUIRED. Apps/tools this project uses, from the list_apps catalog (e.g. ["Monday.com","n8n"]). ASK THE USER if they have not said. Pass [] only if they confirm none apply.',
        ),
      deal_id: z.string().uuid().optional().describe('Omit for internal projects.'),
      status: z.string().optional().describe('project_status; defaults to "upcoming". See get_statuses.'),
      start_date: z.string().optional().describe('YYYY-MM-DD'),
      estimated_completion_date: z.string().optional().describe('YYYY-MM-DD'),
      estimated_hours: z.number().optional(),
      project_manager_id: z.string().uuid().optional().describe('Use find_user.'),
    },
    guard(async (a: any) => {
      // Normalise the app names to the catalog's canonical casing. Unlike the OS
      // UI, which silently drops unknown entries, we REJECT them and list what is
      // valid — a silent drop would lose data the caller thought it had set.
      const apps = await normaliseApps(env, Array.isArray(a.apps) ? a.apps : []);

      const rows = await asUser(env, (sql) => sql`
        INSERT INTO projects (
          name, deal_id, status, start_date,
          estimated_completion_date, estimated_hours, project_manager_id, apps_used
        )
        VALUES (
          ${a.name},
          ${a.deal_id ?? null},
          COALESCE(${a.status ?? null}::project_status, 'upcoming'::project_status),
          ${a.start_date ?? null}::date,
          ${a.estimated_completion_date ?? null}::date,
          ${a.estimated_hours ?? null},
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
    'Create a task under a milestone (or a deal/payment). ASK THE USER for priority, project manager, assignee, start date, due date and estimated hours if any are missing — never guess them.',
    {
      title: z.string().min(1).max(300),
      parent_id: z.string().uuid().describe('Usually a milestone id — see find_milestone.'),
      parent_type: z.enum(['milestone', 'deal', 'payment']).default('milestone'),
      priority: PRIORITY.describe('REQUIRED. If the user has not said, ASK THEM — do not default to medium.'),
      manager_ids: z
        .array(z.string().uuid())
        .min(1)
        .describe(
          'REQUIRED. The project manager(s) overseeing this task. If the user has not named one, ASK THEM, then use find_user. The first id also becomes the cached primary PM.',
        ),
      assignee_ids: z
        .array(z.string().uuid())
        .min(1)
        .describe(
          'REQUIRED. Who will do the work. If the user has not named anyone, ASK THEM, then use find_user.',
        ),
      start_date: z
        .string()
        .describe('REQUIRED. YYYY-MM-DD. If the user has not given a start date, ASK THEM.'),
      plan_due_date: z
        .string()
        .describe('REQUIRED. YYYY-MM-DD. If the user has not given a due date, ASK THEM.'),
      estimated_hours: z
        .number()
        .min(0)
        .max(100000)
        .describe('REQUIRED. Estimated effort in hours. If the user has not given one, ASK THEM.'),
      status: z.string().optional().describe('task_status; defaults to "todo". See get_statuses.'),
    },
    guard(async (a: any) => {
      const taskId = crypto.randomUUID();
      const managerIds: string[] = a.manager_ids ?? [];
      const assigneeIds: string[] = a.assignee_ids ?? [];

      // Insert WITHOUT RETURNING, then SELECT back in the same transaction: the
      // tasks SELECT policy (fn_can_see) is self-referential, so the new row is
      // invisible to RETURNING and the insert is rejected even for an admin.
      const rows = await asUserMany(env, (sql) => [
        sql`
          INSERT INTO tasks (
            id, title, parent_type, parent_id, status, priority, start_date, plan_due_date,
            estimated_hours, primary_pm_id, is_management, created_by
          )
          VALUES (
            ${taskId}::uuid,
            ${a.title},
            ${a.parent_type ?? 'milestone'}::entity_type,
            ${a.parent_id}::uuid,
            COALESCE(${a.status ?? null}::task_status, 'todo'::task_status),
            COALESCE(${a.priority ?? null}::priority, 'medium'::priority),
            ${a.start_date ?? null}::date,
            ${a.plan_due_date ?? null}::date,
            ${a.estimated_hours ?? null},
            ${managerIds[0] ?? null}::uuid,
            false,
            ${actorUid(env)}::uuid
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
        sql`SELECT *,
                   to_char(start_date, 'YYYY-MM-DD')           AS start_date,
                   to_char(plan_due_date, 'YYYY-MM-DD')        AS plan_due_date,
                   to_char(execution_start_date, 'YYYY-MM-DD') AS execution_start_date,
                   to_char(execution_end_date, 'YYYY-MM-DD')   AS execution_end_date
            FROM tasks WHERE id = ${taskId}::uuid`,
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
      status: MILESTONE_STATUS.describe(
        'REQUIRED. If the user has not said what state this milestone is in, ASK THEM — do not default to not_started.',
      ),
      target_date: z.string().optional().describe('YYYY-MM-DD'),
      estimated_hours: z.number().optional(),
      price: z.number().optional(),
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
            COALESCE(${a.status ?? null}::milestone_status, 'not_started'::milestone_status),
            ${a.target_date ?? null}::date,
            ${a.estimated_hours ?? null},
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
      entity: z.enum(['contact', 'deal', 'project', 'milestone', 'task', 'payment']),
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
      project_id: z.string().uuid().optional(),
      milestone_id: z.string().uuid().optional(),
      status: z.array(z.string()).optional(),
      due_before: z.string().optional().describe('plan_due_date <= YYYY-MM-DD'),
      search: z.string().max(200).optional().describe('Matches title or display id.'),
      include_management: z.boolean().default(false).describe('Include management-stream tasks.'),
      limit: z.number().int().min(1).max(500).default(100),
    },
    guard(async (a: any) => {
      const statuses = a.status?.length ? a.status : null;
      const search = a.search ? `%${a.search}%` : null;
      return asUser(env, (sql) => sql`
        SELECT t.id, t.display_id, t.title,
               t.status::text AS status, t.priority::text AS priority,
               t.start_date::text AS start_date,
               t.plan_due_date::text AS plan_due_date,
               t.estimated_hours, t.is_management,
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
        ORDER BY t.plan_due_date NULLS LAST, t.created_at DESC
        LIMIT ${a.limit ?? 100}
      `);
    }),
  );

  server.tool(
    'get_record',
    'Fetch one record in full by id.',
    {
      entity: z.enum(['contact', 'deal', 'project', 'milestone', 'task', 'payment']),
      id: z.string().uuid(),
    },
    guard(async (a: any) => {
      const id = a.id;
      let rows: Record<string, unknown>[];
      switch (a.entity) {
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
          rows = await asUser(env, (sql) => sql`
            SELECT t.*,
                   to_char(t.start_date, 'YYYY-MM-DD')           AS start_date,
                   to_char(t.plan_due_date, 'YYYY-MM-DD')        AS plan_due_date,
                   to_char(t.execution_start_date, 'YYYY-MM-DD') AS execution_start_date,
                   to_char(t.execution_end_date, 'YYYY-MM-DD')   AS execution_end_date,
                   p.name AS project_name, m.name AS milestone_name, c.full_name AS client_name
            FROM tasks t
            LEFT JOIN projects p   ON p.id = t.project_id
            LEFT JOIN milestones m ON m.id = t.milestone_id
            LEFT JOIN contacts c   ON c.id = t.contact_id
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
      entity: z.enum(['contact', 'deal', 'project', 'milestone', 'task', 'payment']),
      id: z.string().uuid(),
      reason: z.string().trim().min(3).max(1000).describe('Required, 3-1000 chars. Goes on the audit row.'),
    },
    guard(async (a: any) => {
      const id = a.id;
      const why = String(a.reason).trim();
      let rows: Record<string, unknown>[];
      switch (a.entity) {
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
