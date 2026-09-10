# os-mcp

An MCP server for GrowwStacks OS. Stateless Cloudflare Worker, talks directly to
Neon Postgres, exposes 8 capabilities plus 5 lookup tools.

## Setup

```bash
npm install
```

Fill in `.dev.vars` (gitignored, already created):

```
DATABASE_URL=postgresql://app_user:...@...neon.tech/...?sslmode=require
MCP_AUTH_TOKEN=<any long random string, e.g. openssl rand -hex 32>
GS_ACTOR_UID=00000000-0000-0000-0000-0000000000ff
```

Then:

```bash
npm run dev        # local, reads .dev.vars
npm run typecheck
```

Deploy:

```bash
wrangler secret put DATABASE_URL
wrangler secret put MCP_AUTH_TOKEN
npm run deploy
```

## 🚨 DATABASE_URL must be the non-owner `app_user` role

Not the Neon owner. GrowwStacks OS enforces every permission through Row-Level
Security, and **no table in the schema sets `FORCE ROW LEVEL SECURITY`** — which
means a Postgres owner connection bypasses all 55 RLS policies silently. With
the owner string, `app.current_user_id` becomes decorative and salary +
credential protections stop applying.

## Tools (29)

**Create**

| Tool | What it does |
|---|---|
| `create_contact` | Create a contact and its ownership row |
| `create_deal` | Create a deal on a contact, in a pipeline stage |
| `create_project` | Create a delivery project |
| `create_milestone` | Create a milestone under a project |
| `create_task` | Create a task under a milestone (or deal/payment) |
| `create_payment` | Record a payment against a deal |

**Read**

| Tool | What it does |
|---|---|
| `get_statuses` | Allowed status values for an entity |
| `get_payments` | Payments with deal/project/milestone/client context |
| `get_developer_availability` | Daily hours, allocations, free capacity |
| `list_tasks` | Tasks filtered by assignee, manager, project, status, due date |
| `get_record` | One record in full, by entity + id |

**Change status**

| Tool | What it does |
|---|---|
| `set_task_status` | Move a task through its workflow |
| `set_project_status` | Change project status (`on_hold` needs a reason) |
| `set_payment_status` | Change payment status (`received` needs money-in figures) |
| `set_deal_stage` | Move a deal to another stage of its pipeline |

**Assign people** — ownership is always a join table, never a single FK

| Tool | What it does |
|---|---|
| `add_task_assignee` / `remove_task_assignee` | Who does the work |
| `add_task_manager` / `remove_task_manager` | Who oversees it |
| `add_project_member` / `remove_project_member` | Project team (`pm` or `developer`) |
| `set_contact_owner` | Contact ownership (join row + cached pointer) |

**Archive**

| Tool | What it does |
|---|---|
| `archive_record` | Soft-delete any entity with a mandatory audited reason |

**Lookups** — these exist because the create tools need UUIDs nothing else can produce

| Tool | What it does |
|---|---|
| `list_pipelines` | Pipelines + stages (for `create_deal`) |
| `list_apps` | The apps/tools vocabulary (for `create_project`) |
| `search_contacts` | Find a contact |
| `find_user` | Find a team member (owner / manager / assignee ids) |
| `find_deal` | Find a deal (for `create_payment`) |
| `find_project` | Find a project |
| `find_milestone` | Find a milestone (for `create_task`) |

## Fields the tools force you to supply

An MCP tool cannot prompt a human directly. What makes Claude stop and ask is a
**required** field: the call fails validation, Claude sees which field is missing
and what values are legal, and it turns around and asks the user. So anything the
team must not have silently defaulted is required here, not optional.

| Tool | Must be supplied |
|---|---|
| `create_contact` | `status` (prospect / active_client / partner / on_hold / churned), `primary_owner_id` |
| `create_deal` | `stage_id`, `deal_value`, `currency` |
| `create_project` | `apps` (validated against `list_apps`; pass `[]` only if the user confirms none) |
| `create_milestone` | `status` (not_started / in_progress / in_review / client_pending / on_hold / done) |
| `create_task` | `priority`, `manager_ids`, `assignee_ids`, `start_date`, `plan_due_date`, `estimated_hours` |

`source` on a deal stays **optional on purpose** — its description tells Claude
never to infer it, and to leave it out when the user doesn't know. An invented
provenance is worse than a blank one.

Unknown app names are **rejected** with the list of valid options rather than
silently dropped (the OS UI drops them). Casing is normalised to the catalog, so
`monday` becomes `Monday`.

A milestone is created one call at a time — call `create_milestone` once per
milestone to give a project several.

## Attribution

Everything the MCP writes is owned by and audited to `GS_ACTOR_UID`.

A dedicated account has been created for this — **`U-SYS-MCP` / "MCP (System)"**,
id `00000000-0000-0000-0000-0000000000fe`, role `admin` — so records read as
MCP-created rather than borrowing the Slack integration's SYSTEM user. It was
created by `scripts/create-mcp-user.mjs` (a one-off plain `INSERT INTO users`,
idempotent, not a migration, no change to the OS app repo).

To attribute a record to a real person instead, pass `primary_owner_id` on
`create_contact` / `create_deal`, or call `set_contact_owner` afterwards. Use
`find_user` to get the id.

## Access model

Every call acts as one admin user (`GS_ACTOR_UID`, default the OS SYSTEM user —
role `admin`, active). There is no per-user scoping: all callers see the same
admin-level view. `get_payments` therefore returns **every** payment, not the
PM-scoped subset the OS app shows each PM.

Salary (gated to `super_admin`) and credential plaintext (only via the OS's
logged reveal path) remain out of reach, because the actor is `admin`, not
`super_admin`, and `credentials.secret_ref` is revoked from all app roles.

## How it stays inside the security model

- Connects as `app_user`, never the owner.
- Every query runs through `asUser`/`asUserMany` in `src/db.ts`, which sets
  `app.current_user_id` and the real statement in **one transaction** — the same
  pattern as the OS app's `lib/db.ts`.
- Every statement is a Neon tagged template, so all values are parameterised.
- No generic "run SQL" tool. No deletes — the OS never hard-deletes.
- `display_id` and the spine caches (`contact_id`, `company_id`, `project_id`,
  `milestone_id`) are trigger-maintained and never set here.

## Non-obvious things reproduced from the OS code

- **Tasks** are inserted *without* `RETURNING`, then selected back as a separate
  statement in the same transaction. The `tasks` SELECT policy (`fn_can_see`) is
  self-referential, so `INSERT … RETURNING` fails RLS even for an admin.
- **Deals** carry both a `pipeline_id`/`stage_id` (the source of truth) and a
  legacy `deal_stage` enum column. The enum is kept in sync by deriving it from
  the chosen stage's *name* when that name is a valid enum label, else `'new'`.
- **Payment dates** are returned as raw `YYYY-MM-DD` text. The Neon driver
  otherwise parses a `date` into a JS `Date` at UTC midnight, which renders a day
  early in IST.
- **Payment developer shares** must total exactly 100. Checked here for a clear
  message; the database trigger `fn_check_payment_percent` is the real gate.

## Known differences from the OS app

1. **No task-assignment notifications.** The OS `createTask` fires an in-app +
   Teams ping to each assignee. Tasks created here are silent.
2. **The "admin/PM must assign at least one developer" rule is not enforced.**
   That rule lives only in the OS TypeScript, not the database, so a payment can
   be created here with no developers.
3. **Availability working hours.** The OS helper `workingForStatus()` returns
   fixed constants and does *not* zero out `absent`. This server instead reads
   the stored `working_hours` column, halves it for `first_half`/`second_half`,
   and treats `absent` as 0 — which is what "free capacity" should mean. Change
   `get_developer_availability` in `src/tools.ts` if you want strict parity.

## Endpoint

The MCP handler is mounted at **`POST /mcp`** (not `/`). Authenticate with
either header:

```
Authorization: Bearer <MCP_AUTH_TOKEN>
x-api-key: <MCP_AUTH_TOKEN>
```

`GET /health` is unauthenticated and returns `{"ok":true,"service":"os-mcp"}`.

Quick check:

```bash
curl -X POST http://127.0.0.1:8787/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

## Status

Runs locally against the production Neon database. Verified:

- `npm install`, `npm run typecheck` — clean
- `wrangler dev` — starts, loads all three secrets from `.dev.vars`
- auth — 401 with no token and with a wrong token, 200 with the right one
- `tools/list` — all 13 tools registered
- **read tools exercised against live data**: `get_statuses` (task enum and deal
  pipeline stages), `list_pipelines`, `get_payments`, `get_developer_availability`
  (working/allocated/available hours compute correctly)

**The four write tools have not been run** — doing so creates real rows in
production. Test them against records you're willing to keep or archive.
