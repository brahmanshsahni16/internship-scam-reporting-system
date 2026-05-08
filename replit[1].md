# ScamGuard — Job & Internship Scam Detection System

A platform that helps college students identify fraudulent job and internship listings. Students can browse listings, report scams, and leave reviews. Admins can manage companies, verify listings, and moderate reports.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 8080)
- `pnpm --filter @workspace/scam-detect run dev` — run the frontend (port 25067)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string, `SESSION_SECRET` — HMAC secret for JWT

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- Frontend: React + Vite, TanStack Query, Wouter, shadcn/ui, Tailwind CSS
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Auth: Custom JWT (HMAC-SHA256), role-based (student / admin)
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `lib/api-spec/openapi.yaml` — OpenAPI contract (source of truth)
- `lib/db/src/schema/` — Drizzle table definitions (users, companies, jobs, reports, reviews)
- `artifacts/api-server/src/routes/` — Express route handlers
- `artifacts/api-server/src/lib/auth.ts` — JWT sign/verify, password hashing
- `artifacts/api-server/src/middlewares/auth.ts` — authMiddleware, adminOnly, optionalAuth
- `artifacts/scam-detect/src/` — React frontend
- `artifacts/scam-detect/src/hooks/use-auth.tsx` — Auth context and hook

## Architecture decisions

- JWT stored in localStorage (`scam_detect_token`, `scam_detect_role`). Custom fetch in `lib/api-client-react/src/custom-fetch.ts` reads it for every API call.
- Password hashing uses HMAC-SHA256 with SESSION_SECRET (no bcrypt dependency on backend).
- `lib/api-zod/src/index.ts` only exports from `./generated/api` — the codegen script patches this after orval runs to avoid duplicate export errors.
- Stats endpoint is public (no auth required) — admin panel handles filtering client-side.
- Orval `schemas` option removed from zod output config to avoid TypeScript type conflicts with Zod schema names.

## Product

- **Dashboard** (`/`) — System stats overview + recently flagged jobs
- **Jobs** (`/jobs`) — Searchable/filterable job grid with status chips, report counts, ratings. Job detail modal with report + review forms
- **Companies** (`/companies`) — Company directory with verification status, job/report counts
- **Reports** (`/reports`) — Admin-only: manage all submitted scam reports
- **Admin** (`/admin`) — Admin dashboard: full stats, flagged job moderation, company verification, create jobs/companies

## User preferences

- Uses React hooks for all state and API interactions
- Project originally provided as vanilla HTML/JS + Node/MySQL — rebuilt as full-stack React app

## Demo Credentials

| Role    | Email                  | Password    |
|---------|------------------------|-------------|
| Admin   | admin@scamdetect.in    | admin123    |
| Student | priya@college.edu      | student123  |
| Student | rahul@college.edu      | student123  |

## Gotchas

- After changing `openapi.yaml`, always run codegen: `pnpm --filter @workspace/api-spec run codegen`
- The codegen script patches `lib/api-zod/src/index.ts` after orval to fix duplicate exports
- Do not add `schemas` back to the zod orval config — it causes naming conflicts

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
