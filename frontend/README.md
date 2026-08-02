# KingSec Frontend

Professional cybersecurity assessment platform frontend — Attack Surface Management & Vulnerability Management.

Version **2.0.0** — General Availability

---

## Stack

| Layer | Technology |
|-------|-----------|
| Framework | React 19 + TypeScript 6 (strict) |
| Build | Vite 8 |
| Styling | Tailwind CSS 3 |
| Routing | React Router v6 (browser router) |
| Server state | TanStack Query v5 |
| Client state | Zustand v5 |
| Forms | React Hook Form + Zod v4 |
| Animations | Framer Motion v12 |
| Icons | Lucide React |
| Charts | Recharts |
| Tables | TanStack Table v8 |
| HTTP | Native `fetch` (no Axios) |
| Unit tests | Vitest + Testing Library |
| E2E tests | Playwright |
| Linter | Oxlint |

---

## Prerequisites

- **Node.js** >= 20.x (LTS recommended)
- **npm** >= 10.x
- Backend server running at `http://127.0.0.1:8765` (default)

---

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd frontend

# Install dependencies
npm install
```

---

## Development

```bash
# Start the dev server with hot reload (default: http://localhost:5173)
npm run dev

# The Vite dev server proxies /api requests to the backend at http://127.0.0.1:8765
# No .env file is required for development.
```

### Development Server

The dev server runs on port 5173. API requests to `/api/*` are automatically proxied to `http://127.0.0.1:8765` via `vite.config.ts`.

### Hot Module Replacement

Vite enables HMR for all React components by default. Changes appear instantly without full page reloads.

---

## Build

```bash
# TypeScript check + production build
npm run build

# Output: dist/
#   - Static HTML:  index.html
#   - JS bundles:   dist/assets/*.js
#   - CSS bundles:  dist/assets/*.css
#   - Static assets: dist/assets/* (icons, fonts)
```

### Production Build Verification

```bash
# Preview the production build locally
npm run preview
```

The preview server runs on a local port and serves the exact same files that would be deployed to production.

---

## Production Deployment

### Static Host (S3, Nginx, Cloudflare Pages, Vercel)

The build output (`dist/`) is a standard single-page application (SPA).

**Critical: SPA fallback routing**

Because the app uses a client-side router, the web server must serve `index.html` for all non-asset routes. This is known as "SPA fallback" or "rewrite rules."

**Nginx example:**

```nginx
server {
    listen 80;
    server_name kingsec.example.com;
    root /var/www/kingsec/dist;

    # Asset caching (fingerprinted files)
    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # SPA fallback
    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

**S3 / CloudFront example:**

Configure a Custom Error Response for 404 → `/index.html` with 200 status code.

### Environment Variables

There are currently none. The API base path (`/api/v1`, in `src/api/client.ts`)
and the dev-server proxy target (`http://127.0.0.1:8765`, in `vite.config.ts`)
are both hardcoded in source, not read from any `VITE_*` environment
variable or `.env` file — changing either requires editing that file
directly and rebuilding.

**Important:** The API base path is a path-prefix (`/api/v1`), not a full
URL. In production, the API must be reachable at that path from the same
origin the frontend is served from (e.g. behind a reverse proxy that
routes `/api/*` to the backend) — this repository does not yet include
such a reverse-proxy configuration out of the box.

### Docker Deployment Example

```dockerfile
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

---

## Testing

```bash
# Run unit tests (Vitest)
npm test

# Run unit tests in watch mode
npm run test:watch

# Run end-to-end tests (requires Playwright browsers)
npm run test:e2e

# Lint check
npm run lint
```

### Test Conventions

- Tests are co-located with source files in `__tests__/` directories
- Test files use the pattern `*.test.tsx` or `*.test.ts`
- Test setup is in `src/testing/setup.ts` (jsdom environment, jest-dom matchers)
- No test helpers library — tests render components with standard Testing Library

---

## Project Structure

```
src/
├── api/                  # API service layer (fetch-based)
│   ├── client.ts         # Base fetch wrapper with auth interceptor
│   ├── auth.ts           # Auth endpoints
│   ├── assessments.ts    # Assessment CRUD
│   ├── dashboard.ts      # Dashboard data
│   ├── findings.ts       # Findings
│   ├── reports.ts        # Reports
│   ├── settings.ts       # User settings
│   ├── audit.ts          # Audit log (admin)
│   ├── activity.ts       # Activity feed
│   ├── admin.ts          # Admin operations
│   └── notifications.ts  # Notifications
│
├── components/
│   ├── layout/           # AppShell, Sidebar, Header, PageContainer, AuthLayout
│   ├── shared/           # ErrorBoundary, RouteGuards
│   └── ui/               # 28 reusable UI primitives (Button, Modal, Tabs, etc.)
│
├── hooks/                # Custom React hooks (use-auth, use-assessments, etc.)
│
├── lib/                  # Utilities (cn, formatDate, formatRelativeTime)
│
├── pages/                # Route page components
│   ├── __tests__/        # Page-level integration tests
│   ├── LoginPage.tsx
│   ├── DashboardPage.tsx
│   ├── AssessmentsPage.tsx
│   ├── AssessmentDetailPage.tsx
│   ├── CreateAssessmentPage.tsx
│   ├── FindingsPage.tsx
│   ├── FindingDetailPage.tsx
│   ├── ReportsPage.tsx
│   ├── ReportDetailPage.tsx
│   ├── SchedulesPage.tsx
│   ├── SettingsPage.tsx
│   ├── NotificationsPage.tsx
│   ├── LiveActivityPage.tsx
│   ├── AuditLogPage.tsx
│   ├── AdminDashboardPage.tsx
│   ├── UsersPage.tsx
│   ├── UserDetailPage.tsx
│   ├── RolesPage.tsx
│   ├── NotFoundPage.tsx
│   ├── UnauthorizedPage.tsx
│   └── SessionExpiredPage.tsx
│
├── routes/               # Router configuration
│
├── store/                # Zustand stores
│   ├── auth.ts           # Auth state (in-memory only)
│   └── ui.ts             # UI preferences (sidebar, theme, dashboard)
│
├── testing/              # Test configuration (setup.ts)
│
└── types/                # TypeScript type definitions (api.ts)
```

---

## Architecture Overview

### Layout Hierarchy

```
App
└── QueryClientProvider (TanStack Query)
    └── AppErrorBoundary
        └── ToastProvider
            ├── AppInit (auth initialization)
            ├── ToastListener
            ├── GlobalShortcuts (keyboard shortcuts)
            └── RouterProvider
                ├── /login → GuestGuard → AuthLayout → LoginPage
                ├── /register → GuestGuard → AuthLayout → RegisterPage
                ├── /session-expired → SessionExpiredPage
                ├── /unauthorized → UnauthorizedPage
                ├── / → AuthGuard → RoleGuard → AppShell
                │   ├── Sidebar (collapsible, role-aware)
                │   ├── Header (search, breadcrumbs, user menu)
                │   └── <Outlet/>
                │       ├── /dashboard
                │       ├── /assessments
                │       ├── /assessments/:id
                │       ├── /assessments/new
                │       ├── /findings
                │       ├── /findings/:id
                │       ├── /reports
                │       ├── /reports/:id
                │       ├── /monitor
                │       ├── /notifications
                │       ├── /schedules
                │       ├── /settings
                │       ├── /audit (admin)
                │       ├── /admin (admin)
                │       ├── /admin/users (admin)
                │       ├── /admin/users/:id (admin)
                │       └── /admin/roles (admin)
                └── * → NotFoundPage
```

### Route Guards

| Guard | Purpose |
|-------|---------|
| `AuthGuard` | Verifies authenticated session; shows loading during verification |
| `RoleGuard` | Checks role hierarchy (`viewer` < `analyst` < `admin`); redirects to `/unauthorized` |
| `GuestGuard` | Redirects authenticated users away from login/register pages |

### Error Handling

- **AppErrorBoundary**: Catches render errors, shows error ID, retry button, and dashboard link
- **PageErrorBoundary**: Per-page error boundary with retry
- **NotFoundPage**: 404 page showing the attempted path
- **UnauthorizedPage**: Access denied page showing current user role
- **SessionExpiredPage**: Session expiry handling with token cleanup

### State Management

| State Type | Tool | Storage |
|-----------|------|---------|
| Server data | TanStack Query | In-memory cache |
| Auth tokens | Zustand | In-memory only (never persisted) |
| UI preferences | Zustand | localStorage (theme, sidebar, dashboard prefs) |
| Form state | React Hook Form | Component-local |

### Security

- **Tokens**: Access and refresh tokens stored only in memory (Zustand store). Never written to localStorage, sessionStorage, or cookies.
- **Auth header**: `Authorization: Bearer <access_token>` sent with every API request via the base fetch interceptor.
- **No telemetry**: Zero analytics, external CDNs, or third-party requests from the browser.
- **Self-hosted fonts**: Inter and JetBrains Mono served from local bundle — no Google Fonts CDN.

---

## UI Components

28 reusable UI primitives in `src/components/ui/`:

| Category | Components |
|----------|-----------|
| Core | Button, Card, Badge, Spinner |
| Form | Input, Textarea, Select, Checkbox, RadioGroup, Toggle |
| Feedback | Alert, Progress, Skeleton, Toast |
| Overlay | Modal, Drawer, ConfirmDialog, Tooltip |
| Navigation | Tabs, Accordion, DropdownMenu, Breadcrumb, Pagination |
| Composite | EmptyState, ErrorState, LoadingState, Avatar, Divider |

All components use CSS custom properties for theming. Dark-first design with no hardcoded colors.

---

## API Endpoints

The frontend maps 1:1 to the `src/kingsec/` backend API at `/api/v1`:

| Category | Endpoints |
|----------|-----------|
| Auth | `POST /auth/login`, `POST /auth/register`, `POST /auth/refresh`, `GET /auth/me` |
| Assessments | `GET/POST /assessments`, `GET /assessments/{id}`, `POST /assessments/{id}/start/report/cancel`, `DELETE /assessments/{id}` |
| Dashboard | `GET /dashboard/*` (summary, severity, trends, scanners, workers, jobs, activity, etc.) |
| Findings | Embedded in assessment responses |
| Reports | `POST /assessments/{id}/report` |
| Schedules | Full CRUD + pause/resume/enable/disable/trigger |
| Settings | MFA, API keys, sessions, notifications |
| Audit (admin) | `GET /audit`, `GET /audit/events`, `GET /audit/events/{id}` |
| Admin | Users CRUD, roles, secrets, plugins, agents, queue, pipelines, backups, health |

Full API documentation is available from the running backend at `/docs` (Swagger UI) or `/redoc` (ReDoc).

---

## Troubleshooting

### "Module not found" errors

```bash
# Ensure all dependencies are installed
rm -rf node_modules
npm install
```

### Build fails with TypeScript errors

```bash
# Check TypeScript version
npx tsc --version

# Run type check separately
npx tsc --noEmit
```

### Dev server proxy not working

Ensure the backend is running at `http://127.0.0.1:8765`. The Vite proxy configuration in `vite.config.ts` forwards `/api` requests to this address. Check the backend port — the default is `8765` but it can be configured with the `VITE_BACKEND_URL` environment variable.

### Tests failing

```bash
# Clear Vitest cache
npx vitest --clearCache

# Run tests with verbose output
npx vitest run --reporter=verbose
```

### Production build is missing routes

Ensure your reverse proxy or static file server is configured for SPA fallback (serving `index.html` for all routes). See the **Production Deployment** section above.

### Login returns 429 (rate limited)

The backend rate-limits login attempts. Wait before retrying. This is expected behavior — not a frontend issue.

---

## License

Proprietary. All rights reserved.
