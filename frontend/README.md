# KingSec Frontend

Professional cybersecurity assessment platform frontend.

## Stack

- React 19 + TypeScript (strict)
- Vite 8 (build tool)
- Tailwind CSS 3 (styling)
- React Router v7 (routing)
- TanStack Query v5 (server state)
- Zustand (client state)
- Framer Motion (animations)
- Lucide React (icons)
- Zod + React Hook Form (forms)
- Vitest + Testing Library (tests)
- Playwright (e2e)

## Architecture

### Directory Structure

```
src/
├── api/               # API service layer (fetch-based)
├── components/
│   ├── layout/        # AppShell, Sidebar, Header, PageContainer
│   ├── shared/        # ErrorBoundary, RouteGuards, LoadingOverlay
│   └── ui/            # Reusable UI primitives (Phase 2)
├── hooks/             # Custom React hooks
├── lib/               # Utilities (cn, formatters)
├── pages/             # Route page components
├── routes/            # Router configuration
├── store/             # Zustand stores (auth, ui)
├── testing/           # Test utilities
└── types/             # TypeScript type definitions
```

### Layout Architecture

```
App
└── QueryClientProvider
    └── AppErrorBoundary
        └── ToastProvider
            ├── AppInit (auth init)
            ├── ToastListener
            ├── GlobalShortcuts (keyboard)
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
                │       └── /settings
                └── * → NotFoundPage
```

### Navigation

The sidebar supports three modes:
- **Desktop expanded** (256px): full labels + icons
- **Desktop collapsed** (64px): icons only
- **Mobile drawer**: full-width overlay with backdrop

Sidebar items are filtered by user role. Navigation items:
- Dashboard (viewer+)
- Assessments (viewer+)
- Findings (viewer+)
- Reports (analyst+)
- Schedules (viewer+)
- Settings (viewer+)

### Route Guards

- `AuthGuard`: verifies authenticated session, shows loading state during verification
- `RoleGuard`: checks role hierarchy, redirects to /unauthorized on insufficient permissions
- `GuestGuard`: redirects authenticated users away from login/register

### Error Handling

- `AppErrorBoundary`: catches render errors, shows error ID, retry, and dashboard return
- `PageErrorBoundary`: per-page error boundary with retry
- `NotFoundPage`: 404 with path display
- `UnauthorizedPage`: access denied with current role display
- `SessionExpiredPage`: session expiry with token cleanup

### Breadcrumb

Auto-generated from current route path. Maps known path segments to human-readable labels.

### Global Toast System

Connected at the app root. Supports success, error, warning, info variants.
Session expiration triggers a toast before redirect.

## UI Components (Phase 2)

28 reusable components in `src/components/ui/`:

- **Core**: Button, Card, Badge, Spinner
- **Form**: Input, Textarea, Select, Checkbox, RadioGroup, Toggle
- **Feedback**: Alert, Progress, Skeleton, Toast
- **Overlay**: Modal, Drawer, ConfirmDialog, Tooltip
- **Navigation**: Tabs, Accordion, DropdownMenu, Breadcrumb, Pagination
- **Composite**: EmptyState, ErrorState, LoadingState, Avatar, Divider

All components use CSS custom properties for theming.
Dark-first design. No hardcoded colors.

## Development

```bash
npm run dev        # Start dev server
npm run build      # TypeScript check + production build
npm test           # Run unit tests
npm run test:e2e   # Run Playwright e2e tests
npm run lint       # Run linter
```

## Environment

No `.env` file required. The API is proxied through Vite's dev server.
