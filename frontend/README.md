# KingSec Frontend

React-based SPA for the KingSec Attack Surface Management & Vulnerability Management platform.

## Installation

```bash
cd frontend
npm install
```

## Development

```bash
npm run dev      # Start dev server on port 3000
npm run build    # Production build
npm run preview  # Preview production build
npm run test     # Run tests (vitest)
npm run test:watch  # Run tests in watch mode
npm run lint     # Run oxlint
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `VITE_API_BASE_URL` | `/api/v1` | Backend API base URL |
| `VITE_BACKEND_URL` | `http://127.0.0.1:8000` | Backend URL for Vite proxy |

Create a `.env` file in `frontend/`:

```
VITE_API_BASE_URL=/api/v1
VITE_BACKEND_URL=http://127.0.0.1:8000
```

## Architecture

### Tech Stack

- **React 19** with TypeScript
- **Vite 8** for bundling
- **Tailwind CSS v4** (CSS-first config)
- **TanStack Query** for server state
- **Zustand** for client state
- **React Router v7** for routing
- **Recharts** for charts
- **Radix UI** for accessible primitives
- **React Hook Form + Zod** for forms
- **Vitest** + Testing Library for tests

### Folder Structure

```
src/
  app/                    # App shell, routing, providers
    App.tsx               # Root component
    providers.tsx         # QueryClient, ErrorBoundary, Toaster, PWA
    routes.tsx            # Route definitions with lazy loading
  features/               # Feature modules (domain-driven)
    analytics/            # Executive dashboard, charts, exports
    assessments/          # CRUD, detail with tabs, SSE
    auth/                 # Login, auth context, protected routes
    dashboard/            # KPIs, charts, widgets, SSE
    notifications/        # Bell, panel, SSE, Zustand store
    reports/              # List, viewer, PDF generation
    settings/             # 7 settings sections
    users/                # CRUD, detail, role management
  shared/                 # Shared code across all features
    api/                  # Axios client, error handling, interceptors
    components/           # ErrorBoundary, EmptyState, Skeleton, etc.
    hooks/                # useOnline, useLocalStorage, useMediaQuery, etc.
    lib/                  # constants, env, theme-store, utils
    types/                # Shared TypeScript types
    ui/                   # Primitive UI components (Button, Card, etc.)
  widgets/                # Composite layout components
    app-layout/           # Sidebar, Header, AppLayout
    live-events/          # SSE events widget
    theme-switcher/       # Theme selector
```

### Design Principles

- **Feature-based architecture** with domain-driven module structure
- **Shared UI primitives** via `shared/ui/` (Radix-based)
- **Lazy-loaded routes** with `React.lazy` + `Suspense`
- **Code-split dashboard widgets** for faster initial load
- **Memo'd components** to prevent unnecessary re-renders
- **Optimistic updates** for mutations via TanStack Query

### PWA Support

- Service worker caches static assets and offline fallback
- Install prompt with dismiss/snooze
- Update notification when new version available
- Offline banner when connection lost

### Accessibility

- Skip-to-content link
- ARIA labels on navigation
- Focus management in dialogs and mobile sidebar
- `role="alert"` on error states
- Focus-visible styles on all interactive elements
- `prefers-reduced-motion` support

### Mobile Responsive

- Mobile sidebar with hamburger menu and drawer
- Responsive tables with horizontal scroll
- Responsive chart containers
- Mobile-friendly dialogs and cards

### Themes

5 built-in themes via CSS custom properties:

- **Light** - Default clean white
- **Dark** - Deep navy
- **Cyber** - Neon green/cyan
- **Terminal** - Matrix green
- **Corporate** - Professional blue-gray

### Testing

- **Vitest** with jsdom environment
- **Testing Library** for component tests
- **@testing-library/user-event** for interaction tests
- API tests mock Axios
- Component tests wrap in QueryClientProvider

## Backend API

The frontend communicates with the KingSec FastAPI backend:

- `POST /api/v1/auth/login` - Login
- `POST /api/v1/auth/refresh` - Token refresh
- `GET /api/v1/auth/me` - Current user
- `GET /api/v1/assessments` - List assessments
- `POST /api/v1/assessments` - Create assessment
- `GET /api/v1/assessments/:id` - Assessment detail
- `POST /api/v1/assessments/:id/start` - Start scan
- `POST /api/v1/assessments/:id/cancel` - Cancel scan
- `POST /api/v1/assessments/:id/report` - Generate report
- `GET /api/v1/events` - SSE event stream
- `GET /api/v1/audit` - Audit log (ADMIN)
- `GET /api/v1/health` - Health check
