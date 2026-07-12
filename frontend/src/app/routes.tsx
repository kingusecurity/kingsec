import { lazy, Suspense } from "react"
import { createBrowserRouter, Navigate } from "react-router-dom"
import { ProtectedRoute } from "@/features/auth/components/protected-route"
import { AppLayout } from "@/widgets/app-layout/app-layout"
import { PageSkeleton } from "@/shared/components/loading-skeleton"

const LoginPage = lazy(() => import("@/features/auth/pages/login-page").then((m) => ({ default: m.LoginPage })))
const DashboardPage = lazy(() => import("@/features/dashboard/pages/dashboard-page").then((m) => ({ default: m.DashboardPage })))
const AnalyticsPage = lazy(() => import("@/features/analytics/pages/analytics-page").then((m) => ({ default: m.AnalyticsPage })))
const AssessmentListPage = lazy(() => import("@/features/assessments/pages/assessment-list-page").then((m) => ({ default: m.AssessmentListPage })))
const AssessmentDetailPage = lazy(() => import("@/features/assessments/pages/assessment-detail-page").then((m) => ({ default: m.AssessmentDetailPage })))
const ReportsListPage = lazy(() => import("@/features/reports/pages/reports-list-page").then((m) => ({ default: m.ReportsListPage })))
const ReportViewerPage = lazy(() => import("@/features/reports/pages/report-viewer-page").then((m) => ({ default: m.ReportViewerPage })))
const UsersListPage = lazy(() => import("@/features/users/pages/users-list-page").then((m) => ({ default: m.UsersListPage })))
const UserDetailPage = lazy(() => import("@/features/users/pages/user-detail-page").then((m) => ({ default: m.UserDetailPage })))
const CreateUserPage = lazy(() => import("@/features/users/pages/create-user-page").then((m) => ({ default: m.CreateUserPage })))
const EditUserPage = lazy(() => import("@/features/users/pages/edit-user-page").then((m) => ({ default: m.EditUserPage })))
const SettingsPage = lazy(() => import("@/features/settings/pages/settings-page").then((m) => ({ default: m.SettingsPage })))
const AuditPage = lazy(() => import("@/features/audit/pages/audit-page").then((m) => ({ default: m.AuditPage })))
const ProfilePage = lazy(() => import("@/features/profile/pages/profile-page").then((m) => ({ default: m.ProfilePage })))
const NotFoundPage = lazy(() => import("@/shared/components/not-found-page").then((m) => ({ default: m.NotFoundPage })))

function LazyWrapper({ children }: { children: React.ReactNode }) {
  return (
    <Suspense fallback={<PageSkeleton />}>
      {children}
    </Suspense>
  )
}

export const router = createBrowserRouter([
  {
    path: "/login",
    element: <LazyWrapper><LoginPage /></LazyWrapper>,
  },
  {
    path: "/",
    element: (
      <ProtectedRoute>
        <AppLayout />
      </ProtectedRoute>
    ),
    children: [
      { index: true, element: <Navigate to="/dashboard" replace /> },
      { path: "dashboard", element: <LazyWrapper><DashboardPage /></LazyWrapper> },
      { path: "analytics", element: <LazyWrapper><AnalyticsPage /></LazyWrapper> },
      { path: "assessments", element: <LazyWrapper><AssessmentListPage /></LazyWrapper> },
      { path: "assessments/:id", element: <LazyWrapper><AssessmentDetailPage /></LazyWrapper> },
      { path: "reports", element: <LazyWrapper><ReportsListPage /></LazyWrapper> },
      { path: "reports/:id", element: <LazyWrapper><ReportViewerPage /></LazyWrapper> },
      { path: "users", element: <LazyWrapper><ProtectedRoute requiredRole="ADMIN"><UsersListPage /></ProtectedRoute></LazyWrapper> },
      { path: "users/new", element: <LazyWrapper><ProtectedRoute requiredRole="ADMIN"><CreateUserPage /></ProtectedRoute></LazyWrapper> },
      { path: "users/:id", element: <LazyWrapper><ProtectedRoute requiredRole="ADMIN"><UserDetailPage /></ProtectedRoute></LazyWrapper> },
      { path: "users/:id/edit", element: <LazyWrapper><ProtectedRoute requiredRole="ADMIN"><EditUserPage /></ProtectedRoute></LazyWrapper> },
      { path: "settings", element: <LazyWrapper><SettingsPage /></LazyWrapper> },
      { path: "settings/:section", element: <LazyWrapper><SettingsPage /></LazyWrapper> },
      { path: "audit", element: <LazyWrapper><ProtectedRoute requiredRole="ADMIN"><AuditPage /></ProtectedRoute></LazyWrapper> },
      { path: "profile", element: <LazyWrapper><ProfilePage /></LazyWrapper> },
      { path: "*", element: <LazyWrapper><NotFoundPage /></LazyWrapper> },
    ],
  },
])
