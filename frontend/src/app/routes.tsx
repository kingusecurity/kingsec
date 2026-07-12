import { createBrowserRouter, Navigate } from "react-router-dom"
import { ProtectedRoute } from "@/features/auth/components/protected-route"
import { AppLayout } from "@/widgets/app-layout/app-layout"
import { LoginPage } from "@/features/auth/pages/login-page"
import { DashboardPage } from "@/features/dashboard/pages/dashboard-page"
import { AssessmentListPage } from "@/features/assessments/pages/assessment-list-page"
import { AssessmentDetailPage } from "@/features/assessments/pages/assessment-detail-page"
import { ReportsListPage } from "@/features/reports/pages/reports-list-page"
import { ReportViewerPage } from "@/features/reports/pages/report-viewer-page"
import { UsersListPage } from "@/features/users/pages/users-list-page"
import { UserDetailPage } from "@/features/users/pages/user-detail-page"
import { CreateUserPage } from "@/features/users/pages/create-user-page"
import { EditUserPage } from "@/features/users/pages/edit-user-page"
import { AuditPage } from "@/features/audit/pages/audit-page"
import { ProfilePage } from "@/features/profile/pages/profile-page"
import { ROUTES } from "@/shared/lib/constants"

export const router = createBrowserRouter([
  {
    path: ROUTES.LOGIN,
    element: <LoginPage />,
  },
  {
    path: "/",
    element: (
      <ProtectedRoute>
        <AppLayout />
      </ProtectedRoute>
    ),
    children: [
      { index: true, element: <Navigate to={ROUTES.DASHBOARD} replace /> },
      { path: "dashboard", element: <DashboardPage /> },
      { path: "assessments", element: <AssessmentListPage /> },
      { path: "assessments/:id", element: <AssessmentDetailPage /> },
      { path: "reports", element: <ReportsListPage /> },
      { path: "reports/:id", element: <ReportViewerPage /> },
      { path: "users", element: <ProtectedRoute requiredRole="ADMIN"><UsersListPage /></ProtectedRoute> },
      { path: "users/new", element: <ProtectedRoute requiredRole="ADMIN"><CreateUserPage /></ProtectedRoute> },
      { path: "users/:id", element: <ProtectedRoute requiredRole="ADMIN"><UserDetailPage /></ProtectedRoute> },
      { path: "users/:id/edit", element: <ProtectedRoute requiredRole="ADMIN"><EditUserPage /></ProtectedRoute> },
      { path: "audit", element: <ProtectedRoute requiredRole="ADMIN"><AuditPage /></ProtectedRoute> },
      { path: "profile", element: <ProfilePage /> },
    ],
  },
])
