import { createBrowserRouter, Navigate } from 'react-router-dom'
import { AppShell } from '@/components/layout/AppShell'
import { AuthLayout } from '@/components/layout/AuthLayout'
import { AuthGuard } from '@/components/shared/RouteGuards'
import { RoleGuard } from '@/components/shared/RouteGuards'
import { GuestGuard } from '@/components/shared/RouteGuards'
import { PageErrorBoundary } from '@/components/shared/ErrorBoundary'
import { LoginPage } from '@/pages/LoginPage'
import { RegisterPage } from '@/pages/RegisterPage'
import { DashboardPage } from '@/pages/DashboardPage'
import { AssessmentsPage } from '@/pages/AssessmentsPage'
import { AssessmentDetailPage } from '@/pages/AssessmentDetailPage'
import { CreateAssessmentPage } from '@/pages/CreateAssessmentPage'
import { SettingsPage } from '@/pages/SettingsPage'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { UnauthorizedPage } from '@/pages/UnauthorizedPage'
import { SessionExpiredPage } from '@/pages/SessionExpiredPage'
import { UIShowcasePage } from '@/pages/UIShowcasePage'

const isDev = import.meta.env.DEV

export const router = createBrowserRouter([
  {
    path: '/login',
    element: <GuestGuard><AuthLayout /></GuestGuard>,
    children: [{ index: true, element: <LoginPage /> }],
  },
  {
    path: '/register',
    element: <GuestGuard><AuthLayout /></GuestGuard>,
    children: [{ index: true, element: <RegisterPage /> }],
  },
  {
    path: '/session-expired',
    element: <SessionExpiredPage />,
  },
  {
    path: '/unauthorized',
    element: <UnauthorizedPage />,
  },
  {
    path: '/',
    element: (
      <AuthGuard>
        <RoleGuard roles={['viewer', 'analyst', 'admin']}>
          <PageErrorBoundary>
            <AppShell />
          </PageErrorBoundary>
        </RoleGuard>
      </AuthGuard>
    ),
    children: [
      { index: true, element: <Navigate to="/dashboard" replace /> },
      { path: 'dashboard', element: <DashboardPage /> },
      { path: 'assessments', element: <AssessmentsPage /> },
      { path: 'assessments/new', element: <CreateAssessmentPage /> },
      { path: 'assessments/:id', element: <AssessmentDetailPage /> },
      { path: 'settings', element: <SettingsPage /> },
      ...(isDev ? [{ path: 'ui', element: <UIShowcasePage /> }] : []),
    ],
  },
  {
    path: '*',
    element: <NotFoundPage />,
  },
])
