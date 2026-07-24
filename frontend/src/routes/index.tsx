import { lazy, Suspense } from 'react'
import { createBrowserRouter, Navigate } from 'react-router-dom'
import { AppShell } from '@/components/layout/AppShell'
import { AuthLayout } from '@/components/layout/AuthLayout'
import { AuthGuard, RoleGuard, GuestGuard } from '@/components/shared/RouteGuards'
import { PageErrorBoundary } from '@/components/shared/ErrorBoundary'
import { Spinner } from '@/components/ui/Spinner'

const LoginPage = lazy(() => import('@/pages/LoginPage').then(m => ({ default: m.LoginPage })))
const RegisterPage = lazy(() => import('@/pages/RegisterPage').then(m => ({ default: m.RegisterPage })))
const DashboardPage = lazy(() => import('@/pages/DashboardPage').then(m => ({ default: m.DashboardPage })))
const AssessmentsPage = lazy(() => import('@/pages/AssessmentsPage').then(m => ({ default: m.AssessmentsPage })))
const AssessmentDetailPage = lazy(() => import('@/pages/AssessmentDetailPage').then(m => ({ default: m.AssessmentDetailPage })))
const CreateAssessmentPage = lazy(() => import('@/pages/CreateAssessmentPage').then(m => ({ default: m.CreateAssessmentPage })))
const FindingsPage = lazy(() => import('@/pages/FindingsPage').then(m => ({ default: m.FindingsPage })))
const FindingDetailPage = lazy(() => import('@/pages/FindingDetailPage').then(m => ({ default: m.FindingDetailPage })))
const ReportsPage = lazy(() => import('@/pages/ReportsPage').then(m => ({ default: m.ReportsPage })))
const ReportDetailPage = lazy(() => import('@/pages/ReportDetailPage').then(m => ({ default: m.ReportDetailPage })))
const SchedulesPage = lazy(() => import('@/pages/SchedulesPage').then(m => ({ default: m.SchedulesPage })))
const SettingsPage = lazy(() => import('@/pages/SettingsPage').then(m => ({ default: m.SettingsPage })))
const NotFoundPage = lazy(() => import('@/pages/NotFoundPage').then(m => ({ default: m.NotFoundPage })))
const UnauthorizedPage = lazy(() => import('@/pages/UnauthorizedPage').then(m => ({ default: m.UnauthorizedPage })))
const SessionExpiredPage = lazy(() => import('@/pages/SessionExpiredPage').then(m => ({ default: m.SessionExpiredPage })))
const UIShowcasePage = lazy(() => import('@/pages/UIShowcasePage').then(m => ({ default: m.UIShowcasePage })))

function PageLoader() {
  return (
    <div className="flex h-[50vh] items-center justify-center">
      <Spinner size="lg" />
    </div>
  )
}

const isDev = import.meta.env.DEV

export const router = createBrowserRouter([
  {
    path: '/login',
    element: <GuestGuard><AuthLayout /></GuestGuard>,
    children: [{ index: true, element: <Suspense fallback={<PageLoader />}><LoginPage /></Suspense> }],
  },
  {
    path: '/register',
    element: <GuestGuard><AuthLayout /></GuestGuard>,
    children: [{ index: true, element: <Suspense fallback={<PageLoader />}><RegisterPage /></Suspense> }],
  },
  {
    path: '/session-expired',
    element: <Suspense fallback={<PageLoader />}><SessionExpiredPage /></Suspense>,
  },
  {
    path: '/unauthorized',
    element: <Suspense fallback={<PageLoader />}><UnauthorizedPage /></Suspense>,
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
      {
        path: 'dashboard',
        element: <Suspense fallback={<PageLoader />}><DashboardPage /></Suspense>,
      },
      {
        path: 'assessments',
        element: <Suspense fallback={<PageLoader />}><AssessmentsPage /></Suspense>,
      },
      {
        path: 'assessments/new',
        element: <Suspense fallback={<PageLoader />}><CreateAssessmentPage /></Suspense>,
      },
      {
        path: 'assessments/:id',
        element: <Suspense fallback={<PageLoader />}><AssessmentDetailPage /></Suspense>,
      },
      {
        path: 'assessments/:assessmentId/findings/:findingId',
        element: <Suspense fallback={<PageLoader />}><FindingDetailPage /></Suspense>,
      },
      {
        path: 'findings',
        element: <Suspense fallback={<PageLoader />}><FindingsPage /></Suspense>,
      },
      {
        path: 'reports',
        element: <Suspense fallback={<PageLoader />}><ReportsPage /></Suspense>,
      },
      {
        path: 'reports/:id',
        element: <Suspense fallback={<PageLoader />}><ReportDetailPage /></Suspense>,
      },
      {
        path: 'schedules',
        element: <Suspense fallback={<PageLoader />}><SchedulesPage /></Suspense>,
      },
      {
        path: 'settings',
        element: <Suspense fallback={<PageLoader />}><SettingsPage /></Suspense>,
      },
      ...(isDev ? [{ path: 'ui', element: <Suspense fallback={<PageLoader />}><UIShowcasePage /></Suspense> }] : []),
    ],
  },
  {
    path: '*',
    element: <Suspense fallback={<PageLoader />}><NotFoundPage /></Suspense>,
  },
])
