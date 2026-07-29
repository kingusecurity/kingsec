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
const FindingDetailPage = lazy(() => import('@/pages/FindingDetailPage').then(m => ({ default: m.FindingDetailPage })))
const FindingsPage = lazy(() => import('@/pages/FindingsPage').then(m => ({ default: m.FindingsPage })))
const ReportsPage = lazy(() => import('@/pages/ReportsPage').then(m => ({ default: m.ReportsPage })))
const AdministrationPage = lazy(() => import('@/pages/AdministrationPage').then(m => ({ default: m.AdministrationPage })))
const SchedulesPage = lazy(() => import('@/pages/SchedulesPage').then(m => ({ default: m.SchedulesPage })))
const SettingsPage = lazy(() => import('@/pages/SettingsPage').then(m => ({ default: m.SettingsPage })))
const NotFoundPage = lazy(() => import('@/pages/NotFoundPage').then(m => ({ default: m.NotFoundPage })))
const UnauthorizedPage = lazy(() => import('@/pages/UnauthorizedPage').then(m => ({ default: m.UnauthorizedPage })))
const SessionExpiredPage = lazy(() => import('@/pages/SessionExpiredPage').then(m => ({ default: m.SessionExpiredPage })))
const LiveActivityPage = lazy(() => import('@/pages/LiveActivityPage').then(m => ({ default: m.LiveActivityPage })))
const NotificationsPage = lazy(() => import('@/pages/NotificationsPage').then(m => ({ default: m.NotificationsPage })))
const AuditLogPage = lazy(() => import('@/pages/AuditLogPage').then(m => ({ default: m.AuditLogPage })))
const UIShowcasePage = lazy(() => import('@/pages/UIShowcasePage').then(m => ({ default: m.UIShowcasePage })))
const AIAssistantPage = lazy(() => import('@/pages/AIAssistantPage').then(m => ({ default: m.AIAssistantPage })))
const ComplianceDashboardPage = lazy(() => import('@/pages/ComplianceDashboardPage').then(m => ({ default: m.ComplianceDashboardPage })))
const AssetInventoryPage = lazy(() => import('@/pages/AssetInventoryPage').then(m => ({ default: m.AssetInventoryPage })))
const AssetDetailPage = lazy(() => import('@/pages/AssetDetailPage').then(m => ({ default: m.AssetDetailPage })))
const AttackSurfacePage = lazy(() => import('@/pages/AttackSurfacePage').then(m => ({ default: m.AttackSurfacePage })))
const AttackSurfaceDetailPage = lazy(() => import('@/pages/AttackSurfaceDetailPage').then(m => ({ default: m.AttackSurfaceDetailPage })))
const SecurityOperationsPage = lazy(() => import('@/pages/SecurityOperationsPage').then(m => ({ default: m.SecurityOperationsPage })))
const AlertsPage = lazy(() => import('@/pages/AlertsPage').then(m => ({ default: m.AlertsPage })))
const AlertDetailPage = lazy(() => import('@/pages/AlertDetailPage').then(m => ({ default: m.AlertDetailPage })))
const MonitoringRulesPage = lazy(() => import('@/pages/MonitoringRulesPage').then(m => ({ default: m.MonitoringRulesPage })))
const MonitoringTimelinePage = lazy(() => import('@/pages/MonitoringTimelinePage').then(m => ({ default: m.MonitoringTimelinePage })))
const ThreatIntelligenceDashboard = lazy(() => import('@/pages/ThreatIntelligenceDashboard').then(m => ({ default: m.ThreatIntelligenceDashboard })))
const CveExplorerPage = lazy(() => import('@/pages/CveExplorerPage').then(m => ({ default: m.CveExplorerPage })))
const CveDetailPage = lazy(() => import('@/pages/CveDetailPage').then(m => ({ default: m.CveDetailPage })))
const KevViewPage = lazy(() => import('@/pages/KevViewPage').then(m => ({ default: m.KevViewPage })))
const ThreatTimelinePage = lazy(() => import('@/pages/ThreatTimelinePage').then(m => ({ default: m.ThreatTimelinePage })))
const AICopilotPage = lazy(() => import('@/pages/AICopilotPage').then(m => ({ default: m.AICopilotPage })))
const PlaybooksPage = lazy(() => import('@/pages/PlaybooksPage').then(m => ({ default: m.PlaybooksPage })))
const PlaybookDetailPage = lazy(() => import('@/pages/PlaybookDetailPage').then(m => ({ default: m.PlaybookDetailPage })))
const ExecutionHistoryPage = lazy(() => import('@/pages/ExecutionHistoryPage').then(m => ({ default: m.ExecutionHistoryPage })))
const PluginsSdkPage = lazy(() => import('@/pages/PluginsSdkPage').then(m => ({ default: m.PluginsSdkPage })))

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
        path: 'administration',
        element: <Suspense fallback={<PageLoader />}><AdministrationPage /></Suspense>,
      },
      {
        path: 'monitor',
        element: <Suspense fallback={<PageLoader />}><LiveActivityPage /></Suspense>,
      },
      {
        path: 'notifications',
        element: <Suspense fallback={<PageLoader />}><NotificationsPage /></Suspense>,
      },
      {
        path: 'schedules',
        element: <Suspense fallback={<PageLoader />}><SchedulesPage /></Suspense>,
      },
      {
        path: 'audit',
        element: <Suspense fallback={<PageLoader />}><AuditLogPage /></Suspense>,
      },
      {
        path: 'ai',
        element: <Suspense fallback={<PageLoader />}><AIAssistantPage /></Suspense>,
      },
      {
        path: 'compliance',
        element: <Suspense fallback={<PageLoader />}><ComplianceDashboardPage /></Suspense>,
      },
      {
        path: 'assets',
        element: <Suspense fallback={<PageLoader />}><AssetInventoryPage /></Suspense>,
      },
      {
        path: 'assets/:id',
        element: <Suspense fallback={<PageLoader />}><AssetDetailPage /></Suspense>,
      },
      {
        path: 'attack-surface',
        element: <Suspense fallback={<PageLoader />}><AttackSurfacePage /></Suspense>,
      },
      {
        path: 'attack-surface/:id',
        element: <Suspense fallback={<PageLoader />}><AttackSurfaceDetailPage /></Suspense>,
      },
      {
        path: 'monitoring',
        element: <Suspense fallback={<PageLoader />}><SecurityOperationsPage /></Suspense>,
      },
      {
        path: 'monitoring/alerts',
        element: <Suspense fallback={<PageLoader />}><AlertsPage /></Suspense>,
      },
      {
        path: 'monitoring/alerts/:id',
        element: <Suspense fallback={<PageLoader />}><AlertDetailPage /></Suspense>,
      },
      {
        path: 'monitoring/rules',
        element: <Suspense fallback={<PageLoader />}><MonitoringRulesPage /></Suspense>,
      },
      {
        path: 'monitoring/timeline',
        element: <Suspense fallback={<PageLoader />}><MonitoringTimelinePage /></Suspense>,
      },
      {
        path: 'copilot',
        element: <Suspense fallback={<PageLoader />}><AICopilotPage /></Suspense>,
      },
      {
        path: 'threat-intelligence',
        element: <Suspense fallback={<PageLoader />}><ThreatIntelligenceDashboard /></Suspense>,
      },
      {
        path: 'threat-intelligence/cves',
        element: <Suspense fallback={<PageLoader />}><CveExplorerPage /></Suspense>,
      },
      {
        path: 'threat-intelligence/cves/:id',
        element: <Suspense fallback={<PageLoader />}><CveDetailPage /></Suspense>,
      },
      {
        path: 'threat-intelligence/kev',
        element: <Suspense fallback={<PageLoader />}><KevViewPage /></Suspense>,
      },
      {
        path: 'threat-intelligence/timeline',
        element: <Suspense fallback={<PageLoader />}><ThreatTimelinePage /></Suspense>,
      },
      {
        path: 'playbooks',
        element: <Suspense fallback={<PageLoader />}><PlaybooksPage /></Suspense>,
      },
      {
        path: 'playbooks/history',
        element: <Suspense fallback={<PageLoader />}><ExecutionHistoryPage /></Suspense>,
      },
      {
        path: 'plugins',
        element: <Suspense fallback={<PageLoader />}><PluginsSdkPage /></Suspense>,
      },
      {
        path: 'playbooks/:id',
        element: <Suspense fallback={<PageLoader />}><PlaybookDetailPage /></Suspense>,
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
