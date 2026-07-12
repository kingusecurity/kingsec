import { useState, useCallback, Suspense } from "react"
import { useParams, useNavigate } from "react-router-dom"
import { ArrowLeft, RefreshCw, Shield, Calendar, Hash, Activity } from "lucide-react"
import { useAssessmentDetail, useGenerateReport } from "../hooks/use-assessments"
import { useAssessmentSSE } from "@/widgets/live-events/use-assessment-sse"
import { OverviewTab } from "../components/overview-tab"
import {
  LazyFindingsTab,
  LazyEvidenceTab,
  LazyRecommendationsTab,
  LazyTimelineTab,
  LazyReportsTab,
  LazyLiveEventsTab,
} from "../components/tab-lazy"
import { AssessmentActions } from "../components/assessment-actions"
import { AssessmentStatusBadge } from "../components/assessment-status-badge"
import { PageHeader } from "@/shared/components/page-header"
import { PageSkeleton } from "@/shared/components/loading-skeleton"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/shared/ui/tabs"
import { Button } from "@/shared/ui/button"
import { Card, CardContent } from "@/shared/ui/card"
import { getApiError } from "@/shared/api/error-handler"
import { formatDate } from "@/shared/lib/utils"

function TabSkeleton(): React.ReactElement {
  return (
    <div className="space-y-4 py-8">
      <div className="skeleton h-8 w-48 rounded" />
      <div className="skeleton h-64 rounded-xl" />
    </div>
  )
}

export function AssessmentDetailPage(): React.ReactElement {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState("overview")

  const { data: assessment, isLoading, error, refetch, isFetching } = useAssessmentDetail(id ?? "")
  const reportMutation = useGenerateReport()

  const handleEventUpdate = useCallback(() => {
    refetch()
  }, [refetch])

  const { events, isConnected, error: sseError } = useAssessmentSSE({
    assessmentId: id,
    enabled: activeTab === "live-events",
    onEvent: handleEventUpdate,
  })

  if (isLoading) {
    return <PageSkeleton />
  }

  if (error || !assessment) {
    const apiErr = error ? getApiError(error) : { detail: "Assessment not found", status: 404 }
    return (
      <div className="p-6">
        <Button variant="ghost" size="sm" onClick={() => navigate("/assessments")} className="mb-4">
          <ArrowLeft className="mr-2 size-4" />
          Back to Assessments
        </Button>
        <div className="flex flex-col items-center gap-4 rounded-xl border border-[hsl(var(--border))] py-16" role="alert">
          <p className="text-sm text-[hsl(var(--destructive))]">{apiErr.detail}</p>
          <Button variant="outline" onClick={() => refetch()}>
            <RefreshCw className="mr-2 size-4" />
            Retry
          </Button>
        </div>
      </div>
    )
  }

  return (
    <ErrorBoundary>
      <div className="p-6">
        {/* Back + Refresh */}
        <div className="mb-4 flex items-center justify-between">
          <Button variant="ghost" size="sm" onClick={() => navigate("/assessments")}>
            <ArrowLeft className="mr-2 size-4" />
            Back
          </Button>
          <div className="flex items-center gap-3">
            <AssessmentStatusBadge status={assessment.status} />
            <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
              <RefreshCw className={`mr-2 size-4 ${isFetching ? "animate-spin" : ""}`} />
            </Button>
          </div>
        </div>

        <PageHeader
          title={assessment.target}
          description={`Assessment ${assessment.assessment_id}`}
          actions={
            <AssessmentActions
              assessmentId={assessment.assessment_id}
              status={assessment.status}
              onDeleted={() => navigate("/assessments")}
            />
          }
        />

        {/* Rich Assessment Metadata */}
        <Card className="mt-4">
          <CardContent className="p-4">
            <div className="grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
              <div className="flex items-center gap-2">
                <Hash className="size-4 text-[hsl(var(--muted-fg))]" />
                <span className="text-[hsl(var(--muted-fg))]">ID:</span>
                <span className="font-mono text-[hsl(var(--fg))]">{assessment.assessment_id}</span>
              </div>
              <div className="flex items-center gap-2">
                <Shield className="size-4 text-[hsl(var(--muted-fg))]" />
                <span className="text-[hsl(var(--muted-fg))]">Target:</span>
                <span className="text-[hsl(var(--fg))]">{assessment.target}</span>
              </div>
              <div className="flex items-center gap-2">
                <Calendar className="size-4 text-[hsl(var(--muted-fg))]" />
                <span className="text-[hsl(var(--muted-fg))]">Created:</span>
                <span className="text-[hsl(var(--fg))]">{formatDate(assessment.created_at)}</span>
              </div>
              <div className="flex items-center gap-2">
                <Activity className="size-4 text-[hsl(var(--muted-fg))]" />
                <span className="text-[hsl(var(--muted-fg))]">Findings:</span>
                <span className="text-[hsl(var(--fg))]">{assessment.findings.length}</span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Tabs */}
        <div className="mt-6">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="w-full justify-start overflow-x-auto">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="findings">Findings ({assessment.findings.length})</TabsTrigger>
              <TabsTrigger value="evidence">Evidence</TabsTrigger>
              <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
              <TabsTrigger value="timeline">Timeline</TabsTrigger>
              <TabsTrigger value="live-events">Live Events</TabsTrigger>
              <TabsTrigger value="reports">Reports</TabsTrigger>
            </TabsList>

            <div className="mt-4">
              <TabsContent value="overview">
                <OverviewTab assessment={assessment} />
              </TabsContent>
              <TabsContent value="findings">
                <Suspense fallback={<TabSkeleton />}>
                  <LazyFindingsTab findings={assessment.findings} />
                </Suspense>
              </TabsContent>
              <TabsContent value="evidence">
                <Suspense fallback={<TabSkeleton />}>
                  <LazyEvidenceTab />
                </Suspense>
              </TabsContent>
              <TabsContent value="recommendations">
                <Suspense fallback={<TabSkeleton />}>
                  <LazyRecommendationsTab />
                </Suspense>
              </TabsContent>
              <TabsContent value="timeline">
                <Suspense fallback={<TabSkeleton />}>
                  <LazyTimelineTab />
                </Suspense>
              </TabsContent>
              <TabsContent value="live-events">
                <Suspense fallback={<TabSkeleton />}>
                  <LazyLiveEventsTab events={events} isConnected={isConnected} error={sseError} />
                </Suspense>
              </TabsContent>
              <TabsContent value="reports">
                <Suspense fallback={<TabSkeleton />}>
                  <LazyReportsTab
                    assessmentId={assessment.assessment_id}
                    report={null}
                    onGenerateReport={() => reportMutation.mutate(assessment.assessment_id)}
                    isGenerating={reportMutation.isPending}
                  />
                </Suspense>
              </TabsContent>
            </div>
          </Tabs>
        </div>
      </div>
    </ErrorBoundary>
  )
}
