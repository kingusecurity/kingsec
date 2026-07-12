import { useState, useCallback } from "react"
import { useParams, useNavigate } from "react-router-dom"
import { ArrowLeft, RefreshCw } from "lucide-react"
import { useAssessmentDetail, useGenerateReport } from "../hooks/use-assessments"
import { useAssessmentSSE } from "@/widgets/live-events/use-assessment-sse"
import { OverviewTab } from "../components/overview-tab"
import { FindingsTab } from "../components/findings-tab"
import { EvidenceTab } from "../components/evidence-tab"
import { RecommendationsTab } from "../components/recommendations-tab"
import { TimelineTab } from "../components/timeline-tab"
import { LiveEventsTab } from "@/widgets/live-events/live-events-widget"
import { ReportsTab } from "../components/reports-tab"
import { AssessmentActions } from "../components/assessment-actions"
import { AssessmentStatusBadge } from "../components/assessment-status-badge"
import { PageHeader } from "@/shared/components/page-header"
import { PageSkeleton } from "@/shared/components/loading-skeleton"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/shared/ui/tabs"
import { Button } from "@/shared/ui/button"
import { getApiError } from "@/shared/api/error-handler"

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
                <FindingsTab findings={assessment.findings} />
              </TabsContent>
              <TabsContent value="evidence">
                <EvidenceTab />
              </TabsContent>
              <TabsContent value="recommendations">
                <RecommendationsTab />
              </TabsContent>
              <TabsContent value="timeline">
                <TimelineTab />
              </TabsContent>
              <TabsContent value="live-events">
                <LiveEventsTab events={events} isConnected={isConnected} error={sseError} />
              </TabsContent>
              <TabsContent value="reports">
                <ReportsTab
                  onGenerateReport={() => reportMutation.mutate(assessment.assessment_id)}
                  isGenerating={reportMutation.isPending}
                />
              </TabsContent>
            </div>
          </Tabs>
        </div>
      </div>
    </ErrorBoundary>
  )
}
