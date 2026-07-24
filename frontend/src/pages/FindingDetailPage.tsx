import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, ExternalLink } from 'lucide-react'
import { PageContainer } from '@/components/layout/PageContainer'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { FindingDetailCard } from '@/components/features/findings/FindingDetailCard'
import { FindingRecommendations } from '@/components/features/findings/FindingRecommendations'
import { FindingReferences } from '@/components/features/findings/FindingReferences'
import { FindingDetailPanel } from '@/components/features/findings/FindingDetailPanel'
import { EvidencePanel } from '@/components/features/findings/EvidencePanel'
import { useFinding } from '@/hooks/use-findings'

export function FindingDetailPage() {
  const { assessmentId, findingId } = useParams<{ assessmentId: string; findingId: string }>()
  const { data: finding, isLoading, error, refetch } = useFinding(assessmentId ?? '', findingId ?? '')

  if (error) {
    return (
      <PageContainer>
        <ErrorState title="Failed to load finding" message={(error as Error).message} onRetry={refetch} />
      </PageContainer>
    )
  }

  const findingDetail = finding as import('@/types/api').FindingDetail | undefined

  return (
    <PageContainer>
      {assessmentId ? (
        <Link
          to={`/assessments/${assessmentId}`}
          className="inline-flex items-center gap-1.5 text-sm text-text-secondary hover:text-text-primary transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to assessment
        </Link>
      ) : (
        <Link
          to="/findings"
          className="inline-flex items-center gap-1.5 text-sm text-text-secondary hover:text-text-primary transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to findings
        </Link>
      )}

      {isLoading ? (
        <div className="space-y-6">
          <Skeleton className="h-8 w-64" />
          <div className="grid gap-6 lg:grid-cols-2">
            <Skeleton className="h-48 rounded-xl" />
            <Skeleton className="h-48 rounded-xl" />
          </div>
        </div>
      ) : findingDetail ? (
        <>
          <FindingDetailCard finding={findingDetail} />

          <FindingDetailPanel finding={findingDetail} />

          {findingDetail.assessment_id && (
            <Card>
              <CardHeader>
                <CardTitle>Related Assessment</CardTitle>
              </CardHeader>
              <div className="px-5 pb-5">
                <Link
                  to={`/assessments/${findingDetail.assessment_id}`}
                  className="inline-flex items-center gap-2 text-sm text-accent hover:text-emerald-400 transition-colors"
                >
                  <ExternalLink className="h-4 w-4" />
                  View {findingDetail.target ?? findingDetail.assessment_id}
                </Link>
              </div>
            </Card>
          )}

          {findingDetail.cve && findingDetail.cve.length > 0 && (
            <FindingReferences
              cve={findingDetail.cve}
              cwe={findingDetail.cwe}
              cvssScore={findingDetail.cvss_score}
              cvssVector={findingDetail.cvss_vector}
            />
          )}

          <div className="grid gap-6 lg:grid-cols-2">
            <EvidencePanel
              evidence={findingDetail.evidence}
            />
            <FindingRecommendations finding={findingDetail} />
          </div>

          {(!findingDetail.cve || findingDetail.cve.length === 0) && (
            <FindingReferences
              cve={findingDetail.cve}
              cwe={findingDetail.cwe}
              cvssScore={findingDetail.cvss_score}
              cvssVector={findingDetail.cvss_vector}
            />
          )}
        </>
      ) : (
        <div className="flex flex-col items-center gap-4 py-16 text-center">
          <h2 className="text-lg font-semibold text-text-primary">Finding not found</h2>
          <p className="text-sm text-text-secondary">The requested finding could not be found.</p>
          <Link to={assessmentId ? `/assessments/${assessmentId}` : '/findings'} className="text-sm text-accent hover:text-emerald-400">
            Back to {assessmentId ? 'assessment' : 'findings'}
          </Link>
        </div>
      )}
    </PageContainer>
  )
}
