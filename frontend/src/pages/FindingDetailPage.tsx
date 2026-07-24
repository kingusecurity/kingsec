import { useParams, Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { PageContainer } from '@/components/layout/PageContainer'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { FindingDetailCard } from '@/components/features/findings/FindingDetailCard'
import { FindingEvidence } from '@/components/features/findings/FindingEvidence'
import { FindingRecommendations } from '@/components/features/findings/FindingRecommendations'
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

  return (
    <PageContainer>
      <Link
        to={`/assessments/${assessmentId}`}
        className="inline-flex items-center gap-1.5 text-sm text-text-secondary hover:text-text-primary transition-colors"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to assessment
      </Link>

      {isLoading ? (
        <div className="space-y-6">
          <Skeleton className="h-8 w-64" />
          <div className="grid gap-6 lg:grid-cols-2">
            <Skeleton className="h-48 rounded-xl" />
            <Skeleton className="h-48 rounded-xl" />
          </div>
        </div>
      ) : finding ? (
        <>
          <FindingDetailCard finding={finding} />

          <div className="grid gap-6 lg:grid-cols-2">
            <FindingEvidence finding={finding} />
            <FindingRecommendations finding={finding} />
          </div>

          <Card>
            <CardHeader>
              <CardTitle>References</CardTitle>
            </CardHeader>
            <div className="px-5 pb-5">
              <p className="text-sm text-text-muted py-4 text-center">
                Reference details are not available from the current API.
              </p>
            </div>
          </Card>
        </>
      ) : (
        <div className="flex flex-col items-center gap-4 py-16 text-center">
          <h2 className="text-lg font-semibold text-text-primary">Finding not found</h2>
          <p className="text-sm text-text-secondary">The requested finding could not be found.</p>
          <Link to={`/assessments/${assessmentId}`} className="text-sm text-accent hover:text-emerald-400">
            Back to assessment
          </Link>
        </div>
      )}
    </PageContainer>
  )
}
