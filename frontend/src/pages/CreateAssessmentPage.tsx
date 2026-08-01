import { Link, useNavigate } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { CreateAssessmentForm } from '@/components/features/assessment/CreateAssessmentForm'
import { useCreateAssessment } from '@/hooks/use-assessments'
import type { CreateAssessmentFormData } from '@/components/features/assessment/CreateAssessmentForm'

export function CreateAssessmentPage() {
  const navigate = useNavigate()
  const createAssessment = useCreateAssessment()

  const handleSubmit = (data: CreateAssessmentFormData) => {
    createAssessment.mutate({
      target_value: data.target_value,
      target_type: data.target_type,
      authorized_by: data.authorized_by,
      scope: data.scope,
    }, {
      onSuccess: (result) => {
        navigate(`/assessments/${result.assessment_id}`, { replace: true })
      },
    })
  }

  return (
    <PageContainer>
      <Link
        to="/assessments"
        className="inline-flex items-center gap-1.5 text-sm text-text-secondary hover:text-text-primary transition-colors"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to assessments
      </Link>

      <PageHeader
        title="New Assessment"
        description="Create a new security assessment to scan and analyze targets"
      />

      <div className="max-w-2xl">
        <CreateAssessmentForm onSubmit={handleSubmit} isPending={createAssessment.isPending} />
      </div>
    </PageContainer>
  )
}
