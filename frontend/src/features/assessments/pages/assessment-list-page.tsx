import { PageHeader } from "@/shared/components/page-header"

export function AssessmentListPage(): React.ReactElement {
  return (
    <div className="p-6">
      <PageHeader title="Assessments" description="Manage your assessments." />
      <div className="mt-6 text-sm text-[hsl(var(--fg-secondary))]">Assessment list coming in Feature 2.</div>
    </div>
  )
}
