import { PageHeader } from "@/shared/components/page-header"

export function AuditPage(): React.ReactElement {
  return (
    <div className="p-6">
      <PageHeader title="Audit Log" description="Security event trail." />
      <div className="mt-6 text-sm text-[hsl(var(--fg-secondary))]">Audit log coming in Feature 5.</div>
    </div>
  )
}
