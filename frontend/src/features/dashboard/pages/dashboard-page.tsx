import { PageHeader } from "@/shared/components/page-header"

export function DashboardPage(): React.ReactElement {
  return (
    <div className="p-6">
      <PageHeader title="Dashboard" description="Overview of your attack surface." />
      <div className="mt-6 text-sm text-[hsl(var(--fg-secondary))]">Dashboard coming in Feature 4.</div>
    </div>
  )
}
