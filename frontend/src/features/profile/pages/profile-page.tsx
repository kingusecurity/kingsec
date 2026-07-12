import { PageHeader } from "@/shared/components/page-header"

export function ProfilePage(): React.ReactElement {
  return (
    <div className="p-6">
      <PageHeader title="Profile" description="Manage your account." />
      <div className="mt-6 text-sm text-[hsl(var(--fg-secondary))]">Profile coming in Feature 6.</div>
    </div>
  )
}
