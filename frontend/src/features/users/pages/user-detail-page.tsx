import { useState, useCallback } from "react"
import { useParams, useNavigate } from "react-router-dom"
import {
  ArrowLeft,
  RefreshCw,
  Shield,
  Key,
  Activity,
  ScrollText,
  Pencil,
  Trash2,
  Construction,
} from "lucide-react"
import { useUser, useDeleteUser, useUserSessions, useUserAuditEntries } from "../hooks/use-users"
import { UserRoleBadge } from "../components/user-role-badge"
import { UserStatusBadge } from "../components/user-status-badge"
import { PageHeader } from "@/shared/components/page-header"
import { PageSkeleton } from "@/shared/components/loading-skeleton"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { ConfirmDialog } from "@/shared/components/confirm-dialog"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/shared/ui/tabs"
import { Button } from "@/shared/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Badge } from "@/shared/ui/badge"
import { getApiError } from "@/shared/api/error-handler"
import { formatDate } from "@/shared/lib/utils"
import { ROUTES } from "@/shared/lib/constants"
import { ROLE_PERMISSIONS, ROLE_LABELS } from "../types"
import type { UserRole } from "../types"

export function UserDetailPage(): React.ReactElement {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState("profile")
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)

  const { data: user, isLoading, error, refetch } = useUser(id ?? "")
  const deleteMutation = useDeleteUser()
  const { data: sessions, isLoading: sessionsLoading } = useUserSessions(id ?? "")
  const { data: auditData, isLoading: auditLoading } = useUserAuditEntries(id ?? "", { limit: 20 })

  const handleDelete = useCallback(() => {
    if (!user) return
    deleteMutation.mutate(user.user_id, {
      onSuccess: () => navigate(ROUTES.USERS),
    })
  }, [user, deleteMutation, navigate])

  if (isLoading) return <PageSkeleton />

  if (error || !user) {
    const apiErr = error ? getApiError(error) : { detail: "User not found", status: 404 }
    return (
      <div className="p-6">
        <Button variant="ghost" size="sm" onClick={() => navigate(ROUTES.USERS)} className="mb-4">
          <ArrowLeft className="mr-2 size-4" />
          Back to Users
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

  const permissions = ROLE_PERMISSIONS[user.role] ?? []

  return (
    <ErrorBoundary>
      <div className="p-6">
        <div className="mb-4 flex items-center justify-between">
          <Button variant="ghost" size="sm" onClick={() => navigate(ROUTES.USERS)}>
            <ArrowLeft className="mr-2 size-4" />
            Back
          </Button>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate(`${ROUTES.USERS}/${user.user_id}/edit`)}
            >
              <Pencil className="mr-1 size-4" />
              Edit
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowDeleteConfirm(true)}
              className="text-[hsl(var(--destructive))] hover:text-[hsl(var(--destructive))]"
            >
              <Trash2 className="mr-1 size-4" />
              Delete
            </Button>
          </div>
        </div>

        <PageHeader
          title={user.username}
          description={user.email}
        />

        <div className="mt-6">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList>
              <TabsTrigger value="profile">Profile</TabsTrigger>
              <TabsTrigger value="permissions">Permissions</TabsTrigger>
              <TabsTrigger value="sessions">Sessions</TabsTrigger>
              <TabsTrigger value="audit">Audit Activity</TabsTrigger>
            </TabsList>

            <div className="mt-4">
              <TabsContent value="profile">
                <Card>
                  <CardHeader>
                    <CardTitle>User Information</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <MetadataRow label="Username" value={user.username} />
                    <MetadataRow label="Email" value={user.email} />
                    <MetadataRow
                      label="Role"
                      value={<UserRoleBadge role={user.role} />}
                    />
                    <MetadataRow
                      label="Status"
                      value={<UserStatusBadge isActive={user.is_active} />}
                    />
                    <MetadataRow label="Created" value={formatDate(user.created_at)} />
                    {user.last_login && (
                      <MetadataRow label="Last Login" value={formatDate(user.last_login)} />
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="permissions">
                <Card>
                  <CardHeader>
                    <CardTitle>Effective Permissions</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="mb-3 text-sm text-[hsl(var(--muted-fg))]">
                      Role: <span className="font-medium text-[hsl(var(--fg))]">{ROLE_LABELS[user.role]}</span>
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {permissions.map((perm) => (
                        <Badge key={perm} variant="secondary">
                          {perm}
                        </Badge>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="sessions">
                <Card>
                  <CardHeader>
                    <CardTitle>Active Sessions</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {sessionsLoading ? (
                      <div className="space-y-2">
                        {Array.from({ length: 3 }).map((_, i) => (
                          <div key={i} className="skeleton h-16 rounded-lg" />
                        ))}
                      </div>
                    ) : sessions && sessions.length > 0 ? (
                      <div className="space-y-2">
                        {sessions.map((session) => (
                          <div
                            key={session.session_id}
                            className="flex items-center justify-between rounded-lg border border-[hsl(var(--border))] p-3"
                          >
                            <div className="space-y-1">
                              <p className="text-sm font-medium text-[hsl(var(--fg))]">{session.ip_address}</p>
                              <p className="text-xs text-[hsl(var(--muted-fg))]">
                                {session.user_agent} · Last active {formatDate(session.last_active)}
                              </p>
                            </div>
                            <Button variant="outline" size="sm" disabled>
                              Revoke
                            </Button>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="flex flex-col items-center gap-2 py-8 text-center">
                        <Construction className="size-8 text-[hsl(var(--muted-fg))]" />
                        <p className="text-sm text-[hsl(var(--muted-fg))]">
                          Session management will be available when the backend supports it.
                        </p>
                        <Badge variant="secondary">Ready for backend integration</Badge>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="audit">
                <Card>
                  <CardHeader>
                    <CardTitle>Audit Activity</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {auditLoading ? (
                      <div className="space-y-2">
                        {Array.from({ length: 3 }).map((_, i) => (
                          <div key={i} className="skeleton h-12 rounded-lg" />
                        ))}
                      </div>
                    ) : auditData?.items && auditData.items.length > 0 ? (
                      <div className="space-y-2">
                        {auditData.items.map((entry) => (
                          <div
                            key={entry.audit_id}
                            className="flex items-center justify-between rounded-lg border border-[hsl(var(--border))] p-3"
                          >
                            <div className="space-y-1">
                              <p className="text-sm font-medium text-[hsl(var(--fg))]">{entry.action}</p>
                              <p className="text-xs text-[hsl(var(--muted-fg))]">
                                {entry.details} · {formatDate(entry.created_at)}
                              </p>
                            </div>
                            <Badge variant={entry.success ? "success" : "destructive"}>
                              {entry.success ? "Success" : "Failed"}
                            </Badge>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="flex flex-col items-center gap-2 py-8 text-center">
                        <Construction className="size-8 text-[hsl(var(--muted-fg))]" />
                        <p className="text-sm text-[hsl(var(--muted-fg))]">
                          User-specific audit activity will be available when the backend supports it.
                        </p>
                        <Badge variant="secondary">Ready for backend integration</Badge>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>
            </div>
          </Tabs>
        </div>

        <ConfirmDialog
          open={showDeleteConfirm}
          onOpenChange={setShowDeleteConfirm}
          title="Delete User"
          description={`Are you sure you want to delete "${user.username}"? This action cannot be undone.`}
          confirmLabel="Delete"
          onConfirm={handleDelete}
          variant="destructive"
        />
      </div>
    </ErrorBoundary>
  )
}

function MetadataRow({
  label,
  value,
}: {
  label: string
  value: React.ReactNode
}): React.ReactElement {
  return (
    <div className="flex justify-between border-b border-[hsl(var(--border))] pb-2">
      <span className="text-sm text-[hsl(var(--muted-fg))]">{label}</span>
      <span className="text-sm text-[hsl(var(--fg))]">{value}</span>
    </div>
  )
}
