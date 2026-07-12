import { useState, useCallback } from "react"
import { zodResolver } from "@hookform/resolvers/zod"
import { useForm } from "react-hook-form"
import { Loader2, Shield, LogOut } from "lucide-react"
import { useChangePassword, useLogoutAllSessions, useActiveSessions, useRevokeSession } from "../hooks/use-settings"
import { SettingsSection } from "../components/settings-section"
import { SettingsPlaceholder } from "../components/settings-placeholder"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { Button } from "@/shared/ui/button"
import { Input } from "@/shared/ui/input"
import { Label } from "@/shared/ui/label"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Badge } from "@/shared/ui/badge"
import { ConfirmDialog } from "@/shared/components/confirm-dialog"
import { securitySchema, type SecurityFormData } from "../validation"
import { formatDate } from "@/shared/lib/utils"
import { getApiError } from "@/shared/api/error-handler"

export function SecuritySettingsPage(): React.ReactElement {
  const [showLogoutAll, setShowLogoutAll] = useState(false)
  const changePasswordMutation = useChangePassword()
  const logoutAllMutation = useLogoutAllSessions()
  const { data: sessions, isLoading: sessionsLoading, error: sessionsError, refetch: refetchSessions } = useActiveSessions()
  const revokeSessionMutation = useRevokeSession()

  const { register, handleSubmit, reset, formState: { errors } } = useForm<SecurityFormData>({
    resolver: zodResolver(securitySchema),
    defaultValues: { current_password: "", new_password: "", confirm_password: "" },
  })

  const onSubmit = useCallback(
    (data: SecurityFormData) => {
      changePasswordMutation.mutate(
        { currentPassword: data.current_password, newPassword: data.new_password },
        { onSuccess: () => reset() },
      )
    },
    [changePasswordMutation, reset],
  )

  const handleLogoutAll = useCallback(() => {
    logoutAllMutation.mutate(undefined, {
      onSuccess: () => {
        setShowLogoutAll(false)
        refetchSessions()
      },
    })
  }, [logoutAllMutation, refetchSessions])

  return (
    <ErrorBoundary>
      <div className="space-y-8">
        <SettingsSection
          title="Change Password"
          description="Update your account password."
        >
          <Card>
            <CardContent className="p-6">
              <form onSubmit={handleSubmit(onSubmit)} className="space-y-4 max-w-lg">
                <div className="space-y-2">
                  <Label htmlFor="current_password">Current Password</Label>
                  <Input id="current_password" type="password" {...register("current_password")} />
                  {errors.current_password && <p className="text-xs text-[hsl(var(--destructive))]">{errors.current_password.message}</p>}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="new_password">New Password</Label>
                  <Input id="new_password" type="password" {...register("new_password")} />
                  {errors.new_password && <p className="text-xs text-[hsl(var(--destructive))]">{errors.new_password.message}</p>}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="confirm_password">Confirm Password</Label>
                  <Input id="confirm_password" type="password" {...register("confirm_password")} />
                  {errors.confirm_password && <p className="text-xs text-[hsl(var(--destructive))]">{errors.confirm_password.message}</p>}
                </div>
                <Button type="submit" disabled={changePasswordMutation.isPending}>
                  {changePasswordMutation.isPending && <Loader2 className="mr-2 size-4 animate-spin" />}
                  Change Password
                </Button>
              </form>
            </CardContent>
          </Card>
        </SettingsSection>

        <SettingsSection
          title="Sessions"
          description="Manage your active sessions."
        >
          <Card>
            <CardContent className="p-6">
              <div className="mb-4 flex items-center justify-between">
                <p className="text-sm text-[hsl(var(--muted-fg))]">
                  Terminate all other sessions across devices.
                </p>
                <Button variant="outline" size="sm" onClick={() => setShowLogoutAll(true)}>
                  <LogOut className="mr-2 size-4" />
                  Logout All Sessions
                </Button>
              </div>

              {sessionsLoading || sessionsError ? (
                <SettingsPlaceholder
                  title="Session Management"
                  description="Active session listing will be available when the backend supports it."
                  isLoading={sessionsLoading}
                  error={sessionsError ? getApiError(sessionsError).detail : null}
                  onRetry={refetchSessions}
                />
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
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => revokeSessionMutation.mutate(session.session_id)}
                        disabled={revokeSessionMutation.isPending}
                      >
                        Revoke
                      </Button>
                    </div>
                  ))}
                </div>
              ) : (
                <SettingsPlaceholder
                  title="Session Management"
                  description="Active session listing will be available when the backend supports it."
                />
              )}
            </CardContent>
          </Card>
        </SettingsSection>

        <ConfirmDialog
          open={showLogoutAll}
          onOpenChange={setShowLogoutAll}
          title="Logout All Sessions"
          description="This will terminate all active sessions across all devices. You will need to log in again."
          confirmLabel="Logout All"
          onConfirm={handleLogoutAll}
          variant="destructive"
          loading={logoutAllMutation.isPending}
        />
      </div>
    </ErrorBoundary>
  )
}
