import { useState, useCallback, useEffect } from "react"
import { useParams, useNavigate } from "react-router-dom"
import { ArrowLeft, Loader2, RefreshCw } from "lucide-react"
import { z } from "zod"
import { useUser, useUpdateUser, useResetPassword } from "../hooks/use-users"
import { PageHeader } from "@/shared/components/page-header"
import { PageSkeleton } from "@/shared/components/loading-skeleton"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { ConfirmDialog } from "@/shared/components/confirm-dialog"
import { Button } from "@/shared/ui/button"
import { Input } from "@/shared/ui/input"
import { Label } from "@/shared/ui/label"
import { Select } from "@/shared/ui/select"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Badge } from "@/shared/ui/badge"
import { getApiError } from "@/shared/api/error-handler"
import { ROUTES } from "@/shared/lib/constants"
import type { UserRole } from "../types"

const editUserSchema = z.object({
  email: z.string().email("Invalid email address"),
  role: z.enum(["VIEWER", "ANALYST", "ADMIN"]),
  is_active: z.boolean(),
})

const resetPasswordSchema = z.object({
  new_password: z.string().min(8, "Password must be at least 8 characters"),
})

export function EditUserPage(): React.ReactElement {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { data: user, isLoading, error, refetch } = useUser(id ?? "")
  const updateUserMutation = useUpdateUser()
  const resetPasswordMutation = useResetPassword()

  const [form, setForm] = useState({ email: "", role: "VIEWER" as UserRole, is_active: true })
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [showResetPassword, setShowResetPassword] = useState(false)
  const [newPassword, setNewPassword] = useState("")
  const [passwordError, setPasswordError] = useState("")

  useEffect(() => {
    if (user) {
      setForm({ email: user.email, role: user.role, is_active: user.is_active })
    }
  }, [user])

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault()
      setErrors({})

      const result = editUserSchema.safeParse(form)
      if (!result.success) {
        const fieldErrors: Record<string, string> = {}
        for (const issue of result.error.issues) {
          const field = issue.path[0] as string
          fieldErrors[field] = issue.message
        }
        setErrors(fieldErrors)
        return
      }

      if (!user) return
      updateUserMutation.mutate(
        { userId: user.user_id, data: result.data },
        { onSuccess: () => navigate(`${ROUTES.USERS}/${user.user_id}`) },
      )
    },
    [form, user, updateUserMutation, navigate],
  )

  const handleResetPassword = useCallback(() => {
    setPasswordError("")
    const result = resetPasswordSchema.safeParse({ new_password: newPassword })
    if (!result.success) {
      setPasswordError(result.error.issues[0]?.message ?? "Invalid password")
      return
    }
    if (!user) return
    resetPasswordMutation.mutate(
      { userId: user.user_id, data: result.data },
      {
        onSuccess: () => {
          setShowResetPassword(false)
          setNewPassword("")
        },
      },
    )
  }, [newPassword, user, resetPasswordMutation])

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

  return (
    <ErrorBoundary>
      <div className="p-6">
        <Button variant="ghost" size="sm" onClick={() => navigate(`${ROUTES.USERS}/${user.user_id}`)} className="mb-4">
          <ArrowLeft className="mr-2 size-4" />
          Back to User
        </Button>

        <PageHeader title={`Edit: ${user.username}`} description="Update user account settings." />

        <div className="mt-6 flex flex-col gap-6 max-w-lg">
          <Card>
            <CardHeader>
              <CardTitle>Account Settings</CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <Input
                    id="email"
                    type="email"
                    value={form.email}
                    onChange={(e) => setForm((prev) => ({ ...prev, email: e.target.value }))}
                  />
                  {errors.email && <p className="text-xs text-[hsl(var(--destructive))]">{errors.email}</p>}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="role">Role</Label>
                  <Select
                    id="role"
                    value={form.role}
                    onChange={(e) => setForm((prev) => ({ ...prev, role: e.target.value as UserRole }))}
                  >
                    <option value="VIEWER">Viewer</option>
                    <option value="ANALYST">Analyst</option>
                    <option value="ADMIN">Admin</option>
                  </Select>
                  {errors.role && <p className="text-xs text-[hsl(var(--destructive))]">{errors.role}</p>}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="status">Account Status</Label>
                  <Select
                    id="status"
                    value={form.is_active ? "active" : "disabled"}
                    onChange={(e) => setForm((prev) => ({ ...prev, is_active: e.target.value === "active" }))}
                  >
                    <option value="active">Active</option>
                    <option value="disabled">Disabled</option>
                  </Select>
                </div>

                <div className="flex gap-2 pt-2">
                  <Button type="submit" disabled={updateUserMutation.isPending}>
                    {updateUserMutation.isPending && <Loader2 className="mr-2 size-4 animate-spin" />}
                    Save Changes
                  </Button>
                  <Button type="button" variant="outline" onClick={() => navigate(`${ROUTES.USERS}/${user.user_id}`)}>
                    Cancel
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Security</CardTitle>
            </CardHeader>
            <CardContent>
              <Button variant="outline" onClick={() => setShowResetPassword(true)}>
                Reset Password
              </Button>
            </CardContent>
          </Card>
        </div>

        <ConfirmDialog
          open={showResetPassword}
          onOpenChange={setShowResetPassword}
          title="Reset Password"
          description={`Set a new password for "${user.username}".`}
          confirmLabel="Reset"
          onConfirm={handleResetPassword}
        >
          <div className="mt-4 space-y-2">
            <Label htmlFor="new-password">New Password</Label>
            <Input
              id="new-password"
              type="password"
              value={newPassword}
              onChange={(e) => { setNewPassword(e.target.value); setPasswordError("") }}
              placeholder="Min 8 characters"
            />
            {passwordError && <p className="text-xs text-[hsl(var(--destructive))]">{passwordError}</p>}
          </div>
        </ConfirmDialog>
      </div>
    </ErrorBoundary>
  )
}
