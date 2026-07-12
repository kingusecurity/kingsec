import { useState, useCallback } from "react"
import { useNavigate } from "react-router-dom"
import { ArrowLeft, Loader2 } from "lucide-react"
import { z } from "zod"
import { useCreateUser } from "../hooks/use-users"
import { PageHeader } from "@/shared/components/page-header"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { Button } from "@/shared/ui/button"
import { Input } from "@/shared/ui/input"
import { Label } from "@/shared/ui/label"
import { Select } from "@/shared/ui/select"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { ROUTES } from "@/shared/lib/constants"
import type { UserRole } from "../types"

const createUserSchema = z.object({
  username: z.string().min(3, "Username must be at least 3 characters"),
  email: z.string().email("Invalid email address"),
  password: z.string().min(8, "Password must be at least 8 characters"),
  role: z.enum(["VIEWER", "ANALYST", "ADMIN"]),
})

type FormData = z.infer<typeof createUserSchema>

export function CreateUserPage(): React.ReactElement {
  const navigate = useNavigate()
  const createUserMutation = useCreateUser()
  const [form, setForm] = useState<FormData>({
    username: "",
    email: "",
    password: "",
    role: "VIEWER",
  })
  const [errors, setErrors] = useState<Record<string, string>>({})

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault()
      setErrors({})

      const result = createUserSchema.safeParse(form)
      if (!result.success) {
        const fieldErrors: Record<string, string> = {}
        for (const issue of result.error.issues) {
          const field = issue.path[0] as string
          fieldErrors[field] = issue.message
        }
        setErrors(fieldErrors)
        return
      }

      createUserMutation.mutate(result.data, {
        onSuccess: () => navigate(ROUTES.USERS),
      })
    },
    [form, createUserMutation, navigate],
  )

  const updateField = useCallback((field: keyof FormData, value: string) => {
    setForm((prev) => ({ ...prev, [field]: value }))
    setErrors((prev) => {
      const next = { ...prev }
      delete next[field]
      return next
    })
  }, [])

  return (
    <ErrorBoundary>
      <div className="p-6">
        <Button variant="ghost" size="sm" onClick={() => navigate(ROUTES.USERS)} className="mb-4">
          <ArrowLeft className="mr-2 size-4" />
          Back to Users
        </Button>

        <PageHeader title="Create User" description="Add a new user account." />

        <Card className="mt-6 max-w-lg">
          <CardHeader>
            <CardTitle>User Details</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  value={form.username}
                  onChange={(e) => updateField("username", e.target.value)}
                  placeholder="johndoe"
                />
                {errors.username && <p className="text-xs text-[hsl(var(--destructive))]">{errors.username}</p>}
              </div>

              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  value={form.email}
                  onChange={(e) => updateField("email", e.target.value)}
                  placeholder="john@example.com"
                />
                {errors.email && <p className="text-xs text-[hsl(var(--destructive))]">{errors.email}</p>}
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  value={form.password}
                  onChange={(e) => updateField("password", e.target.value)}
                  placeholder="Min 8 characters"
                />
                {errors.password && <p className="text-xs text-[hsl(var(--destructive))]">{errors.password}</p>}
              </div>

              <div className="space-y-2">
                <Label htmlFor="role">Role</Label>
                <Select
                  id="role"
                  value={form.role}
                  onChange={(e) => updateField("role", e.target.value as UserRole)}
                >
                  <option value="VIEWER">Viewer</option>
                  <option value="ANALYST">Analyst</option>
                  <option value="ADMIN">Admin</option>
                </Select>
                {errors.role && <p className="text-xs text-[hsl(var(--destructive))]">{errors.role}</p>}
              </div>

              <div className="flex gap-2 pt-2">
                <Button type="submit" disabled={createUserMutation.isPending}>
                  {createUserMutation.isPending && <Loader2 className="mr-2 size-4 animate-spin" />}
                  Create User
                </Button>
                <Button type="button" variant="outline" onClick={() => navigate(ROUTES.USERS)}>
                  Cancel
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </ErrorBoundary>
  )
}
