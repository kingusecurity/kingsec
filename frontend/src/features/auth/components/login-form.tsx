import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { toast } from "sonner"
import { Loader2 } from "lucide-react"
import { loginApi } from "../api/auth"
import { useAuth } from "../hooks/use-auth"
import { loginSchema, type LoginFormData } from "../validation/auth"
import { getApiError } from "@/shared/api/error-handler"
import { Button } from "@/shared/ui/button"
import { Input } from "@/shared/ui/input"
import { Label } from "@/shared/ui/label"

export function LoginForm(): React.ReactElement {
  const { login } = useAuth()
  const [loading, setLoading] = useState(false)

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
  })

  async function onSubmit(data: LoginFormData): Promise<void> {
    setLoading(true)
    try {
      const response = await loginApi(data)
      await login(response.access_token, response.refresh_token)
      toast.success("Logged in successfully")
    } catch (err) {
      const apiErr = getApiError(err)
      toast.error(apiErr.detail)
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="username">Username</Label>
        <Input id="username" placeholder="Enter username" {...register("username")} />
        {errors.username && (
          <p className="text-xs text-[hsl(var(--destructive))]">{errors.username.message}</p>
        )}
      </div>
      <div className="space-y-2">
        <Label htmlFor="password">Password</Label>
        <Input id="password" type="password" placeholder="Enter password" {...register("password")} />
        {errors.password && (
          <p className="text-xs text-[hsl(var(--destructive))]">{errors.password.message}</p>
        )}
      </div>
      <Button type="submit" className="w-full" disabled={loading}>
        {loading ? <Loader2 className="mr-2 size-4 animate-spin" /> : null}
        Sign In
      </Button>
    </form>
  )
}
