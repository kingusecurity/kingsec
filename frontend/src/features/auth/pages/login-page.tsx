import { Shield } from "lucide-react"
import { LoginForm } from "../components/login-form"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card"

export function LoginPage(): React.ReactElement {
  return (
    <div className="flex min-h-screen items-center justify-center bg-[hsl(var(--bg))] p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1 text-center">
          <div className="mx-auto mb-2 flex size-12 items-center justify-center rounded-lg bg-[hsl(var(--primary))]/10">
            <Shield className="size-6 text-[hsl(var(--primary))]" />
          </div>
          <CardTitle className="text-2xl">KingSec</CardTitle>
          <CardDescription>Attack Surface Management Platform</CardDescription>
        </CardHeader>
        <CardContent>
          <LoginForm />
        </CardContent>
      </Card>
    </div>
  )
}
