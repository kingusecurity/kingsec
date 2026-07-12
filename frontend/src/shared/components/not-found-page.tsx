import { Shield } from "lucide-react"
import { useNavigate } from "react-router-dom"
import { Button } from "@/shared/ui/button"

export function NotFoundPage(): React.ReactElement {
  const navigate = useNavigate()

  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-6 p-8 text-center">
      <Shield className="size-16 text-[hsl(var(--muted-fg))]" aria-hidden="true" />
      <div className="space-y-2">
        <h1 className="text-4xl font-bold text-[hsl(var(--fg))]">404</h1>
        <p className="text-lg text-[hsl(var(--fg-secondary))]">Page not found</p>
        <p className="text-sm text-[hsl(var(--muted-fg))]">
          The page you are looking for does not exist or has been moved.
        </p>
      </div>
      <Button onClick={() => navigate("/dashboard")}>Go to Dashboard</Button>
    </div>
  )
}
