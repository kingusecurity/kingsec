import { Navigate } from "react-router-dom"
import { useAuth } from "../hooks/use-auth"
import { PageSkeleton } from "@/shared/components/loading-skeleton"
import { ROUTES } from "@/shared/lib/constants"

interface ProtectedRouteProps {
  children: React.ReactNode
  requiredRole?: "VIEWER" | "ANALYST" | "ADMIN"
}

const ROLE_LEVEL: Record<string, number> = { VIEWER: 10, ANALYST: 20, ADMIN: 30 }

export function ProtectedRoute({ children, requiredRole }: ProtectedRouteProps): React.ReactElement {
  const { user, isLoading, isAuthenticated } = useAuth()

  if (isLoading) {
    return <PageSkeleton />
  }

  if (!isAuthenticated || !user) {
    return <Navigate to={ROUTES.LOGIN} replace />
  }

  if (requiredRole && ROLE_LEVEL[user.role] < ROLE_LEVEL[requiredRole]) {
    return <Navigate to={ROUTES.DASHBOARD} replace />
  }

  return <>{children}</>
}
