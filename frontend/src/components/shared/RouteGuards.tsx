import { Navigate, useLocation } from 'react-router-dom'
import { useAuthStore } from '@/store/auth'
import { LoadingState } from '@/components/ui'
import { useMe } from '@/hooks/use-auth'

const roleHierarchy: Record<string, number> = {
  viewer: 10,
  analyst: 20,
  admin: 30,
}

interface AuthGuardProps {
  children: React.ReactNode
}

export function AuthGuard({ children }: AuthGuardProps) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const location = useLocation()

  const { isLoading } = useMe()

  if (isLoading) {
    return <LoadingState message="Verifying session..." />
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  return <>{children}</>
}

interface RoleGuardProps {
  roles: string[]
  children: React.ReactNode
  fallback?: React.ReactNode
}

export function RoleGuard({ roles, children, fallback }: RoleGuardProps) {
  const user = useAuthStore((s) => s.user)
  const location = useLocation()

  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  const userLevel = roleHierarchy[user.role.toLowerCase()] ?? 0
  const requiredLevel = Math.min(...roles.map((r) => roleHierarchy[r.toLowerCase()] ?? 99))

  if (userLevel < requiredLevel) {
    if (fallback) {
      return <>{fallback}</>
    }

    return <Navigate to="/unauthorized" state={{ from: location }} replace />
  }

  return <>{children}</>
}

interface GuestGuardProps {
  children: React.ReactNode
}

export function GuestGuard({ children }: GuestGuardProps) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />
  }

  return <>{children}</>
}
