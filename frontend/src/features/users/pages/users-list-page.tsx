import { memo, useState, useMemo } from "react"
import { useNavigate } from "react-router-dom"
import { Search, Users, UserPlus, ExternalLink, RefreshCw } from "lucide-react"
import { useUsers } from "../hooks/use-users"
import { UserRoleBadge } from "../components/user-role-badge"
import { UserStatusBadge } from "../components/user-status-badge"
import { PageHeader } from "@/shared/components/page-header"
import { EmptyState } from "@/shared/components/empty-state"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { Button } from "@/shared/ui/button"
import { Input } from "@/shared/ui/input"
import { Card, CardContent } from "@/shared/ui/card"
import { formatRelative } from "@/shared/lib/utils"
import { ROUTES } from "@/shared/lib/constants"
import { useDebounce } from "@/shared/hooks/use-debounce"
import { getApiError } from "@/shared/api/error-handler"
import type { User } from "../types"

export function UsersListPage(): React.ReactElement {
  const navigate = useNavigate()
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebounce(search, 300)

  const { data, isLoading, error, refetch, isFetching } = useUsers({ limit: 200, offset: 0 })

  const users = useMemo(() => {
    const items = data?.items ?? []
    if (!debouncedSearch) return items
    const q = debouncedSearch.toLowerCase()
    return items.filter(
      (u) =>
        u.username.toLowerCase().includes(q) ||
        u.email.toLowerCase().includes(q) ||
        u.role.toLowerCase().includes(q),
    )
  }, [data?.items, debouncedSearch])

  if (error) {
    const apiErr = getApiError(error)
    return (
      <div className="p-6">
        <PageHeader title="Users" description="Manage user accounts and permissions." />
        <div className="mt-6 flex flex-col items-center gap-4 rounded-xl border border-[hsl(var(--border))] py-16" role="alert">
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
        <PageHeader
          title="Users"
          description="Manage user accounts and permissions."
          actions={
            <Button size="sm" onClick={() => navigate(`${ROUTES.USERS}/new`)}>
              <UserPlus className="mr-2 size-4" />
              Add User
            </Button>
          }
        />

        <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-[hsl(var(--muted-fg))]" aria-hidden="true" />
            <Input
              placeholder="Search by username, email, or role..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
              aria-label="Search users"
            />
          </div>
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`mr-2 size-4 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>

        <div className="mt-4">
          {isLoading ? (
            <div className="space-y-3">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="skeleton h-20 rounded-xl" />
              ))}
            </div>
          ) : users.length === 0 ? (
            <EmptyState
              icon={<Users className="size-12" />}
              title="No users found"
              description="Create a new user to get started."
            />
          ) : (
            <div className="space-y-3">
              {users.map((user) => (
                <UserCard
                  key={user.user_id}
                  user={user}
                  onClick={() => navigate(`${ROUTES.USERS}/${user.user_id}`)}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </ErrorBoundary>
  )
}

interface UserCardProps {
  user: User
  onClick: () => void
}

const UserCard = memo(function UserCard({ user, onClick }: UserCardProps): React.ReactElement {
  return (
    <Card
      className="cursor-pointer transition-colors hover:bg-[hsl(var(--accent))]/30"
      onClick={onClick}
    >
      <CardContent className="p-4">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <h3 className="font-medium text-[hsl(var(--fg))]">{user.username}</h3>
              <UserRoleBadge role={user.role} />
              <UserStatusBadge isActive={user.is_active} />
            </div>
            <p className="text-xs text-[hsl(var(--muted-fg))]">
              {user.email}
              {user.last_login && <> · Last login {formatRelative(user.last_login)}</>}
            </p>
          </div>
          <Button variant="ghost" size="sm" onClick={(e) => { e.stopPropagation(); onClick() }}>
            <ExternalLink className="mr-1 size-4" />
            View
          </Button>
        </div>
      </CardContent>
    </Card>
  )
})
