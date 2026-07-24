import { Link } from 'react-router-dom'
import { ArrowRight, ChevronUp, ChevronDown } from 'lucide-react'
import { Pagination } from '@/components/ui/Pagination'
import { TableSkeleton } from '@/components/ui/Skeleton'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ui/ErrorState'
import { UserStatusBadge } from './UserStatusBadge'
import { RoleBadge } from './RoleBadge'
import { formatDate } from '@/lib/utils'
import type { AdminUser } from '@/api/admin'

type SortField = 'username' | 'email' | 'role' | 'created_at' | 'last_login_at'

interface UserTableProps {
  users: AdminUser[] | undefined
  isLoading: boolean
  error: Error | null
  onRetry: () => void
  currentPage: number
  totalPages: number
  onPageChange: (page: number) => void
  sortBy: SortField
  sortOrder: 'asc' | 'desc'
  onSortChange: (field: SortField) => void
}

const sortableColumns: { field: SortField; label: string }[] = [
  { field: 'username', label: 'Username' },
  { field: 'email', label: 'Email' },
  { field: 'role', label: 'Role' },
  { field: 'last_login_at', label: 'Last Login' },
  { field: 'created_at', label: 'Created' },
]

export function UserTable({
  users,
  isLoading,
  error,
  onRetry,
  currentPage,
  totalPages,
  onPageChange,
  sortBy,
  sortOrder,
  onSortChange,
}: UserTableProps) {
  if (error) {
    return (
      <div className="rounded-xl border border-border bg-surface-secondary p-5">
        <ErrorState title="Failed to load users" message={error.message} onRetry={onRetry} />
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="rounded-xl border border-border bg-surface-secondary p-5">
        <TableSkeleton rows={8} />
      </div>
    )
  }

  if (!users || users.length === 0) {
    return (
      <div className="rounded-xl border border-border bg-surface-secondary">
        <EmptyState title="No users found" description="No users match your search criteria." />
      </div>
    )
  }

  return (
    <div className="rounded-xl border border-border bg-surface-secondary overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-surface-tertiary">
              {sortableColumns.map((col) => (
                <th
                  key={col.field}
                  scope="col"
                  className="px-5 py-3 text-left font-medium text-text-secondary cursor-pointer select-none hover:text-text-primary"
                  onClick={() => onSortChange(col.field)}
                  aria-label={`Sort by ${col.label}`}
                >
                  <div className="flex items-center gap-1">
                    {col.label}
                    {sortBy === col.field && (
                      sortOrder === 'asc' ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />
                    )}
                  </div>
                </th>
              ))}
              <th scope="col" className="px-5 py-3 text-left font-medium text-text-secondary">Status</th>
              <th scope="col" className="px-5 py-3 w-10" />
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr
                key={user.user_id}
                className="border-b border-border transition-colors hover:bg-surface-tertiary/50"
              >
                <td className="px-5 py-3">
                  <Link
                    to={`/admin/users/${user.user_id}`}
                    className="font-medium text-accent hover:text-emerald-400 transition-colors"
                  >
                    {user.username}
                  </Link>
                </td>
                <td className="px-5 py-3 text-text-secondary">{user.email}</td>
                <td className="px-5 py-3">
                  <RoleBadge role={user.role} />
                </td>
                <td className="px-5 py-3 text-text-secondary whitespace-nowrap">
                  {user.last_login_at ? formatDate(user.last_login_at) : 'Never'}
                </td>
                <td className="px-5 py-3 text-text-secondary whitespace-nowrap">
                  {formatDate(user.created_at)}
                </td>
                <td className="px-5 py-3">
                  <UserStatusBadge isActive={user.is_active} />
                </td>
                <td className="px-5 py-3">
                  <Link
                    to={`/admin/users/${user.user_id}`}
                    className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-text-muted hover:text-text-primary hover:bg-surface-tertiary"
                    aria-label={`View user: ${user.username}`}
                  >
                    <ArrowRight className="h-4 w-4" />
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {totalPages > 1 && (
        <div className="flex justify-center border-t border-border px-5 py-4">
          <Pagination currentPage={currentPage} totalPages={totalPages} onPageChange={onPageChange} />
        </div>
      )}
    </div>
  )
}
