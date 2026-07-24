import { useState, useCallback } from 'react'
import { Plus } from 'lucide-react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Button } from '@/components/ui/Button'
import { Modal } from '@/components/ui/Modal'
import { UserFilters } from '@/components/features/admin/UserFilters'
import { UserTable } from '@/components/features/admin/UserTable'
import { UserForm } from '@/components/features/admin/UserForm'
import { useUsers, useCreateUser } from '@/hooks/use-admin'
import type { CreateUserFormData, EditUserFormData } from '@/components/features/admin/UserForm'

const PAGE_SIZE = 20

export function UsersPage() {
  const [search, setSearch] = useState('')
  const [roleFilter, setRoleFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [page, setPage] = useState(0)
  const [sortBy, setSortBy] = useState<'username' | 'email' | 'role' | 'created_at' | 'last_login_at'>('created_at')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')
  const [createOpen, setCreateOpen] = useState(false)

  const params = {
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
    search: search || undefined,
    role: roleFilter || undefined,
    is_active: statusFilter || undefined,
    sort_by: sortBy,
    sort_order: sortOrder,
  }

  const { data, isLoading, error, refetch } = useUsers(params)
  const createUser = useCreateUser()

  const totalPages = data ? Math.ceil(data.total / data.limit) : 0
  const hasFilters = !!(search || roleFilter || statusFilter)

  const handleClear = useCallback(() => {
    setSearch('')
    setRoleFilter('')
    setStatusFilter('')
    setPage(0)
  }, [])

  const handleSortChange = useCallback((field: typeof sortBy) => {
    setSortBy((prev) => {
      if (prev === field) {
        setSortOrder((o) => (o === 'asc' ? 'desc' : 'asc'))
        return prev
      }
      setSortOrder('asc')
      return field
    })
    setPage(0)
  }, [])

  const handleCreateUser = useCallback((data: CreateUserFormData | EditUserFormData) => {
    createUser.mutate(data as CreateUserFormData, {
      onSuccess: () => {
        setCreateOpen(false)
      },
    })
  }, [createUser])

  return (
    <PageContainer>
      <PageHeader
        title="Users"
        description="Manage user accounts and roles"
        actions={
          <Button onClick={() => setCreateOpen(true)} iconLeft={<Plus className="h-4 w-4" />}>
            Create User
          </Button>
        }
      />

      <UserFilters
        search={search}
        roleFilter={roleFilter}
        statusFilter={statusFilter}
        onSearchChange={(v) => { setSearch(v); setPage(0) }}
        onRoleFilterChange={(v) => { setRoleFilter(v); setPage(0) }}
        onStatusFilterChange={(v) => { setStatusFilter(v); setPage(0) }}
        onClear={handleClear}
        hasFilters={hasFilters}
      />

      <UserTable
        users={data?.items}
        isLoading={isLoading}
        error={error as Error | null}
        onRetry={() => refetch()}
        currentPage={page + 1}
        totalPages={totalPages}
        onPageChange={(p) => setPage(p - 1)}
        sortBy={sortBy}
        sortOrder={sortOrder}
        onSortChange={handleSortChange}
      />

      <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="Create User" size="md">
        <UserForm
          mode="create"
          onSubmit={handleCreateUser}
          isPending={createUser.isPending}
        />
      </Modal>
    </PageContainer>
  )
}
