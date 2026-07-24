import { useState, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, Edit3, Trash2, Lock, Ban, CheckCircle } from 'lucide-react'
import { PageContainer } from '@/components/layout/PageContainer'
import { Button } from '@/components/ui/Button'
import { Modal } from '@/components/ui/Modal'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ui/ErrorState'
import { UserCard } from '@/components/features/admin/UserCard'
import { UserForm } from '@/components/features/admin/UserForm'
import { formatDate } from '@/lib/utils'
import { useUser, useUpdateUser, useDeleteUser, useEnableUser, useDisableUser, useResetPassword } from '@/hooks/use-admin'
import type { EditUserFormData } from '@/components/features/admin/UserForm'

export function UserDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data: user, isLoading, error, refetch } = useUser(id ?? '')
  const updateUser = useUpdateUser()
  const deleteUser = useDeleteUser()
  const enableUser = useEnableUser()
  const disableUser = useDisableUser()
  const resetPassword = useResetPassword()

  const [editOpen, setEditOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)

  const handleEdit = useCallback((data: EditUserFormData) => {
    if (!id) return
    updateUser.mutate({ id, data }, {
      onSuccess: () => setEditOpen(false),
    })
  }, [id, updateUser])

  const handleDelete = useCallback(() => {
    if (!id) return
    deleteUser.mutate(id, {
      onSuccess: () => setDeleteOpen(false),
    })
  }, [id, deleteUser])

  const handleToggleActive = useCallback(() => {
    if (!id) return
    if (user?.is_active) {
      disableUser.mutate(id)
    } else {
      enableUser.mutate(id)
    }
  }, [id, user, enableUser, disableUser])

  const handleResetPassword = useCallback(() => {
    if (!id) return
    resetPassword.mutate(id)
  }, [id, resetPassword])

  if (error) {
    return (
      <PageContainer>
        <ErrorState title="Failed to load user" message={(error as Error).message} onRetry={refetch} />
      </PageContainer>
    )
  }

  return (
    <PageContainer>
      <Link
        to="/admin/users"
        className="inline-flex items-center gap-1.5 text-sm text-text-secondary hover:text-text-primary transition-colors"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to users
      </Link>

      <UserCard user={user} isLoading={isLoading} />

      <div className="flex flex-wrap gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => setEditOpen(true)}
          iconLeft={<Edit3 className="h-4 w-4" />}
        >
          Edit User
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={handleToggleActive}
          loading={enableUser.isPending || disableUser.isPending}
          iconLeft={user?.is_active ? <Ban className="h-4 w-4" /> : <CheckCircle className="h-4 w-4" />}
        >
          {user?.is_active ? 'Disable User' : 'Enable User'}
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={handleResetPassword}
          loading={resetPassword.isPending}
          iconLeft={<Lock className="h-4 w-4" />}
        >
          Reset Password
        </Button>
        <Button
          variant="danger"
          size="sm"
          onClick={() => setDeleteOpen(true)}
          loading={deleteUser.isPending}
          iconLeft={<Trash2 className="h-4 w-4" />}
        >
          Delete User
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>User Information</CardTitle>
          <CardDescription>Detailed account information</CardDescription>
        </CardHeader>
        <div className="px-5 pb-5">
          {isLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-5 w-full" />
              <Skeleton className="h-5 w-3/4" />
            </div>
          ) : user ? (
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <p className="text-xs text-text-muted">User ID</p>
                <p className="text-sm font-mono text-text-primary">{user.user_id}</p>
              </div>
              <div>
                <p className="text-xs text-text-muted">Username</p>
                <p className="text-sm font-medium text-text-primary">{user.username}</p>
              </div>
              <div>
                <p className="text-xs text-text-muted">Email</p>
                <p className="text-sm font-medium text-text-primary">{user.email}</p>
              </div>
              <div>
                <p className="text-xs text-text-muted">Role</p>
                <p className="text-sm font-medium text-text-primary capitalize">{user.role}</p>
              </div>
              <div>
                <p className="text-xs text-text-muted">Status</p>
                <p className="text-sm font-medium text-text-primary">{user.is_active ? 'Active' : 'Inactive'}</p>
              </div>
              <div>
                <p className="text-xs text-text-muted">Last Login</p>
                <p className="text-sm font-medium text-text-primary">{user.last_login_at ? formatDate(user.last_login_at) : 'Never'}</p>
              </div>
              <div>
                <p className="text-xs text-text-muted">Member Since</p>
                <p className="text-sm font-medium text-text-primary">{formatDate(user.created_at)}</p>
              </div>
            </div>
          ) : (
            <p className="text-sm text-text-secondary">User not found.</p>
          )}
        </div>
      </Card>

      <Modal open={editOpen} onClose={() => setEditOpen(false)} title="Edit User" size="md">
        <UserForm
          mode="edit"
          defaultValues={{ email: user?.email ?? '', role: user?.role ?? 'viewer' }}
          onSubmit={handleEdit}
          isPending={updateUser.isPending}
        />
      </Modal>

      <ConfirmDialog
        open={deleteOpen}
        onClose={() => setDeleteOpen(false)}
        onConfirm={handleDelete}
        title="Delete User"
        message={`Are you sure you want to delete ${user?.username ?? 'this user'}? This action cannot be undone.`}
        confirmLabel="Delete"
        loading={deleteUser.isPending}
      />
    </PageContainer>
  )
}
