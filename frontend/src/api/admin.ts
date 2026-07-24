import { apiRequest } from './client'

export interface AdminUser {
  user_id: string
  username: string
  email: string
  role: string
  is_active: boolean
  created_at: string
  last_login_at: string | null
}

export interface CreateUserBody {
  username: string
  email: string
  password: string
  role: string
}

export interface UpdateUserBody {
  email?: string
  role?: string
}

export interface AdminUserListResponse {
  items: AdminUser[]
  total: number
  limit: number
  offset: number
}

export interface AdminStats {
  total_users: number
  active_users: number
  disabled_users: number
  admin_count: number
  analyst_count: number
  viewer_count: number
}

export interface RolePermission {
  role: string
  description: string
  permissions: string[]
  accessible_modules: string[]
}

export interface RoleListResponse {
  roles: RolePermission[]
}

export const adminApi = {
  listUsers: (params?: { limit?: number; offset?: number; search?: string; role?: string; is_active?: string; sort_by?: string; sort_order?: string }) =>
    apiRequest<AdminUserListResponse>('/admin/users', { params }),

  getUser: (id: string) =>
    apiRequest<AdminUser>('/admin/users/' + id),

  createUser: (data: CreateUserBody) =>
    apiRequest<AdminUser>('/admin/users', { method: 'POST', body: data }),

  updateUser: (id: string, data: UpdateUserBody) =>
    apiRequest<AdminUser>('/admin/users/' + id, { method: 'PUT', body: data }),

  deleteUser: (id: string) =>
    apiRequest<void>('/admin/users/' + id, { method: 'DELETE' }),

  enableUser: (id: string) =>
    apiRequest<AdminUser>('/admin/users/' + id + '/enable', { method: 'PUT' }),

  disableUser: (id: string) =>
    apiRequest<AdminUser>('/admin/users/' + id + '/disable', { method: 'PUT' }),

  resetPassword: (id: string) =>
    apiRequest<void>('/admin/users/' + id + '/reset-password', { method: 'POST' }),

  getStats: () =>
    apiRequest<AdminStats>('/admin/stats'),

  listRoles: () =>
    apiRequest<RoleListResponse>('/admin/roles'),
}

export type { ApiError } from './client'
