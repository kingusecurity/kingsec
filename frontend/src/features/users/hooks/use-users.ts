import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  listUsers,
  getUser,
  createUser,
  updateUser,
  deleteUser,
  resetPassword,
  getUserSessions,
  revokeSession,
  getUserAuditEntries,
} from "../api/users"
import { getApiError } from "@/shared/api/error-handler"
import type { CreateUserRequest, UpdateUserRequest, ResetPasswordRequest } from "../types"

export const userKeys = {
  all: ["users"] as const,
  lists: () => [...userKeys.all, "list"] as const,
  list: (params?: { limit?: number; offset?: number }) => [...userKeys.lists(), params] as const,
  details: () => [...userKeys.all, "detail"] as const,
  detail: (id: string) => [...userKeys.details(), id] as const,
  sessions: (id: string) => [...userKeys.all, "sessions", id] as const,
  audit: (id: string) => [...userKeys.all, "audit", id] as const,
}

export function useUsers(params?: { limit?: number; offset?: number }) {
  return useQuery({
    queryKey: userKeys.list(params),
    queryFn: () => listUsers(params),
  })
}

export function useUser(userId: string) {
  return useQuery({
    queryKey: userKeys.detail(userId),
    queryFn: () => getUser(userId),
    enabled: !!userId,
  })
}

export function useCreateUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: CreateUserRequest) => createUser(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.lists() })
      toast.success("User created")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}

export function useUpdateUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ userId, data }: { userId: string; data: UpdateUserRequest }) => updateUser(userId, data),
    onSuccess: (_, { userId }) => {
      queryClient.invalidateQueries({ queryKey: userKeys.detail(userId) })
      queryClient.invalidateQueries({ queryKey: userKeys.lists() })
      toast.success("User updated")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}

export function useDeleteUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (userId: string) => deleteUser(userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.lists() })
      toast.success("User deleted")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}

export function useResetPassword() {
  return useMutation({
    mutationFn: ({ userId, data }: { userId: string; data: ResetPasswordRequest }) => resetPassword(userId, data),
    onSuccess: () => {
      toast.success("Password reset")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}

export function useUserSessions(userId: string) {
  return useQuery({
    queryKey: userKeys.sessions(userId),
    queryFn: () => getUserSessions(userId),
    enabled: !!userId,
  })
}

export function useRevokeSession() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ userId, sessionId }: { userId: string; sessionId: string }) => revokeSession(userId, sessionId),
    onSuccess: (_, { userId }) => {
      queryClient.invalidateQueries({ queryKey: userKeys.sessions(userId) })
      toast.success("Session revoked")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}

export function useUserAuditEntries(userId: string, params?: { limit?: number; offset?: number }) {
  return useQuery({
    queryKey: [...userKeys.audit(userId), params],
    queryFn: () => getUserAuditEntries(userId, params),
    enabled: !!userId,
  })
}
