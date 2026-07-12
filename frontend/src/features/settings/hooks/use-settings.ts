import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  getProfileSettings,
  updateProfileSettings,
  changePassword,
  logoutAllSessions,
  getActiveSessions,
  revokeSession,
  listApiKeys,
  generateApiKey,
  revokeApiKey,
  getSystemInfo,
} from "../api/settings"
import { getApiError } from "@/shared/api/error-handler"
import type { ProfileSettings } from "../types"

export const settingsKeys = {
  all: ["settings"] as const,
  profile: () => [...settingsKeys.all, "profile"] as const,
  sessions: () => [...settingsKeys.all, "sessions"] as const,
  apiKeys: () => [...settingsKeys.all, "api-keys"] as const,
  systemInfo: () => [...settingsKeys.all, "system-info"] as const,
}

export function useProfileSettings() {
  return useQuery({
    queryKey: settingsKeys.profile(),
    queryFn: getProfileSettings,
  })
}

export function useUpdateProfileSettings() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: ProfileSettings) => updateProfileSettings(data),
    onSuccess: (data) => {
      queryClient.setQueryData(settingsKeys.profile(), data)
      toast.success("Profile updated")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}

export function useChangePassword() {
  return useMutation({
    mutationFn: ({ currentPassword, newPassword }: { currentPassword: string; newPassword: string }) =>
      changePassword(currentPassword, newPassword),
    onSuccess: () => {
      toast.success("Password changed")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}

export function useLogoutAllSessions() {
  return useMutation({
    mutationFn: logoutAllSessions,
    onSuccess: () => {
      toast.success("All sessions terminated")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}

export function useActiveSessions() {
  return useQuery({
    queryKey: settingsKeys.sessions(),
    queryFn: getActiveSessions,
  })
}

export function useRevokeSession() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (sessionId: string) => revokeSession(sessionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: settingsKeys.sessions() })
      toast.success("Session revoked")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}

export function useApiKeys() {
  return useQuery({
    queryKey: settingsKeys.apiKeys(),
    queryFn: listApiKeys,
  })
}

export function useGenerateApiKey() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (name: string) => generateApiKey(name),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: settingsKeys.apiKeys() })
      toast.success("API key generated")
      return data
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}

export function useRevokeApiKey() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (keyId: string) => revokeApiKey(keyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: settingsKeys.apiKeys() })
      toast.success("API key revoked")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}

export function useSystemInfo() {
  return useQuery({
    queryKey: settingsKeys.systemInfo(),
    queryFn: getSystemInfo,
  })
}
