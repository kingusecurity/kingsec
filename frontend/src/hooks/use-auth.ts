import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { authApi } from '@/api/auth'
import { settingsApi } from '@/api/settings'
import { setTokens, clearTokens, setLogoutHandler } from '@/api/client'
import { useAuthStore } from '@/store/auth'
import type { LoginBody, RegisterUserBody } from '@/types/api'

export function useLogin() {
  const setUser = useAuthStore((s) => s.setUser)
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: LoginBody) => authApi.login(data),
    onSuccess: (data) => {
      setTokens(data.access_token, data.refresh_token)
      setUser({
        user_id: data.user_id,
        username: data.username,
        role: data.role,
        email: '',
        is_active: true,
        created_at: '',
        last_login_at: null,
      })
      queryClient.invalidateQueries()
    },
  })
}

export function useRegister() {
  return useMutation({
    mutationFn: (data: RegisterUserBody) => authApi.register(data),
  })
}

export function useMe() {
  const setUser = useAuthStore((s) => s.setUser)

  return useQuery({
    queryKey: ['auth', 'me'],
    queryFn: async () => {
      const user = await authApi.me()
      setUser(user)
      return user
    },
    retry: false,
    staleTime: 5 * 60 * 1000,
  })
}

export function useLogout() {
  const clearUser = useAuthStore((s) => s.clearUser)
  const queryClient = useQueryClient()

  return () => {
    // Best-effort: revoke the session server-side too, but never let a failed
    // (e.g. already-expired) revocation call block the local sign-out.
    settingsApi.deleteCurrentSession().catch(() => undefined)
    clearTokens()
    clearUser()
    queryClient.clear()
    window.dispatchEvent(
      new CustomEvent('kingsec-toast', {
        detail: { variant: 'info' as const, title: 'Signed out', message: 'You have been signed out.' },
      }),
    )
  }
}

export function useAuthInit() {
  const logout = useLogout()

  setLogoutHandler(() => {
    window.dispatchEvent(
      new CustomEvent('kingsec-toast', {
        detail: { variant: 'info' as const, title: 'Session expired', message: 'Please sign in again.' },
      }),
    )
    logout()
  })
}
