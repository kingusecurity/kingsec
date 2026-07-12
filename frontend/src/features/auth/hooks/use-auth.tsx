import { createContext, useContext, useCallback, useState, useEffect, type ReactNode } from "react"
import { useNavigate } from "react-router-dom"
import type { User } from "../types"
import { getMeApi } from "../api/auth"
import {
  setTokens,
  clearTokens,
  getStoredToken,
} from "@/shared/api/client"
import { ROUTES } from "@/shared/lib/constants"

interface AuthState {
  user: User | null
  isLoading: boolean
  isAuthenticated: boolean
  login: (accessToken: string, refreshToken: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }): React.ReactElement {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const navigate = useNavigate()

  const fetchUser = useCallback(async (): Promise<boolean> => {
    const token = getStoredToken()
    if (!token) return false
    try {
      const me = await getMeApi()
      setUser(me)
      return true
    } catch {
      clearTokens()
      setUser(null)
      return false
    }
  }, [])

  useEffect(() => {
    fetchUser().finally(() => setIsLoading(false))
  }, [fetchUser])

  const login = useCallback(
    async (accessToken: string, refreshToken: string): Promise<void> => {
      setTokens(accessToken, refreshToken)
      const me = await getMeApi()
      setUser(me)
      navigate(ROUTES.DASHBOARD)
    },
    [navigate],
  )

  const logout = useCallback(() => {
    clearTokens()
    setUser(null)
    navigate(ROUTES.LOGIN)
  }, [navigate])

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAuthenticated: !!user,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider")
  }
  return context
}
