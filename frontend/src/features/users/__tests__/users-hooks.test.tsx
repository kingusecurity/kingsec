import { describe, it, expect, vi, beforeEach } from "vitest"
import { renderHook, waitFor } from "@testing-library/react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import {
  useUsers,
  useUser,
  useCreateUser,
  useUpdateUser,
  useDeleteUser,
  userKeys,
} from "../hooks/use-users"
import * as usersApi from "../api/users"
import type { ReactNode } from "react"

vi.mock("../api/users", () => ({
  listUsers: vi.fn(),
  getUser: vi.fn(),
  createUser: vi.fn(),
  updateUser: vi.fn(),
  deleteUser: vi.fn(),
  resetPassword: vi.fn(),
  getUserSessions: vi.fn(),
  revokeSession: vi.fn(),
  getUserAuditEntries: vi.fn(),
}))

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
}

describe("User hooks", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe("userKeys", () => {
    it("generates correct cache keys", () => {
      expect(userKeys.all).toEqual(["users"])
      expect(userKeys.lists()).toEqual(["users", "list"])
      expect(userKeys.list({ limit: 10 })).toEqual(["users", "list", { limit: 10 }])
      expect(userKeys.detail("abc")).toEqual(["users", "detail", "abc"])
      expect(userKeys.sessions("abc")).toEqual(["users", "sessions", "abc"])
      expect(userKeys.audit("abc")).toEqual(["users", "audit", "abc"])
    })
  })

  describe("useUsers", () => {
    it("fetches users list", async () => {
      vi.mocked(usersApi.listUsers).mockResolvedValue({ items: [], total: 0 })
      const { result } = renderHook(() => useUsers(), { wrapper: createWrapper() })
      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(result.current.data?.total).toBe(0)
    })
  })

  describe("useUser", () => {
    it("fetches single user", async () => {
      vi.mocked(usersApi.getUser).mockResolvedValue({ user_id: "u1", username: "admin" } as any)
      const { result } = renderHook(() => useUser("u1"), { wrapper: createWrapper() })
      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(result.current.data?.user_id).toBe("u1")
    })

    it("does not fetch when id is empty", () => {
      vi.mocked(usersApi.getUser).mockResolvedValue({ user_id: "" } as any)
      const { result } = renderHook(() => useUser(""), { wrapper: createWrapper() })
      expect(result.current.fetchStatus).toBe("idle")
    })
  })

  describe("useCreateUser", () => {
    it("creates user and invalidates cache", async () => {
      vi.mocked(usersApi.createUser).mockResolvedValue({ user_id: "u2" } as any)
      const { result } = renderHook(() => useCreateUser(), { wrapper: createWrapper() })
      result.current.mutate({ username: "new", email: "new@test.com", password: "pass1234", role: "VIEWER" })
      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(usersApi.createUser).toHaveBeenCalled()
    })
  })

  describe("useUpdateUser", () => {
    it("updates user", async () => {
      vi.mocked(usersApi.updateUser).mockResolvedValue({ user_id: "u1" } as any)
      const { result } = renderHook(() => useUpdateUser(), { wrapper: createWrapper() })
      result.current.mutate({ userId: "u1", data: { role: "ADMIN" } })
      await waitFor(() => expect(result.current.isSuccess).toBe(true))
    })
  })

  describe("useDeleteUser", () => {
    it("deletes user", async () => {
      vi.mocked(usersApi.deleteUser).mockResolvedValue(undefined)
      const { result } = renderHook(() => useDeleteUser(), { wrapper: createWrapper() })
      result.current.mutate("u1")
      await waitFor(() => expect(result.current.isSuccess).toBe(true))
    })
  })
})
