import { describe, it, expect, vi, beforeEach } from "vitest"
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
import { apiClient } from "@/shared/api/client"

vi.mock("@/shared/api/client", () => ({
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
  },
}))

describe("Users API", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("listUsers calls GET /auth/users", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: { items: [], total: 0 } })
    const result = await listUsers({ limit: 10, offset: 0 })
    expect(apiClient.get).toHaveBeenCalledWith("/auth/users", { params: { limit: 10, offset: 0 } })
    expect(result.total).toBe(0)
  })

  it("getUser calls GET /auth/users/:id", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: { user_id: "u1", username: "admin" } })
    const result = await getUser("u1")
    expect(apiClient.get).toHaveBeenCalledWith("/auth/users/u1")
    expect(result.user_id).toBe("u1")
  })

  it("createUser calls POST /auth/users", async () => {
    vi.mocked(apiClient.post).mockResolvedValue({ data: { user_id: "u2", username: "new" } })
    await createUser({ username: "new", email: "new@test.com", password: "pass1234", role: "VIEWER" })
    expect(apiClient.post).toHaveBeenCalledWith("/auth/users", {
      username: "new", email: "new@test.com", password: "pass1234", role: "VIEWER",
    })
  })

  it("updateUser calls PATCH /auth/users/:id", async () => {
    vi.mocked(apiClient.patch).mockResolvedValue({ data: { user_id: "u1" } })
    await updateUser("u1", { role: "ADMIN" })
    expect(apiClient.patch).toHaveBeenCalledWith("/auth/users/u1", { role: "ADMIN" })
  })

  it("deleteUser calls DELETE /auth/users/:id", async () => {
    vi.mocked(apiClient.delete).mockResolvedValue({})
    await deleteUser("u1")
    expect(apiClient.delete).toHaveBeenCalledWith("/auth/users/u1")
  })

  it("resetPassword calls POST /auth/users/:id/reset-password", async () => {
    vi.mocked(apiClient.post).mockResolvedValue({})
    await resetPassword("u1", { new_password: "newpass123" })
    expect(apiClient.post).toHaveBeenCalledWith("/auth/users/u1/reset-password", { new_password: "newpass123" })
  })

  it("getUserSessions calls GET /auth/users/:id/sessions", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: [] })
    await getUserSessions("u1")
    expect(apiClient.get).toHaveBeenCalledWith("/auth/users/u1/sessions")
  })

  it("revokeSession calls DELETE /auth/users/:id/sessions/:sid", async () => {
    vi.mocked(apiClient.delete).mockResolvedValue({})
    await revokeSession("u1", "s1")
    expect(apiClient.delete).toHaveBeenCalledWith("/auth/users/u1/sessions/s1")
  })

  it("getUserAuditEntries calls GET /auth/users/:id/audit", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: { items: [], total: 0 } })
    await getUserAuditEntries("u1", { limit: 10 })
    expect(apiClient.get).toHaveBeenCalledWith("/auth/users/u1/audit", { params: { limit: 10 } })
  })
})
