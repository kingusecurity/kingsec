import { describe, it, expect, vi, beforeEach } from "vitest"
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
import { apiClient } from "@/shared/api/client"

vi.mock("@/shared/api/client", () => ({
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
  },
}))

describe("Settings API", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("getProfileSettings calls GET /auth/me", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: { full_name: "John", email: "john@test.com" } })
    const result = await getProfileSettings()
    expect(apiClient.get).toHaveBeenCalledWith("/auth/me")
    expect(result.full_name).toBe("John")
  })

  it("updateProfileSettings calls PATCH /auth/me", async () => {
    vi.mocked(apiClient.patch).mockResolvedValue({ data: { full_name: "Jane" } })
    await updateProfileSettings({ full_name: "Jane", email: "jane@test.com", timezone: "UTC", language: "en" })
    expect(apiClient.patch).toHaveBeenCalledWith("/auth/me", { full_name: "Jane", email: "jane@test.com", timezone: "UTC", language: "en" })
  })

  it("changePassword calls POST /auth/change-password", async () => {
    vi.mocked(apiClient.post).mockResolvedValue({})
    await changePassword("old", "new12345")
    expect(apiClient.post).toHaveBeenCalledWith("/auth/change-password", { current_password: "old", new_password: "new12345" })
  })

  it("logoutAllSessions calls POST /auth/logout-all", async () => {
    vi.mocked(apiClient.post).mockResolvedValue({})
    await logoutAllSessions()
    expect(apiClient.post).toHaveBeenCalledWith("/auth/logout-all")
  })

  it("getActiveSessions calls GET /auth/sessions", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: [] })
    const result = await getActiveSessions()
    expect(apiClient.get).toHaveBeenCalledWith("/auth/sessions")
    expect(result).toEqual([])
  })

  it("revokeSession calls DELETE /auth/sessions/:id", async () => {
    vi.mocked(apiClient.delete).mockResolvedValue({})
    await revokeSession("s1")
    expect(apiClient.delete).toHaveBeenCalledWith("/auth/sessions/s1")
  })

  it("listApiKeys calls GET /auth/api-keys", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: [] })
    await listApiKeys()
    expect(apiClient.get).toHaveBeenCalledWith("/auth/api-keys")
  })

  it("generateApiKey calls POST /auth/api-keys", async () => {
    vi.mocked(apiClient.post).mockResolvedValue({ data: { key_id: "k1", raw_key: "sk-abc" } })
    const result = await generateApiKey("my-key")
    expect(apiClient.post).toHaveBeenCalledWith("/auth/api-keys", { name: "my-key" })
    expect(result.raw_key).toBe("sk-abc")
  })

  it("revokeApiKey calls DELETE /auth/api-keys/:id", async () => {
    vi.mocked(apiClient.delete).mockResolvedValue({})
    await revokeApiKey("k1")
    expect(apiClient.delete).toHaveBeenCalledWith("/auth/api-keys/k1")
  })

  it("getSystemInfo calls GET /system/info", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: { frontend_version: "1.0.0" } })
    const result = await getSystemInfo()
    expect(apiClient.get).toHaveBeenCalledWith("/system/info")
    expect(result.frontend_version).toBe("1.0.0")
  })
})
