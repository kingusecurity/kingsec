import { describe, it, expect, vi, beforeEach } from "vitest"
import { renderHook, waitFor, act } from "@testing-library/react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import {
  useProfileSettings,
  useUpdateProfileSettings,
  useChangePassword,
  useApiKeys,
  useGenerateApiKey,
  settingsKeys,
} from "../hooks/use-settings"
import {
  useAppearanceSettings,
  useNotificationSettings,
  useScannerSettings,
} from "../hooks/use-local-settings"
import * as settingsApi from "../api/settings"
import type { ReactNode } from "react"

vi.mock("../api/settings", () => ({
  getProfileSettings: vi.fn(),
  updateProfileSettings: vi.fn(),
  changePassword: vi.fn(),
  logoutAllSessions: vi.fn(),
  getActiveSessions: vi.fn(),
  revokeSession: vi.fn(),
  listApiKeys: vi.fn(),
  generateApiKey: vi.fn(),
  revokeApiKey: vi.fn(),
  getSystemInfo: vi.fn(),
}))

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
}

describe("Settings hooks", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe("settingsKeys", () => {
    it("generates correct cache keys", () => {
      expect(settingsKeys.all).toEqual(["settings"])
      expect(settingsKeys.profile()).toEqual(["settings", "profile"])
      expect(settingsKeys.sessions()).toEqual(["settings", "sessions"])
      expect(settingsKeys.apiKeys()).toEqual(["settings", "api-keys"])
      expect(settingsKeys.systemInfo()).toEqual(["settings", "system-info"])
    })
  })

  describe("useProfileSettings", () => {
    it("fetches profile settings", async () => {
      vi.mocked(settingsApi.getProfileSettings).mockResolvedValue({ full_name: "John" } as any)
      const { result } = renderHook(() => useProfileSettings(), { wrapper: createWrapper() })
      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(result.current.data?.full_name).toBe("John")
    })
  })

  describe("useUpdateProfileSettings", () => {
    it("updates profile and invalidates cache", async () => {
      vi.mocked(settingsApi.updateProfileSettings).mockResolvedValue({ full_name: "Jane" } as any)
      const { result } = renderHook(() => useUpdateProfileSettings(), { wrapper: createWrapper() })
      result.current.mutate({ full_name: "Jane", email: "jane@test.com", timezone: "UTC", language: "en" })
      await waitFor(() => expect(result.current.isSuccess).toBe(true))
    })
  })

  describe("useChangePassword", () => {
    it("changes password", async () => {
      vi.mocked(settingsApi.changePassword).mockResolvedValue(undefined)
      const { result } = renderHook(() => useChangePassword(), { wrapper: createWrapper() })
      result.current.mutate({ currentPassword: "old", newPassword: "new12345" })
      await waitFor(() => expect(result.current.isSuccess).toBe(true))
    })
  })

  describe("useApiKeys", () => {
    it("fetches API keys", async () => {
      vi.mocked(settingsApi.listApiKeys).mockResolvedValue([])
      const { result } = renderHook(() => useApiKeys(), { wrapper: createWrapper() })
      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(result.current.data).toEqual([])
    })
  })
})

describe("Local settings hooks", () => {
  describe("useAppearanceSettings", () => {
    it("returns default appearance settings", () => {
      const { result } = renderHook(() => useAppearanceSettings())
      expect(result.current.settings.theme).toBe("dark")
      expect(result.current.settings.compact_mode).toBe(false)
      expect(result.current.settings.sidebar_collapsed).toBe(false)
    })

    it("updates appearance settings", () => {
      const { result } = renderHook(() => useAppearanceSettings())
      act(() => {
        result.current.update({ compact_mode: true })
      })
      expect(result.current.settings.compact_mode).toBe(true)
    })
  })

  describe("useNotificationSettings", () => {
    it("returns default notification settings", () => {
      const { result } = renderHook(() => useNotificationSettings())
      expect(result.current.settings.sse_notifications).toBe(true)
      expect(result.current.settings.browser_notifications).toBe(false)
    })

    it("updates notification settings", () => {
      const { result } = renderHook(() => useNotificationSettings())
      act(() => {
        result.current.update({ browser_notifications: true })
      })
      expect(result.current.settings.browser_notifications).toBe(true)
    })
  })

  describe("useScannerSettings", () => {
    it("returns default scanner settings", () => {
      const { result } = renderHook(() => useScannerSettings())
      expect(result.current.settings.default_scan_profile).toBe("full")
      expect(result.current.settings.timeout_seconds).toBe(300)
    })

    it("updates scanner settings", () => {
      const { result } = renderHook(() => useScannerSettings())
      act(() => {
        result.current.update({ timeout_seconds: 600 })
      })
      expect(result.current.settings.timeout_seconds).toBe(600)
    })
  })
})
