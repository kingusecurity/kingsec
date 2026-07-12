import { describe, it, expect, vi, beforeEach } from "vitest"
import { renderHook, waitFor } from "@testing-library/react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { analyticsKeys } from "../hooks/use-analytics"
import type { ReactNode } from "react"

vi.mock("@/shared/api/client", () => ({
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
  },
}))

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
}

describe("Analytics hooks", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe("analyticsKeys", () => {
    it("generates correct cache keys", () => {
      expect(analyticsKeys.all).toEqual(["analytics"])
      expect(analyticsKeys.kpis()).toEqual(["analytics", "kpis"])
      expect(analyticsKeys.trends("7d")).toEqual(["analytics", "trends", "7d"])
      expect(analyticsKeys.trends("30d")).toEqual(["analytics", "trends", "30d"])
      expect(analyticsKeys.risk()).toEqual(["analytics", "risk"])
      expect(analyticsKeys.summary()).toEqual(["analytics", "summary"])
      expect(analyticsKeys.audit()).toEqual(["analytics", "audit"])
      expect(analyticsKeys.users()).toEqual(["analytics", "users"])
      expect(analyticsKeys.reports()).toEqual(["analytics", "reports"])
    })
  })
})
