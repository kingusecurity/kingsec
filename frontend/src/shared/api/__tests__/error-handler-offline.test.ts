import { describe, it, expect, vi, beforeEach } from "vitest"
import axios from "axios"
import { getApiError } from "../error-handler"

describe("getApiError", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    Object.defineProperty(navigator, "onLine", { value: true, writable: true })
  })

  it("handles offline state", () => {
    Object.defineProperty(navigator, "onLine", { value: false, writable: true })
    const error = new Error("Network error")
    const result = getApiError(error)
    expect(result.isOffline).toBe(true)
    expect(result.detail).toContain("offline")
  })

  it("handles axios cancel", () => {
    const cancel = new axios.Cancel("cancelled by user")
    const result = getApiError(cancel)
    expect(result.isCancelled).toBe(true)
  })

  it("handles network error when online", () => {
    Object.defineProperty(navigator, "onLine", { value: true, writable: true })
    const axiosError = Object.assign(new Error("Network Error"), {
      isAxiosError: true,
      code: "ERR_NETWORK",
      response: undefined,
    })
    const result = getApiError(axiosError)
    expect(result.isNetworkError).toBe(true)
  })

  it("handles 401 response", () => {
    const axiosError = Object.assign(new Error("401"), {
      isAxiosError: true,
      response: { status: 401, data: {} },
    })
    const result = getApiError(axiosError)
    expect(result.status).toBe(401)
    expect(result.detail).toContain("Session expired")
  })

  it("handles 500 response", () => {
    const axiosError = Object.assign(new Error("500"), {
      isAxiosError: true,
      response: { status: 500, data: {} },
    })
    const result = getApiError(axiosError)
    expect(result.status).toBe(500)
    expect(result.detail).toContain("Server error")
  })

  it("handles regular Error instances", () => {
    const error = new TypeError("Type mismatch")
    const result = getApiError(error)
    expect(result.status).toBe(500)
    expect(result.detail).toBe("Type mismatch")
  })

  it("handles unknown error types", () => {
    const result = getApiError("string error")
    expect(result.status).toBe(500)
  })
})
