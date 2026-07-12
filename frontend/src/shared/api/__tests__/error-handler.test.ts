import { describe, it, expect } from "vitest"
import { getApiError } from "@/shared/api/error-handler"
import axios from "axios"

describe("getApiError", () => {
  it("handles cancelled requests", () => {
    const error = new axios.Cancel("cancelled")
    const result = getApiError(error)
    expect(result.isCancelled).toBe(true)
    expect(result.detail).toBe("Request cancelled")
  })

  it("handles network errors", () => {
    const error = new axios.AxiosError("Network Error", "ERR_NETWORK")
    const result = getApiError(error)
    expect(result.isNetworkError).toBe(true)
    expect(result.detail).toContain("Network error")
  })

  it("handles 401 errors", () => {
    const error = new axios.AxiosError("Unauthorized", "401", undefined, undefined, {
      data: { detail: "Session expired" },
      status: 401,
    } as never)
    const result = getApiError(error)
    expect(result.status).toBe(401)
    expect(result.detail).toBe("Session expired")
  })

  it("handles 403 errors with default message", () => {
    const error = new axios.AxiosError("Forbidden", "403", undefined, undefined, {
      data: {},
      status: 403,
    } as never)
    const result = getApiError(error)
    expect(result.status).toBe(403)
    expect(result.detail).toBe("You don't have permission to perform this action")
  })

  it("handles 404 errors", () => {
    const error = new axios.AxiosError("Not Found", "404", undefined, undefined, {
      data: {},
      status: 404,
    } as never)
    const result = getApiError(error)
    expect(result.status).toBe(404)
    expect(result.detail).toBe("Resource not found")
  })

  it("handles 409 conflicts", () => {
    const error = new axios.AxiosError("Conflict", "409", undefined, undefined, {
      data: {},
      status: 409,
    } as never)
    const result = getApiError(error)
    expect(result.status).toBe(409)
    expect(result.detail).toContain("Conflict")
  })

  it("handles 422 validation errors", () => {
    const error = new axios.AxiosError("Unprocessable", "422", undefined, undefined, {
      data: {},
      status: 422,
    } as never)
    const result = getApiError(error)
    expect(result.status).toBe(422)
    expect(result.detail).toContain("Invalid input")
  })

  it("handles 500 server errors", () => {
    const error = new axios.AxiosError("Server Error", "500", undefined, undefined, {
      data: {},
      status: 500,
    } as never)
    const result = getApiError(error)
    expect(result.status).toBe(500)
    expect(result.detail).toContain("Server error")
  })

  it("handles generic Error instances", () => {
    const error = new Error("something broke")
    const result = getApiError(error)
    expect(result.detail).toBe("something broke")
    expect(result.status).toBe(500)
  })

  it("handles unknown errors", () => {
    const result = getApiError("random string")
    expect(result.detail).toBe("An unexpected error occurred")
    expect(result.status).toBe(500)
  })
})
