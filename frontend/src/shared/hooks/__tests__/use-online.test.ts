import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { renderHook, act } from "@testing-library/react"
import { useOnline } from "../use-online"

describe("useOnline", () => {
  beforeEach(() => {
    Object.defineProperty(navigator, "onLine", { value: true, writable: true })
  })

  it("returns true when online", () => {
    const { result } = renderHook(() => useOnline())
    expect(result.current).toBe(true)
  })

  it("returns false when offline", () => {
    Object.defineProperty(navigator, "onLine", { value: false, writable: true })
    const { result } = renderHook(() => useOnline())
    expect(result.current).toBe(false)
  })

  it("updates when going offline", () => {
    const { result } = renderHook(() => useOnline())
    act(() => {
      Object.defineProperty(navigator, "onLine", { value: false, writable: true })
      window.dispatchEvent(new Event("offline"))
    })
    expect(result.current).toBe(false)
  })

  it("updates when going online", () => {
    Object.defineProperty(navigator, "onLine", { value: false, writable: true })
    const { result } = renderHook(() => useOnline())
    act(() => {
      Object.defineProperty(navigator, "onLine", { value: true, writable: true })
      window.dispatchEvent(new Event("online"))
    })
    expect(result.current).toBe(true)
  })
})
