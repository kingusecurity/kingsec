import { describe, it, expect, vi, beforeEach } from "vitest"
import { renderHook, act } from "@testing-library/react"
import { useLocalStorage } from "../use-local-storage"

describe("useLocalStorage", () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it("returns initial value when no stored value", () => {
    const { result } = renderHook(() => useLocalStorage("test-key", "default"))
    expect(result.current[0]).toBe("default")
  })

  it("returns stored value if exists", () => {
    localStorage.setItem("test-key", JSON.stringify("stored"))
    const { result } = renderHook(() => useLocalStorage("test-key", "default"))
    expect(result.current[0]).toBe("stored")
  })

  it("updates stored value", () => {
    const { result } = renderHook(() => useLocalStorage("test-key", "default"))
    act(() => {
      result.current[1]("new-value")
    })
    expect(result.current[0]).toBe("new-value")
    expect(JSON.parse(localStorage.getItem("test-key")!)).toBe("new-value")
  })

  it("updates with functional value", () => {
    const { result } = renderHook(() => useLocalStorage("counter", 0))
    act(() => {
      result.current[1]((prev) => prev + 1)
    })
    expect(result.current[0]).toBe(1)
  })

  it("handles JSON parse errors gracefully", () => {
    localStorage.setItem("bad-key", "not-json")
    const { result } = renderHook(() => useLocalStorage("bad-key", "fallback"))
    expect(result.current[0]).toBe("fallback")
  })
})
