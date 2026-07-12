import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"

// Mock EventSource
class MockEventSource {
  static instances: MockEventSource[] = []
  url: string
  readyState = 0
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  private listeners: Record<string, ((e: MessageEvent) => void)[]> = {}

  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
  }

  addEventListener(type: string, listener: (e: MessageEvent) => void) {
    if (!this.listeners[type]) this.listeners[type] = []
    this.listeners[type].push(listener)
  }

  removeEventListener(type: string, listener: (e: MessageEvent) => void) {
    if (this.listeners[type]) {
      this.listeners[type] = this.listeners[type].filter((l) => l !== listener)
    }
  }

  close() {
    this.readyState = 2
  }

  simulateOpen() {
    this.readyState = 1
    this.onopen?.()
  }

  simulateEvent(type: string, data: string) {
    this.listeners[type]?.forEach((l) => l(new MessageEvent(type, { data })))
  }

  simulateError() {
    this.onerror?.()
  }
}

// @ts-expect-error mock
globalThis.EventSource = MockEventSource

import { renderHook, act } from "@testing-library/react"
import { useAssessmentSSE } from "@/widgets/live-events/use-assessment-sse"

beforeEach(() => {
  MockEventSource.instances = []
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
})

describe("useAssessmentSSE", () => {
  it("creates EventSource with correct URL", () => {
    renderHook(() => useAssessmentSSE({ assessmentId: "test-123", enabled: true }))

    expect(MockEventSource.instances.length).toBe(1)
    expect(MockEventSource.instances[0].url).toContain("assessment_id=test-123")
  })

  it("does not create EventSource when disabled", () => {
    renderHook(() => useAssessmentSSE({ assessmentId: "test-123", enabled: false }))

    expect(MockEventSource.instances.length).toBe(0)
  })

  it("sets isConnected on open", () => {
    const { result } = renderHook(() => useAssessmentSSE({ assessmentId: "test-123" }))

    act(() => {
      MockEventSource.instances[0].simulateOpen()
    })

    expect(result.current.isConnected).toBe(true)
    expect(result.current.error).toBeNull()
  })

  it("adds events to buffer", () => {
    const { result } = renderHook(() => useAssessmentSSE({ assessmentId: "test-123" }))

    act(() => {
      MockEventSource.instances[0].simulateOpen()
    })

    act(() => {
      MockEventSource.instances[0].simulateEvent(
        "assessment.started",
        JSON.stringify({ event_type: "assessment.started", assessment_id: "test-123", state: "RUNNING", message: "started", severity_counts: null, timestamp: "2024-01-01T00:00:00Z" }),
      )
    })

    expect(result.current.events.length).toBe(1)
    expect(result.current.events[0].event_type).toBe("assessment.started")
  })

  it("caps events at 100", () => {
    const { result } = renderHook(() => useAssessmentSSE({ assessmentId: "test-123" }))

    act(() => {
      MockEventSource.instances[0].simulateOpen()
    })

    for (let i = 0; i < 110; i++) {
      act(() => {
        MockEventSource.instances[0].simulateEvent(
          "assessment.started",
          JSON.stringify({ event_type: "assessment.started", assessment_id: "test-123", state: "RUNNING", message: `event-${i}`, severity_counts: null, timestamp: new Date().toISOString() }),
        )
      })
    }

    expect(result.current.events.length).toBe(100)
    expect(result.current.events[0].message).toBe("event-10")
  })

  it("reconnects with exponential backoff on error", () => {
    const { result } = renderHook(() => useAssessmentSSE({ assessmentId: "test-123" }))

    act(() => {
      MockEventSource.instances[0].simulateOpen()
    })

    // First error — backoff = 1s
    act(() => {
      MockEventSource.instances[0].simulateError()
    })

    expect(result.current.isConnected).toBe(false)
    expect(MockEventSource.instances.length).toBe(1)

    act(() => {
      vi.advanceTimersByTime(1000)
    })

    expect(MockEventSource.instances.length).toBe(2)

    // Second error — backoff = 2s
    act(() => {
      MockEventSource.instances[1].simulateOpen()
    })
    act(() => {
      MockEventSource.instances[1].simulateError()
    })

    act(() => {
      vi.advanceTimersByTime(2000)
    })

    expect(MockEventSource.instances.length).toBe(3)
  })

  it("calls onEvent callback", () => {
    const onEvent = vi.fn()
    renderHook(() => useAssessmentSSE({ assessmentId: "test-123", onEvent }))

    act(() => {
      MockEventSource.instances[0].simulateOpen()
    })

    const eventData = { event_type: "assessment.completed", assessment_id: "test-123", state: "COMPLETED", message: "done", severity_counts: null, timestamp: "2024-01-01T00:00:00Z" }

    act(() => {
      MockEventSource.instances[0].simulateEvent("assessment.completed", JSON.stringify(eventData))
    })

    expect(onEvent).toHaveBeenCalledWith(eventData)
  })

  it("closes EventSource on unmount", () => {
    const { unmount } = renderHook(() => useAssessmentSSE({ assessmentId: "test-123" }))

    const es = MockEventSource.instances[0]
    const closeSpy = vi.spyOn(es, "close")

    unmount()

    expect(closeSpy).toHaveBeenCalled()
  })
})
