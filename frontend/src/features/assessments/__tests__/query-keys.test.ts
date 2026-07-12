import { describe, it, expect } from "vitest"
import { assessmentKeys } from "../hooks/use-assessments"

describe("assessmentKeys", () => {
  it("returns correct key structure", () => {
    expect(assessmentKeys.all).toEqual(["assessments"])
    expect(assessmentKeys.lists()).toEqual(["assessments", "list"])
    expect(assessmentKeys.list({ limit: 10, offset: 0 })).toEqual(["assessments", "list", { limit: 10, offset: 0 }])
    expect(assessmentKeys.details()).toEqual(["assessments", "detail"])
    expect(assessmentKeys.detail("abc-123")).toEqual(["assessments", "detail", "abc-123"])
  })

  it("different params produce different keys", () => {
    const key1 = assessmentKeys.list({ limit: 10, offset: 0 })
    const key2 = assessmentKeys.list({ limit: 10, offset: 10 })
    expect(key1).not.toEqual(key2)
  })
})
