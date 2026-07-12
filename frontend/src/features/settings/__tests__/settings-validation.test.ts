import { describe, it, expect } from "vitest"
import { profileSchema, securitySchema, scannerSchema, apiKeySchema } from "../validation"

describe("Settings validation", () => {
  describe("profileSchema", () => {
    it("accepts valid profile", () => {
      const result = profileSchema.safeParse({
        full_name: "John Doe",
        email: "john@test.com",
        timezone: "UTC",
        language: "en",
      })
      expect(result.success).toBe(true)
    })

    it("rejects empty name", () => {
      const result = profileSchema.safeParse({
        full_name: "",
        email: "john@test.com",
        timezone: "UTC",
        language: "en",
      })
      expect(result.success).toBe(false)
    })

    it("rejects invalid email", () => {
      const result = profileSchema.safeParse({
        full_name: "John",
        email: "not-an-email",
        timezone: "UTC",
        language: "en",
      })
      expect(result.success).toBe(false)
    })
  })

  describe("securitySchema", () => {
    it("accepts valid passwords", () => {
      const result = securitySchema.safeParse({
        current_password: "oldpass",
        new_password: "newpass123",
        confirm_password: "newpass123",
      })
      expect(result.success).toBe(true)
    })

    it("rejects mismatched passwords", () => {
      const result = securitySchema.safeParse({
        current_password: "oldpass",
        new_password: "newpass123",
        confirm_password: "different",
      })
      expect(result.success).toBe(false)
    })

    it("rejects short password", () => {
      const result = securitySchema.safeParse({
        current_password: "old",
        new_password: "short",
        confirm_password: "short",
      })
      expect(result.success).toBe(false)
    })
  })

  describe("scannerSchema", () => {
    it("accepts valid scanner config", () => {
      const result = scannerSchema.safeParse({
        default_scan_profile: "full",
        timeout_seconds: 300,
        concurrent_jobs: 3,
        auto_generate_report: true,
        auto_delete_reports: false,
      })
      expect(result.success).toBe(true)
    })

    it("rejects timeout below minimum", () => {
      const result = scannerSchema.safeParse({
        default_scan_profile: "full",
        timeout_seconds: 10,
        concurrent_jobs: 3,
        auto_generate_report: true,
        auto_delete_reports: false,
      })
      expect(result.success).toBe(false)
    })

    it("rejects concurrent jobs above maximum", () => {
      const result = scannerSchema.safeParse({
        default_scan_profile: "full",
        timeout_seconds: 300,
        concurrent_jobs: 15,
        auto_generate_report: true,
        auto_delete_reports: false,
      })
      expect(result.success).toBe(false)
    })
  })

  describe("apiKeySchema", () => {
    it("accepts valid key name", () => {
      const result = apiKeySchema.safeParse({ name: "my-api-key" })
      expect(result.success).toBe(true)
    })

    it("rejects empty name", () => {
      const result = apiKeySchema.safeParse({ name: "" })
      expect(result.success).toBe(false)
    })

    it("rejects long name", () => {
      const result = apiKeySchema.safeParse({ name: "a".repeat(51) })
      expect(result.success).toBe(false)
    })
  })
})
