import { z } from "zod"

export const profileSchema = z.object({
  full_name: z.string().min(1, "Name is required").max(100, "Name must be under 100 characters"),
  email: z.string().email("Invalid email address"),
  timezone: z.string().min(1, "Timezone is required"),
  language: z.string().min(1, "Language is required"),
})

export type ProfileFormData = z.infer<typeof profileSchema>

export const securitySchema = z.object({
  current_password: z.string().min(1, "Current password is required"),
  new_password: z.string().min(8, "Password must be at least 8 characters"),
  confirm_password: z.string().min(1, "Please confirm your password"),
}).refine((data) => data.new_password === data.confirm_password, {
  message: "Passwords do not match",
  path: ["confirm_password"],
})

export type SecurityFormData = z.infer<typeof securitySchema>

export const scannerSchema = z.object({
  default_scan_profile: z.string().min(1, "Scan profile is required"),
  timeout_seconds: z.number().min(30, "Minimum timeout is 30 seconds").max(3600, "Maximum timeout is 3600 seconds"),
  concurrent_jobs: z.number().min(1, "Minimum 1 concurrent job").max(10, "Maximum 10 concurrent jobs"),
  auto_generate_report: z.boolean(),
  auto_delete_reports: z.boolean(),
})

export type ScannerFormData = z.infer<typeof scannerSchema>

export const apiKeySchema = z.object({
  name: z.string().min(1, "Key name is required").max(50, "Name must be under 50 characters"),
})

export type ApiKeyFormData = z.infer<typeof apiKeySchema>
