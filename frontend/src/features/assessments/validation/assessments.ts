import { z } from "zod"

export const createAssessmentSchema = z.object({
  target_value: z.string().min(1, "Target is required").max(2048),
  target_type: z.enum(["ip_address", "hostname", "url", "network"], {
    message: "Target type is required",
  }),
  authorized_by: z.string().min(1, "Authorized by is required").max(256),
  scope: z.string().min(1, "Scope is required").max(2048),
})

export type CreateAssessmentFormData = z.infer<typeof createAssessmentSchema>
