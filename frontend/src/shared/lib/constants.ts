export const ROUTES = {
  LOGIN: "/login",
  DASHBOARD: "/dashboard",
  ASSESSMENTS: "/assessments",
  ASSESSMENT_DETAIL: "/assessments/:id",
  AUDIT: "/audit",
  PROFILE: "/profile",
} as const

export const ROLE_HIERARCHY = { VIEWER: 10, ANALYST: 20, ADMIN: 30 } as const

export const ASSESSMENT_STATUS_LABELS: Record<string, string> = {
  CREATED: "Created",
  RUNNING: "Running",
  COMPLETED: "Completed",
  FAILED: "Failed",
  CANCELLED: "Cancelled",
} as const

export const SEVERITY_LABELS: Record<string, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFO: "Info",
} as const

export const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "destructive",
  HIGH: "destructive",
  MEDIUM: "warning",
  LOW: "secondary",
  INFO: "muted",
} as const

export const ACTION_LABELS: Record<string, string> = {
  LOGIN: "Login",
  FAILED_LOGIN: "Failed Login",
  LOGOUT: "Logout",
  TOKEN_REFRESHED: "Token Refreshed",
  USER_REGISTERED: "User Registered",
  PASSWORD_CHANGED: "Password Changed",
  ASSESSMENT_CREATED: "Assessment Created",
  ASSESSMENT_STARTED: "Assessment Started",
  ASSESSMENT_COMPLETED: "Assessment Completed",
  ASSESSMENT_FAILED: "Assessment Failed",
  ASSESSMENT_CANCELLED: "Assessment Cancelled",
  ASSESSMENT_DELETED: "Assessment Deleted",
  ASSESSMENT_SUBMITTED: "Assessment Submitted",
  REPORT_GENERATED: "Report Generated",
  AUTHORIZATION_FAILURE: "Authorization Failure",
} as const

export const TOKEN_KEY = "kingsec_access_token"
export const REFRESH_TOKEN_KEY = "kingsec_refresh_token"
