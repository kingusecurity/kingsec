export interface User {
  user_id: string
  username: string
  email: string
  role: "VIEWER" | "ANALYST" | "ADMIN"
  is_active: boolean
  created_at: string
  last_login?: string
}

export interface CreateUserRequest {
  username: string
  email: string
  password: string
  role: "VIEWER" | "ANALYST" | "ADMIN"
}

export interface UpdateUserRequest {
  email?: string
  role?: "VIEWER" | "ANALYST" | "ADMIN"
  is_active?: boolean
}

export interface ResetPasswordRequest {
  new_password: string
}

export interface UserSession {
  session_id: string
  user_id: string
  ip_address: string
  user_agent: string
  created_at: string
  last_active: string
}

export interface UserAuditEntry {
  audit_id: string
  action: string
  resource_type: string
  resource_id: string
  details: string
  success: boolean
  created_at: string
}

export type UserRole = "VIEWER" | "ANALYST" | "ADMIN"

export const ROLE_LABELS: Record<UserRole, string> = {
  VIEWER: "Viewer",
  ANALYST: "Analyst",
  ADMIN: "Admin",
}

export const ROLE_PERMISSIONS: Record<UserRole, string[]> = {
  VIEWER: ["assessments:read", "reports:read"],
  ANALYST: ["assessments:read", "assessments:write", "reports:read", "reports:write"],
  ADMIN: ["assessments:read", "assessments:write", "reports:read", "reports:write", "users:read", "users:write", "audit:read", "system:manage"],
}
