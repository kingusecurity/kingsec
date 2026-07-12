export interface AuthRequest {
  username: string
  password: string
}

export interface AuthResponse {
  access_token: string
  refresh_token: string
  token_type: string
}

export interface User {
  id: number
  username: string
  email: string
  role: "VIEWER" | "ANALYST" | "ADMIN"
  is_active: boolean
  created_at: string
}
