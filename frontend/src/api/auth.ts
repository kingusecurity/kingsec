import { apiRequest } from './client'
import type {
  LoginBody,
  LoginResponse,
  MfaLoginResponse,
  RefreshTokenBody,
  RefreshTokenResponse,
  RegisterUserBody,
  RegisterUserResponse,
  UserResponse,
  AssignRoleBody,
  AssignRoleResponse,
  VerifyMfaBody,
  UseRecoveryCodeBody,
} from '@/types/api'

export const authApi = {
  login: (data: LoginBody) =>
    apiRequest<LoginResponse>('/auth/login', { method: 'POST', body: data }),

  verifyMfa: (data: VerifyMfaBody) =>
    apiRequest<MfaLoginResponse>('/mfa/verify', { method: 'POST', body: data }),

  useRecoveryCode: (data: UseRecoveryCodeBody) =>
    apiRequest<MfaLoginResponse>('/mfa/recovery', { method: 'POST', body: data }),

  refresh: (data: RefreshTokenBody) =>
    apiRequest<RefreshTokenResponse>('/auth/refresh', { method: 'POST', body: data }),

  register: (data: RegisterUserBody) =>
    apiRequest<RegisterUserResponse>('/auth/register', { method: 'POST', body: data }),

  me: () =>
    apiRequest<UserResponse>('/auth/me'),

  assignRole: (userId: string, data: AssignRoleBody) =>
    apiRequest<AssignRoleResponse>(`/users/${userId}/role`, { method: 'PUT', body: data }),
}
