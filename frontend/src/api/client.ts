const API_BASE = '/api/v1'

let accessToken: string | null = null
let refreshToken: string | null = null
let onLogout: (() => void) | null = null

export function setTokens(access: string, refresh: string) {
  accessToken = access
  refreshToken = refresh
}

export function clearTokens() {
  accessToken = null
  refreshToken = null
}

export function setLogoutHandler(handler: () => void) {
  onLogout = handler
}

export function getAccessToken() {
  return accessToken
}

class ApiError extends Error {
  status: number
  errorCode?: string

  constructor(status: number, message: string, errorCode?: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.errorCode = errorCode
  }
}

async function refreshAccessToken(): Promise<string | null> {
  if (!refreshToken) return null

  try {
    const res = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    })

    if (!res.ok) return null

    const data = await res.json()
    accessToken = data.access_token
    return accessToken
  } catch {
    return null
  }
}

interface RequestOptions extends Omit<RequestInit, 'body'> {
  body?: unknown
  params?: Record<string, string | number | undefined>
}

export async function apiRequest<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const { body, params, headers: extraHeaders, ...rest } = options

  let url = `${API_BASE}${path}`

  if (params) {
    const searchParams = new URLSearchParams()
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined) {
        searchParams.set(key, String(value))
      }
    }
    const qs = searchParams.toString()
    if (qs) url += `?${qs}`
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }

  if (extraHeaders) {
    for (const [key, value] of Object.entries(extraHeaders)) {
      headers[key] = value
    }
  }

  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`
  }

  const res = await fetch(url, {
    ...rest,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  })

  if (res.status === 401 && refreshToken) {
    const newToken = await refreshAccessToken()
    if (newToken) {
      headers['Authorization'] = `Bearer ${newToken}`
      const retryRes = await fetch(url, {
        ...rest,
        headers,
        body: body ? JSON.stringify(body) : undefined,
      })
      if (retryRes.ok) {
        if (retryRes.status === 204) return undefined as T
        return retryRes.json()
      }
      if (retryRes.status === 401) {
        onLogout?.()
      }
      const retryError = await parseError(retryRes)
      throw retryError
    } else {
      onLogout?.()
    }
  }

  if (!res.ok) {
    const error = await parseError(res)
    throw error
  }

  if (res.status === 204) return undefined as T
  return res.json()
}

async function parseError(res: Response): Promise<ApiError> {
  try {
    const data = await res.json()
    return new ApiError(res.status, data.message || 'Request failed', data.error_code)
  } catch {
    return new ApiError(res.status, `HTTP ${res.status}`)
  }
}

export { ApiError }
