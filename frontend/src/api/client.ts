const API_BASE = '/api/v1'

// Tokens are kept in localStorage (not just in memory) so a page refresh,
// a bookmarked/shared deep link, or a new tab doesn't drop an otherwise
// valid session — AuthGuard's existing useMe() check on mount then either
// succeeds outright or transparently refreshes via the 401 handling below.
// This does not change the auth model: still short-lived bearer JWTs over
// HTTPS, no new storage of anything beyond what the API already issues.
// Trade-off: localStorage is readable by any script running on the page
// (XSS), which is why the app also ships a strict `default-src 'none'`
// CSP and short (30 min) access-token expiry — the same trade-off most
// bearer-token SPAs make to support refresh/bookmarks/deep-links at all.
const ACCESS_TOKEN_KEY = 'kingsec_access_token'
const REFRESH_TOKEN_KEY = 'kingsec_refresh_token'

function readStoredToken(key: string): string | null {
  try {
    return window.localStorage.getItem(key)
  } catch {
    // localStorage can throw in some contexts (privacy mode, disabled
    // storage) — fall back to memory-only behavior rather than crashing.
    return null
  }
}

let accessToken: string | null = readStoredToken(ACCESS_TOKEN_KEY)
let refreshToken: string | null = readStoredToken(REFRESH_TOKEN_KEY)
let onLogout: (() => void) | null = null

export function setTokens(access: string, refresh: string) {
  accessToken = access
  refreshToken = refresh
  try {
    window.localStorage.setItem(ACCESS_TOKEN_KEY, access)
    window.localStorage.setItem(REFRESH_TOKEN_KEY, refresh)
  } catch {
    // Storage unavailable — session simply won't survive a reload.
  }
}

export function clearTokens() {
  accessToken = null
  refreshToken = null
  try {
    window.localStorage.removeItem(ACCESS_TOKEN_KEY)
    window.localStorage.removeItem(REFRESH_TOKEN_KEY)
  } catch {
    // Storage unavailable — nothing to clear.
  }
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
    try {
      window.localStorage.setItem(ACCESS_TOKEN_KEY, data.access_token)
    } catch {
      // Storage unavailable — the refreshed token still works for the
      // rest of this session, it just won't survive a reload.
    }
    return accessToken
  } catch {
    return null
  }
}

interface RequestOptions extends Omit<RequestInit, 'body'> {
  body?: unknown
  params?: Record<string, string | number | boolean | undefined | null>
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

// FastAPI's default 422 handler puts a list of {loc, msg} objects in
// `detail` (one per invalid field), not a string — stringifying that
// array directly renders as "[object Object],[object Object]".
function formatValidationDetail(detail: unknown[]): string {
  return detail
    .map((entry) => {
      if (entry && typeof entry === 'object' && 'msg' in entry) {
        const loc = 'loc' in entry && Array.isArray((entry as { loc: unknown }).loc) ? (entry as { loc: unknown[] }).loc : []
        const field = loc.filter((part) => part !== 'body').join('.')
        const msg = String((entry as { msg: unknown }).msg)
        return field ? `${field}: ${msg}` : msg
      }
      return String(entry)
    })
    .join('; ')
}

async function parseError(res: Response): Promise<ApiError> {
  try {
    const data = await res.json()
    // Two response shapes exist in this backend: the structured
    // {error_code, message} used by registered exception handlers, and
    // FastAPI's raw HTTPException {detail}. Check both so a route using
    // either convention still surfaces its real message instead of a
    // generic fallback.
    const detail = Array.isArray(data.detail) ? formatValidationDetail(data.detail) : data.detail
    return new ApiError(res.status, data.message || detail || 'Request failed', data.error_code)
  } catch {
    return new ApiError(res.status, `HTTP ${res.status}`)
  }
}

export { ApiError }
