import axios, {
  type AxiosError,
  type InternalAxiosRequestConfig,
  type AxiosResponse,
} from "axios"
import { TOKEN_KEY, REFRESH_TOKEN_KEY } from "@/shared/lib/constants"
import { getApiBaseUrl } from "@/shared/lib/env"

let isRefreshing = false
let failedQueue: Array<{
  resolve: (token: string) => void
  reject: (error: unknown) => void
}> = []

function processQueue(error: unknown, token: string | null): void {
  failedQueue.forEach((p) => {
    if (error || !token) {
      p.reject(error)
    } else {
      p.resolve(token)
    }
  })
  failedQueue = []
}

function getCorrelationId(): string {
  return crypto.randomUUID()
}

function getStoredToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}

function getStoredRefreshToken(): string | null {
  try {
    return localStorage.getItem(REFRESH_TOKEN_KEY)
  } catch {
    return null
  }
}

function setTokens(access: string, refresh: string): void {
  localStorage.setItem(TOKEN_KEY, access)
  localStorage.setItem(REFRESH_TOKEN_KEY, refresh)
}

function clearTokens(): void {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(REFRESH_TOKEN_KEY)
}

function isSafeMethod(method?: string): boolean {
  return !method || ["get", "head", "options"].includes(method.toLowerCase())
}

export const apiClient = axios.create({
  timeout: 30000,
  headers: { "Content-Type": "application/json" },
})

// Request interceptor: set baseURL (desktop-safe) + attach JWT + correlation-id
apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    config.baseURL = getApiBaseUrl()
    const token = getStoredToken()
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`
    }
    if (config.headers) {
      config.headers["X-Correlation-ID"] = getCorrelationId()
    }
    return config
  },
  (error: unknown) => Promise.reject(error),
)

// Response interceptor: handle 401 refresh, retry for safe methods, global errors
apiClient.interceptors.response.use(
  (response: AxiosResponse) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & {
      _retry?: boolean
      _retryCount?: number
    }

    // Retry safe/idempotent requests (GET, HEAD) up to 2 times on network/5xx errors
    const isRetryable =
      isSafeMethod(originalRequest.method) &&
      (!error.response || error.response.status >= 500) &&
      error.code !== "ECONNABORTED"

    if (isRetryable && !originalRequest._retry) {
      originalRequest._retryCount = originalRequest._retryCount ?? 0
      if (originalRequest._retryCount < 2) {
        originalRequest._retryCount += 1
        const delay = 1000 * Math.pow(2, originalRequest._retryCount - 1)
        await new Promise((r) => setTimeout(r, delay))
        return apiClient(originalRequest)
      }
    }

    // 401 — attempt token refresh
    if (error.response?.status === 401 && !originalRequest._retry) {
      const refreshToken = getStoredRefreshToken()
      if (!refreshToken) {
        clearTokens()
        window.location.href = "/login"
        return Promise.reject(error)
      }

      if (isRefreshing) {
        return new Promise<string>((resolve, reject) => {
          failedQueue.push({ resolve, reject })
        }).then((token) => {
          if (originalRequest.headers) {
            originalRequest.headers.Authorization = `Bearer ${token}`
          }
          return apiClient(originalRequest)
        })
      }

      originalRequest._retry = true
      isRefreshing = true

      try {
        const { data } = await axios.post(
          `${getApiBaseUrl()}/auth/refresh`,
          { refresh_token: refreshToken },
          { headers: { "Content-Type": "application/json" } },
        )

        const newAccess: string = data.access_token
        const newRefresh: string = data.refresh_token ?? refreshToken
        setTokens(newAccess, newRefresh)
        processQueue(null, newAccess)

        if (originalRequest.headers) {
          originalRequest.headers.Authorization = `Bearer ${newAccess}`
        }
        return apiClient(originalRequest)
      } catch (refreshError) {
        processQueue(refreshError, null)
        clearTokens()
        window.location.href = "/login"
        return Promise.reject(refreshError)
      } finally {
        isRefreshing = false
      }
    }

    return Promise.reject(error)
  },
)

export { clearTokens, setTokens, getStoredToken, getStoredRefreshToken }
