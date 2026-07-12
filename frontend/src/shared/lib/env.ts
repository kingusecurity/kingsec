export function getApiBaseUrl(): string {
  if (typeof window !== "undefined" && window.__TAURI_INTERNALS__) {
    return "http://127.0.0.1:8000"
  }
  return import.meta.env.VITE_API_BASE_URL ?? "/api/v1"
}

export function getBackendUrl(): string {
  if (typeof window !== "undefined" && window.__TAURI_INTERNALS__) {
    return "http://127.0.0.1:8000"
  }
  return import.meta.env.VITE_BACKEND_URL ?? "http://127.0.0.1:8000"
}

export function isDesktop(): boolean {
  return typeof window !== "undefined" && !!window.__TAURI_INTERNALS__
}

declare global {
  interface Window {
    __TAURI_INTERNALS__?: Record<string, unknown>
  }
}
