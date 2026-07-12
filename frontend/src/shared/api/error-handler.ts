import axios, { type AxiosError } from "axios"
import type { ApiError } from "@/shared/types"

export interface ParsedApiError extends ApiError {
  status: number
  isNetworkError: boolean
  isCancelled: boolean
  isOffline: boolean
}

export function getApiError(error: unknown): ParsedApiError {
  if (axios.isCancel(error)) {
    return {
      detail: "Request cancelled",
      status: 0,
      isNetworkError: false,
      isCancelled: true,
      isOffline: false,
      status_code: 0,
    }
  }

  const isOffline = !navigator.onLine

  if (isOffline) {
    return {
      detail: "You are offline. Please check your internet connection.",
      status: 0,
      isNetworkError: true,
      isCancelled: false,
      isOffline: true,
      status_code: 0,
    }
  }

  if (axios.isAxiosError(error)) {
    const axiosErr = error as AxiosError<{ detail?: string; message?: string }>
    const status = axiosErr.response?.status ?? 0
    const isNetworkError = !axiosErr.response && !!axiosErr.code

    let detail: string
    if (!axiosErr.response) {
      detail = isNetworkError
        ? "Network error -- check your connection"
        : "Request failed"
    } else {
      detail =
        axiosErr.response.data?.detail ??
        axiosErr.response.data?.message ??
        getDefaultMessage(status)
    }

    return {
      detail,
      status,
      isNetworkError,
      isCancelled: false,
      isOffline: false,
      status_code: status,
    }
  }

  if (error instanceof Error) {
    return {
      detail: error.message,
      status: 500,
      isNetworkError: false,
      isCancelled: false,
      isOffline: false,
      status_code: 500,
    }
  }

  return {
    detail: "An unexpected error occurred",
    status: 500,
    isNetworkError: false,
    isCancelled: false,
    isOffline: false,
    status_code: 500,
  }
}

function getDefaultMessage(status: number): string {
  switch (status) {
    case 401:
      return "Session expired -- please log in again"
    case 403:
      return "You don't have permission to perform this action"
    case 404:
      return "Resource not found"
    case 409:
      return "Conflict -- this resource has been modified"
    case 422:
      return "Invalid input -- please check your data"
    case 429:
      return "Too many requests -- please try again later"
    default:
      return status >= 500
        ? "Server error -- please try again later"
        : "Request failed"
  }
}
