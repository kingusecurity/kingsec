import axios, { type AxiosError } from "axios"
import type { ApiError } from "@/shared/types"

export function getApiError(error: unknown): ApiError {
  if (axios.isAxiosError(error)) {
    const axiosErr = error as AxiosError<{ detail?: string }>
    return {
      detail: axiosErr.response?.data?.detail ?? axiosErr.message ?? "Unknown error",
      status_code: axiosErr.response?.status ?? 500,
    }
  }
  if (error instanceof Error) {
    return { detail: error.message, status_code: 500 }
  }
  return { detail: "An unexpected error occurred", status_code: 500 }
}
