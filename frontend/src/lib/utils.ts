import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function focusRing() {
  return 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface'
}

export function severityColor(severity: string): string {
  const map: Record<string, string> = {
    critical: 'text-red-400 bg-red-900/50 border-red-800',
    high: 'text-orange-400 bg-orange-900/50 border-orange-800',
    medium: 'text-yellow-400 bg-yellow-900/50 border-yellow-800',
    low: 'text-blue-400 bg-blue-900/50 border-blue-800',
    informational: 'text-gray-400 bg-gray-800 border-gray-700',
    info: 'text-gray-400 bg-gray-800 border-gray-700',
  }
  return map[severity.toLowerCase()] ?? 'text-gray-400 bg-gray-800 border-gray-700'
}

export function severityLabel(severity: string): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1)
}

export function statusColor(status: string): string {
  const map: Record<string, string> = {
    completed: 'text-emerald-400 bg-emerald-900/50 border-emerald-800',
    running: 'text-blue-400 bg-blue-900/50 border-blue-800',
    pending: 'text-yellow-400 bg-yellow-900/50 border-yellow-800',
    failed: 'text-red-400 bg-red-900/50 border-red-800',
    cancelled: 'text-gray-400 bg-gray-800 border-gray-700',
    draft: 'text-gray-400 bg-gray-800 border-gray-700',
    authorized: 'text-emerald-400 bg-emerald-900/50 border-emerald-800',
    open: 'text-yellow-400 bg-yellow-900/50 border-yellow-800',
    confirmed: 'text-orange-400 bg-orange-900/50 border-orange-800',
    false_positive: 'text-gray-400 bg-gray-800 border-gray-700',
    remediated: 'text-emerald-400 bg-emerald-900/50 border-emerald-800',
    active: 'text-emerald-400 bg-emerald-900/50 border-emerald-800',
    inactive: 'text-gray-400 bg-gray-800 border-gray-700',
    healthy: 'text-emerald-400 bg-emerald-900/50 border-emerald-800',
    degraded: 'text-yellow-400 bg-yellow-900/50 border-yellow-800',
    down: 'text-red-400 bg-red-900/50 border-red-800',
  }
  return map[status.toLowerCase()] ?? 'text-yellow-400 bg-yellow-900/50 border-yellow-800'
}

export function formatDate(dateStr: string): string {
  const date = new Date(dateStr)
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)
  const diffMin = Math.floor(diffSec / 60)
  const diffHr = Math.floor(diffMin / 60)
  const diffDay = Math.floor(diffHr / 24)

  if (diffSec < 60) return 'just now'
  if (diffMin < 60) return `${diffMin}m ago`
  if (diffHr < 24) return `${diffHr}h ago`
  if (diffDay < 7) return `${diffDay}d ago`
  return formatDate(dateStr)
}

export function truncate(str: string, max: number): string {
  if (str.length <= max) return str
  return str.slice(0, max) + '...'
}
