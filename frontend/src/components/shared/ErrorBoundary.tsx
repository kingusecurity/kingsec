import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertCircle, Home, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui'

interface AppErrorBoundaryProps {
  children: ReactNode
}

interface AppErrorBoundaryState {
  hasError: boolean
  error: Error | null
  errorId: string
}

export class AppErrorBoundary extends Component<AppErrorBoundaryProps, AppErrorBoundaryState> {
  constructor(props: AppErrorBoundaryProps) {
    super(props)
    this.state = { hasError: false, error: null, errorId: '' }
  }

  static getDerivedStateFromError(error: Error) {
    return {
      hasError: true,
      error,
      errorId: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[AppErrorBoundary]', error, info.componentStack)
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null, errorId: '' })
  }

  handleGoHome = () => {
    this.setState({ hasError: false, error: null, errorId: '' })
    window.location.href = '/dashboard'
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-gray-950 p-8">
          <div className="flex max-w-md flex-col items-center gap-4 text-center">
            <div className="flex h-16 w-16 items-center justify-center rounded-full bg-red-900/30">
              <AlertCircle className="h-8 w-8 text-red-400" />
            </div>
            <h1 className="text-xl font-semibold text-text-primary">Something went wrong</h1>
            <p className="text-sm text-text-secondary">
              An unexpected error occurred. Our team has been notified.
            </p>
            <p className="text-xs text-text-muted font-mono">
              Error ID: {this.state.errorId}
            </p>
            {this.state.error && (
              <details className="w-full rounded-lg border border-border bg-surface-secondary p-3">
                <summary className="cursor-pointer text-xs text-text-muted">Technical details</summary>
                <pre className="mt-2 overflow-auto text-xs text-text-secondary">
                  {this.state.error.message}
                </pre>
              </details>
            )}
            <div className="flex gap-3">
              <Button variant="outline" iconLeft={<RefreshCw className="h-4 w-4" />} onClick={this.handleRetry}>
                Try Again
              </Button>
              <Button variant="primary" iconLeft={<Home className="h-4 w-4" />} onClick={this.handleGoHome}>
                Return to Dashboard
              </Button>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

interface PageErrorBoundaryProps {
  children: ReactNode
  fallback?: ReactNode
}

interface PageErrorBoundaryState {
  hasError: boolean
}

export class PageErrorBoundary extends Component<PageErrorBoundaryProps, PageErrorBoundaryState> {
  constructor(props: PageErrorBoundaryProps) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  handleRetry = () => {
    this.setState({ hasError: false })
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback
      }

      return (
        <div className="flex flex-col items-center justify-center gap-4 py-16 text-center">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-red-900/30">
            <AlertCircle className="h-8 w-8 text-red-400" />
          </div>
          <h2 className="text-lg font-semibold text-text-primary">Page Error</h2>
          <p className="max-w-sm text-sm text-text-secondary">
            This section encountered an error. Try refreshing the page.
          </p>
          <Button variant="outline" iconLeft={<RefreshCw className="h-4 w-4" />} onClick={this.handleRetry}>
            Try Again
          </Button>
        </div>
      )
    }

    return this.props.children
  }
}
