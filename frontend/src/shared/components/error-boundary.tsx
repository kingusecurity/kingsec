import { Component, type ReactNode, type ErrorInfo } from "react"
import { AlertTriangle, RefreshCw, WifiOff, Copy, Check, ExternalLink } from "lucide-react"
import { Button } from "@/shared/ui/button"

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  hasError: boolean
  isOffline: boolean
  error: Error | null
  errorInfo: ErrorInfo | null
  copied: boolean
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, isOffline: !navigator.onLine, error: null, errorInfo: null, copied: false }
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    this.setState({ errorInfo })
    if (import.meta.env.DEV) {
      console.error("[ErrorBoundary]", error, errorInfo)
    }
  }

  componentDidMount(): void {
    window.addEventListener("online", this.handleOnline)
    window.addEventListener("offline", this.handleOffline)
  }

  componentWillUnmount(): void {
    window.removeEventListener("online", this.handleOnline)
    window.removeEventListener("offline", this.handleOffline)
  }

  handleOnline = (): void => { this.setState({ isOffline: false }) }
  handleOffline = (): void => { this.setState({ isOffline: true }) }

  handleRetry = (): void => {
    this.setState({ hasError: false, error: null, errorInfo: null, copied: false })
  }

  handleReload = (): void => {
    window.location.reload()
  }

  handleCopyStack = (): void => {
    const { error, errorInfo } = this.state
    const stack = [
      error?.message,
      error?.stack,
      errorInfo?.componentStack,
    ].filter(Boolean).join("\n\n")
    navigator.clipboard.writeText(stack).then(() => {
      this.setState({ copied: true })
      setTimeout(() => this.setState({ copied: false }), 2000)
    })
  }

  handleReport = (): void => {
    const { error, errorInfo } = this.state
    const body = [
      `Error: ${error?.message}`,
      error?.stack,
      errorInfo?.componentStack,
    ].filter(Boolean).join("\n\n")
    window.open(
      `https://github.com/kingsec/issues/new?title=${encodeURIComponent(`Error: ${error?.message ?? "Unknown"}`)}&body=${encodeURIComponent(body)}`,
      "_blank",
    )
  }

  getStackString(): string {
    const { error, errorInfo } = this.state
    return [error?.message, error?.stack, errorInfo?.componentStack].filter(Boolean).join("\n\n")
  }

  render(): ReactNode {
    if (this.props.fallback && this.state.hasError) return this.props.fallback

    if (this.state.isOffline) {
      return (
        <div className="flex min-h-[400px] flex-col items-center justify-center gap-4 p-8">
          <WifiOff className="size-12 text-[hsl(var(--destructive))]" aria-hidden="true" />
          <h2 className="text-xl font-semibold text-[hsl(var(--fg))]">You are offline</h2>
          <p className="max-w-md text-center text-[hsl(var(--fg-secondary))]">
            Check your internet connection and try again. Cached pages may still be available.
          </p>
          <div className="flex gap-2">
            <Button onClick={this.handleRetry} variant="outline" aria-label="Retry connection">
              <RefreshCw className="mr-2 size-4" /> Retry
            </Button>
            <Button onClick={this.handleReload} variant="ghost" aria-label="Reload page">
              Reload
            </Button>
          </div>
        </div>
      )
    }

    if (this.state.hasError) {
      return (
        <div className="flex min-h-[400px] flex-col items-center justify-center gap-4 p-8" role="alert">
          <AlertTriangle className="size-12 text-[hsl(var(--destructive))]" aria-hidden="true" />
          <h2 className="text-xl font-semibold text-[hsl(var(--fg))]">Something went wrong</h2>
          <p className="max-w-md text-center text-[hsl(var(--fg-secondary))]">
            {this.state.error?.message ?? "An unexpected error occurred."}
          </p>
          <div className="flex flex-wrap justify-center gap-2">
            <Button onClick={this.handleRetry} variant="outline" aria-label="Try again">
              <RefreshCw className="mr-2 size-4" /> Try Again
            </Button>
            <Button onClick={this.handleReload} variant="ghost" aria-label="Reload page">
              Reload Page
            </Button>
            <Button onClick={this.handleCopyStack} variant="ghost" size="sm" aria-label="Copy error details">
              {this.state.copied ? <Check className="mr-2 size-3" /> : <Copy className="mr-2 size-3" />}
              {this.state.copied ? "Copied" : "Copy Error"}
            </Button>
            <Button onClick={this.handleReport} variant="ghost" size="sm" aria-label="Report error">
              <ExternalLink className="mr-2 size-3" /> Report
            </Button>
          </div>
          {import.meta.env.DEV && this.state.error?.stack && (
            <details className="mt-4 max-w-2xl w-full">
              <summary className="cursor-pointer text-sm text-[hsl(var(--muted-fg))] hover:text-[hsl(var(--fg))]">
                Stack trace
              </summary>
              <pre className="mt-2 max-h-64 overflow-auto rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--bg-secondary))] p-4 text-xs text-[hsl(var(--fg-secondary))]">
                {this.getStackString()}
              </pre>
            </details>
          )}
        </div>
      )
    }

    return this.props.children
  }
}
