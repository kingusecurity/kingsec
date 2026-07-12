import { Component, type ReactNode } from "react"
import { AlertTriangle, RefreshCw, WifiOff } from "lucide-react"
import { Button } from "@/shared/ui/button"

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  hasError: boolean
  isOffline: boolean
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, isOffline: !navigator.onLine, error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, isOffline: !navigator.onLine }
  }

  componentDidMount(): void {
    window.addEventListener("online", this.handleOnline)
    window.addEventListener("offline", this.handleOffline)
  }

  componentWillUnmount(): void {
    window.removeEventListener("online", this.handleOnline)
    window.removeEventListener("offline", this.handleOffline)
  }

  handleOnline = (): void => {
    this.setState({ isOffline: false })
  }

  handleOffline = (): void => {
    this.setState({ isOffline: true })
  }

  handleRetry = (): void => {
    this.setState({ hasError: false, error: null })
  }

  render(): ReactNode {
    if (this.props.fallback && this.state.hasError) {
      return this.props.fallback
    }

    if (this.state.isOffline) {
      return (
        <div className="flex min-h-[400px] flex-col items-center justify-center gap-4 p-8">
          <WifiOff className="size-12 text-[hsl(var(--destructive))]" />
          <h2 className="text-xl font-semibold text-[hsl(var(--fg))]">You're offline</h2>
          <p className="text-[hsl(var(--fg-secondary))]">Check your internet connection and try again.</p>
          <Button onClick={this.handleRetry} variant="outline">
            <RefreshCw className="mr-2 size-4" />
            Retry
          </Button>
        </div>
      )
    }

    if (this.state.hasError) {
      return (
        <div className="flex min-h-[400px] flex-col items-center justify-center gap-4 p-8">
          <AlertTriangle className="size-12 text-[hsl(var(--destructive))]" />
          <h2 className="text-xl font-semibold text-[hsl(var(--fg))]">Something went wrong</h2>
          <p className="max-w-md text-center text-[hsl(var(--fg-secondary))]">
            {this.state.error?.message ?? "An unexpected error occurred."}
          </p>
          <Button onClick={this.handleRetry} variant="outline">
            <RefreshCw className="mr-2 size-4" />
            Retry
          </Button>
        </div>
      )
    }

    return this.props.children
  }
}
