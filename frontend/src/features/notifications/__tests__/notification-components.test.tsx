import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen, fireEvent } from "@testing-library/react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { NotificationBell } from "../components/notification-bell"
import { NotificationItem } from "../components/notification-item"
import { NotificationPanel } from "../components/notification-panel"
import { NotificationFilters } from "../components/notification-filters"
import { NotificationSkeleton } from "../components/notification-skeleton"
import { useNotificationStore } from "../hooks/use-notification-store"
import type { Notification } from "../types"

vi.mock("@/features/auth/hooks/use-auth", () => ({
  useAuth: () => ({
    user: { user_id: "u1", username: "admin", role: "ADMIN" },
    isAuthenticated: true,
    isLoading: false,
    login: vi.fn(),
    logout: vi.fn(),
  }),
}))

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
}

function makeNotification(overrides: Partial<Notification> = {}): Notification {
  return {
    id: "n1",
    type: "scan_started",
    title: "Scan Started",
    description: "A scan has been initiated",
    severity: "info",
    category: "system",
    read: false,
    created_at: new Date().toISOString(),
    ...overrides,
  }
}

describe("NotificationBell", () => {
  beforeEach(() => {
    useNotificationStore.setState({
      notifications: [],
      panelOpen: false,
      filter: "all",
      search: "",
      hasMore: false,
      total: 0,
    })
  })

  it("renders bell button", () => {
    render(<NotificationBell />, { wrapper: createWrapper() })
    expect(screen.getByLabelText(/Notifications/)).toBeInTheDocument()
  })

  it("shows unread count when there are unread notifications", () => {
    useNotificationStore.setState({
      notifications: [
        makeNotification({ id: "n1", read: false }),
        makeNotification({ id: "n2", read: false }),
      ],
    })
    render(<NotificationBell />, { wrapper: createWrapper() })
    expect(screen.getByLabelText(/Notifications \(2 unread\)/)).toBeInTheDocument()
  })

  it("does not show count badge when all read", () => {
    useNotificationStore.setState({
      notifications: [makeNotification({ id: "n1", read: true })],
    })
    render(<NotificationBell />, { wrapper: createWrapper() })
    expect(screen.getByLabelText("Notifications")).toBeInTheDocument()
    expect(screen.queryByLabelText(/Notifications \(\d+ unread\)/)).not.toBeInTheDocument()
  })

  it("toggles panel on click", () => {
    render(<NotificationBell />, { wrapper: createWrapper() })
    const button = screen.getByLabelText(/Notifications/)
    fireEvent.click(button)
    expect(useNotificationStore.getState().panelOpen).toBe(true)
  })
})

describe("NotificationItem", () => {
  const defaultProps = {
    onMarkRead: vi.fn(),
    onMarkUnread: vi.fn(),
    onDelete: vi.fn(),
    onClick: vi.fn(),
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("renders notification title and description", () => {
    const n = makeNotification({ title: "Test Alert", description: "Something happened" })
    render(<NotificationItem notification={n} {...defaultProps} />)
    expect(screen.getByText("Test Alert")).toBeInTheDocument()
    expect(screen.getByText("Something happened")).toBeInTheDocument()
  })

  it("calls onClick when clicked", () => {
    const n = makeNotification({ title: "Click Me", description: "desc" })
    render(<NotificationItem notification={n} {...defaultProps} />)
    fireEvent.click(screen.getByText("Click Me"))
    expect(defaultProps.onClick).toHaveBeenCalledWith(n)
  })

  it("shows mark read button for unread notifications", () => {
    const n = makeNotification({ read: false })
    render(<NotificationItem notification={n} {...defaultProps} />)
    expect(screen.getByText("Mark read")).toBeInTheDocument()
  })

  it("shows mark unread button for read notifications", () => {
    const n = makeNotification({ read: true })
    render(<NotificationItem notification={n} {...defaultProps} />)
    expect(screen.getByText("Mark unread")).toBeInTheDocument()
  })

  it("calls onDelete when delete clicked", () => {
    const n = makeNotification()
    render(<NotificationItem notification={n} {...defaultProps} />)
    fireEvent.click(screen.getByText("Delete"))
    expect(defaultProps.onDelete).toHaveBeenCalledWith("n1")
  })

  it("applies unread styling", () => {
    const n = makeNotification({ read: false })
    const { container } = render(<NotificationItem notification={n} {...defaultProps} />)
    const item = container.firstElementChild
    expect(item?.className).toContain("bg-[hsl(var(--bg-secondary))]/50")
  })
})

describe("NotificationPanel", () => {
  const defaultProps = {
    open: true,
    onClose: vi.fn(),
    isConnected: true,
    sseError: null,
    onReconnect: vi.fn(),
  }

  beforeEach(() => {
    vi.clearAllMocks()
    useNotificationStore.setState({
      notifications: [],
      filter: "all",
      search: "",
      panelOpen: true,
      hasMore: false,
      total: 0,
    })
  })

  it("renders panel when open", () => {
    render(<NotificationPanel {...defaultProps} />, { wrapper: createWrapper() })
    expect(screen.getByText("Notifications")).toBeInTheDocument()
  })

  it("renders search input", () => {
    render(<NotificationPanel {...defaultProps} />, { wrapper: createWrapper() })
    expect(screen.getByPlaceholderText("Search notifications...")).toBeInTheDocument()
  })

  it("shows empty state when no notifications", () => {
    render(<NotificationPanel {...defaultProps} />, { wrapper: createWrapper() })
    expect(screen.getByText("No notifications yet")).toBeInTheDocument()
  })

  it("shows notifications list", () => {
    useNotificationStore.setState({
      notifications: [
        makeNotification({ id: "n1", title: "First" }),
        makeNotification({ id: "n2", title: "Second" }),
      ],
    })
    render(<NotificationPanel {...defaultProps} />, { wrapper: createWrapper() })
    expect(screen.getByText("First")).toBeInTheDocument()
    expect(screen.getByText("Second")).toBeInTheDocument()
  })

  it("calls onClose when close button clicked", () => {
    render(<NotificationPanel {...defaultProps} />, { wrapper: createWrapper() })
    fireEvent.click(screen.getByLabelText("Close notifications"))
    expect(defaultProps.onClose).toHaveBeenCalled()
  })

  it("shows SSE error with retry button", () => {
    render(<NotificationPanel {...defaultProps} sseError="Connection lost" />, { wrapper: createWrapper() })
    expect(screen.getByText("Connection lost")).toBeInTheDocument()
    expect(screen.getByText("Retry")).toBeInTheDocument()
  })

  it("calls onReconnect when retry clicked", () => {
    render(<NotificationPanel {...defaultProps} sseError="Connection lost" />, { wrapper: createWrapper() })
    fireEvent.click(screen.getByText("Retry"))
    expect(defaultProps.onReconnect).toHaveBeenCalled()
  })

  it("shows mark all read button when unread exist", () => {
    useNotificationStore.setState({
      notifications: [makeNotification({ id: "n1", read: false })],
    })
    render(<NotificationPanel {...defaultProps} />, { wrapper: createWrapper() })
    expect(screen.getByText("Mark all read")).toBeInTheDocument()
  })

  it("shows clear all button when notifications exist", () => {
    useNotificationStore.setState({
      notifications: [makeNotification({ id: "n1" })],
    })
    render(<NotificationPanel {...defaultProps} />, { wrapper: createWrapper() })
    expect(screen.getByText("Clear all notifications")).toBeInTheDocument()
  })
})

describe("NotificationFilters", () => {
  beforeEach(() => {
    useNotificationStore.setState({
      notifications: [],
      filter: "all",
      search: "",
      panelOpen: false,
      hasMore: false,
      total: 0,
    })
  })

  it("renders all filter options", () => {
    render(<NotificationFilters />)
    expect(screen.getByText("All")).toBeInTheDocument()
    expect(screen.getByText("Unread")).toBeInTheDocument()
    expect(screen.getByText("Security")).toBeInTheDocument()
    expect(screen.getByText("Reports")).toBeInTheDocument()
    expect(screen.getByText("Users")).toBeInTheDocument()
    expect(screen.getByText("System")).toBeInTheDocument()
  })

  it("changes filter on click", () => {
    render(<NotificationFilters />)
    fireEvent.click(screen.getByText("Security"))
    expect(useNotificationStore.getState().filter).toBe("security")
  })

  it("shows counts for each category", () => {
    useNotificationStore.setState({
      notifications: [
        makeNotification({ id: "n1", category: "security" }),
        makeNotification({ id: "n2", category: "security" }),
        makeNotification({ id: "n3", category: "reports" }),
      ],
    })
    render(<NotificationFilters />)
    expect(screen.getByText("Security")).toBeInTheDocument()
    expect(screen.getByText("2")).toBeInTheDocument()
  })
})

describe("NotificationSkeleton", () => {
  it("renders skeleton items", () => {
    const { container } = render(<NotificationSkeleton count={3} />)
    const skeletons = container.querySelectorAll(".skeleton")
    expect(skeletons.length).toBeGreaterThan(0)
  })

  it("renders default 5 items", () => {
    const { container } = render(<NotificationSkeleton />)
    const skeletons = container.querySelectorAll(".skeleton")
    expect(skeletons.length).toBeGreaterThan(0)
  })
})
