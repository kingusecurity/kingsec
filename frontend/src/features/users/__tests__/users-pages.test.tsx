import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen, fireEvent, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { UsersListPage } from "../pages/users-list-page"
import { UserDetailPage } from "../pages/user-detail-page"
import { CreateUserPage } from "../pages/create-user-page"
import { EditUserPage } from "../pages/edit-user-page"
import { UserRoleBadge } from "../components/user-role-badge"
import { UserStatusBadge } from "../components/user-status-badge"
import * as usersHooks from "../hooks/use-users"
import * as authHook from "@/features/auth/hooks/use-auth"

vi.mock("../hooks/use-users")
vi.mock("@/features/auth/hooks/use-auth")

function createQueryWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
}

function renderWithRouter(ui: React.ReactElement, initialEntries = ["/users"]) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      {ui}
    </MemoryRouter>,
    { wrapper: createQueryWrapper() },
  )
}

const mockUsers = {
  items: [
    { user_id: "u1", username: "admin", email: "admin@test.com", role: "ADMIN", is_active: true, created_at: "2025-01-01T00:00:00Z" },
    { user_id: "u2", username: "analyst", email: "analyst@test.com", role: "ANALYST", is_active: true, created_at: "2025-01-02T00:00:00Z" },
    { user_id: "u3", username: "viewer", email: "viewer@test.com", role: "VIEWER", is_active: false, created_at: "2025-01-03T00:00:00Z" },
  ],
  total: 3,
}

const mockUser = {
  user_id: "u1",
  username: "admin",
  email: "admin@test.com",
  role: "ADMIN" as const,
  is_active: true,
  created_at: "2025-01-01T00:00:00Z",
  last_login: "2025-06-01T00:00:00Z",
}

function mockAuth(role = "ADMIN") {
  vi.mocked(authHook.useAuth).mockReturnValue({
    user: { user_id: "u1", username: "admin", email: "admin@test.com", role, is_active: true, created_at: "2025-01-01T00:00:00Z" },
    login: vi.fn(),
    logout: vi.fn(),
    register: vi.fn(),
    isLoading: false,
    isAuthenticated: true,
  } as any)
}

describe("UserRoleBadge", () => {
  it("renders role badge", () => {
    renderWithRouter(<UserRoleBadge role="ADMIN" />)
    expect(screen.getByText("Admin")).toBeInTheDocument()
  })
})

describe("UserStatusBadge", () => {
  it("renders active status", () => {
    renderWithRouter(<UserStatusBadge isActive={true} />)
    expect(screen.getByText("Active")).toBeInTheDocument()
  })

  it("renders disabled status", () => {
    renderWithRouter(<UserStatusBadge isActive={false} />)
    expect(screen.getByText("Disabled")).toBeInTheDocument()
  })
})

describe("UsersListPage", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockAuth()
  })

  it("renders page header with add user button", () => {
    vi.mocked(usersHooks.useUsers).mockReturnValue({
      data: mockUsers, isLoading: false, error: null, refetch: vi.fn(), isFetching: false,
    } as any)

    renderWithRouter(<UsersListPage />)

    expect(screen.getByText("Users")).toBeInTheDocument()
    expect(screen.getByText("Add User")).toBeInTheDocument()
  })

  it("displays user list", () => {
    vi.mocked(usersHooks.useUsers).mockReturnValue({
      data: mockUsers, isLoading: false, error: null, refetch: vi.fn(), isFetching: false,
    } as any)

    renderWithRouter(<UsersListPage />)

    expect(screen.getByText("admin")).toBeInTheDocument()
    expect(screen.getByText("analyst")).toBeInTheDocument()
    expect(screen.getByText("viewer")).toBeInTheDocument()
  })

  it("shows loading skeletons", () => {
    vi.mocked(usersHooks.useUsers).mockReturnValue({
      data: undefined, isLoading: true, error: null, refetch: vi.fn(), isFetching: false,
    } as any)

    const { container } = renderWithRouter(<UsersListPage />)
    expect(container.querySelectorAll(".skeleton").length).toBeGreaterThan(0)
  })

  it("shows empty state", () => {
    vi.mocked(usersHooks.useUsers).mockReturnValue({
      data: { items: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn(), isFetching: false,
    } as any)

    renderWithRouter(<UsersListPage />)
    expect(screen.getByText("No users found")).toBeInTheDocument()
  })

  it("filters by search", async () => {
    const user = userEvent.setup()
    vi.mocked(usersHooks.useUsers).mockReturnValue({
      data: mockUsers, isLoading: false, error: null, refetch: vi.fn(), isFetching: false,
    } as any)

    renderWithRouter(<UsersListPage />)

    await user.type(screen.getByPlaceholderText("Search by username, email, or role..."), "analyst")

    await waitFor(() => {
      expect(screen.queryByText("admin")).not.toBeInTheDocument()
    })
    expect(screen.getByText("analyst")).toBeInTheDocument()
  })

  it("shows error state", () => {
    const error = new Error("Forbidden") as any
    error.status = 403
    vi.mocked(usersHooks.useUsers).mockReturnValue({
      data: undefined, isLoading: false, error, refetch: vi.fn(), isFetching: false,
    } as any)

    renderWithRouter(<UsersListPage />)
    expect(screen.getByRole("alert")).toBeInTheDocument()
  })
})

describe("UserDetailPage", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockAuth()
  })

  it("shows loading state", () => {
    vi.mocked(usersHooks.useUser).mockReturnValue({
      data: undefined, isLoading: true, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(usersHooks.useDeleteUser).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(usersHooks.useUserSessions).mockReturnValue({ data: undefined, isLoading: true } as any)
    vi.mocked(usersHooks.useUserAuditEntries).mockReturnValue({ data: undefined, isLoading: true } as any)

    const { container } = renderWithRouter(<UserDetailPage />, ["/users/u1"])
    expect(container.querySelectorAll(".skeleton").length).toBeGreaterThan(0)
  })

  it("shows error state", async () => {
    const error = new Error("Not found") as any
    error.status = 404
    vi.mocked(usersHooks.useUser).mockReturnValue({
      data: undefined, isLoading: false, error, refetch: vi.fn(),
    } as any)
    vi.mocked(usersHooks.useDeleteUser).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(usersHooks.useUserSessions).mockReturnValue({ data: undefined, isLoading: false } as any)
    vi.mocked(usersHooks.useUserAuditEntries).mockReturnValue({ data: undefined, isLoading: false } as any)

    renderWithRouter(<UserDetailPage />, ["/users/u1"])

    await waitFor(() => {
      expect(screen.getByText("Not found")).toBeInTheDocument()
    })
  })

  it("renders user detail with tabs", async () => {
    vi.mocked(usersHooks.useUser).mockReturnValue({
      data: mockUser, isLoading: false, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(usersHooks.useDeleteUser).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(usersHooks.useUserSessions).mockReturnValue({ data: [], isLoading: false } as any)
    vi.mocked(usersHooks.useUserAuditEntries).mockReturnValue({ data: { items: [], total: 0 }, isLoading: false } as any)

    renderWithRouter(<UserDetailPage />, ["/users/u1"])

    expect(screen.getAllByText("admin").length).toBeGreaterThan(0)
    expect(screen.getAllByText("admin@test.com").length).toBeGreaterThan(0)
    expect(screen.getByText("Profile")).toBeInTheDocument()
    expect(screen.getByText("Permissions")).toBeInTheDocument()
    expect(screen.getByText("Sessions")).toBeInTheDocument()
    expect(screen.getByText("Audit Activity")).toBeInTheDocument()
  })

  it("shows edit and delete buttons", async () => {
    vi.mocked(usersHooks.useUser).mockReturnValue({
      data: mockUser, isLoading: false, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(usersHooks.useDeleteUser).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(usersHooks.useUserSessions).mockReturnValue({ data: [], isLoading: false } as any)
    vi.mocked(usersHooks.useUserAuditEntries).mockReturnValue({ data: { items: [], total: 0 }, isLoading: false } as any)

    renderWithRouter(<UserDetailPage />, ["/users/u1"])

    expect(screen.getByText("Edit")).toBeInTheDocument()
    expect(screen.getByText("Delete")).toBeInTheDocument()
  })

  it("shows permissions tab with role-based permissions", async () => {
    const user = userEvent.setup()
    vi.mocked(usersHooks.useUser).mockReturnValue({
      data: mockUser, isLoading: false, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(usersHooks.useDeleteUser).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(usersHooks.useUserSessions).mockReturnValue({ data: [], isLoading: false } as any)
    vi.mocked(usersHooks.useUserAuditEntries).mockReturnValue({ data: { items: [], total: 0 }, isLoading: false } as any)

    renderWithRouter(<UserDetailPage />, ["/users/u1"])

    await user.click(screen.getByRole("tab", { name: "Permissions" }))

    await waitFor(() => {
      expect(screen.getByText("assessments:read")).toBeInTheDocument()
    })
    expect(screen.getByText("users:write")).toBeInTheDocument()
  })

  it("shows sessions placeholder", async () => {
    const user = userEvent.setup()
    vi.mocked(usersHooks.useUser).mockReturnValue({
      data: mockUser, isLoading: false, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(usersHooks.useDeleteUser).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(usersHooks.useUserSessions).mockReturnValue({ data: undefined, isLoading: false } as any)
    vi.mocked(usersHooks.useUserAuditEntries).mockReturnValue({ data: { items: [], total: 0 }, isLoading: false } as any)

    renderWithRouter(<UserDetailPage />, ["/users/u1"])

    await user.click(screen.getByRole("tab", { name: "Sessions" }))

    await waitFor(() => {
      expect(screen.getByText("Ready for backend integration")).toBeInTheDocument()
    })
  })
})

describe("CreateUserPage", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockAuth()
  })

  it("renders form", () => {
    vi.mocked(usersHooks.useCreateUser).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)

    renderWithRouter(<CreateUserPage />, ["/users/new"])

    expect(screen.getAllByText("Create User").length).toBeGreaterThan(0)
    expect(screen.getByLabelText("Username")).toBeInTheDocument()
    expect(screen.getByLabelText("Email")).toBeInTheDocument()
    expect(screen.getByLabelText("Password")).toBeInTheDocument()
    expect(screen.getByLabelText("Role")).toBeInTheDocument()
  })

  it("validates required fields", async () => {
    const user = userEvent.setup()
    vi.mocked(usersHooks.useCreateUser).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)

    renderWithRouter(<CreateUserPage />, ["/users/new"])

    await user.click(screen.getByRole("button", { name: "Create User" }))

    await waitFor(() => {
      expect(screen.getByText("Username must be at least 3 characters")).toBeInTheDocument()
    })
    expect(screen.getByText("Invalid email address")).toBeInTheDocument()
    expect(screen.getByText("Password must be at least 8 characters")).toBeInTheDocument()
  })
})

describe("EditUserPage", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockAuth()
  })

  it("renders form with user data", async () => {
    vi.mocked(usersHooks.useUser).mockReturnValue({
      data: mockUser, isLoading: false, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(usersHooks.useUpdateUser).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(usersHooks.useResetPassword).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)

    renderWithRouter(<EditUserPage />, ["/users/u1/edit"])

    await waitFor(() => {
      expect(screen.getByDisplayValue("admin@test.com")).toBeInTheDocument()
    })
    expect(screen.getByText("Edit: admin")).toBeInTheDocument()
    expect(screen.getByText("Reset Password")).toBeInTheDocument()
  })
})
