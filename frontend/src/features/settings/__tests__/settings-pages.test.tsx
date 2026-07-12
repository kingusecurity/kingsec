import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen } from "@testing-library/react"
import { MemoryRouter } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { SettingsPage } from "../pages/settings-page"
import { SettingsSection } from "../components/settings-section"
import { SettingsPlaceholder } from "../components/settings-placeholder"
import * as settingsHooks from "../hooks/use-settings"
import * as authHook from "@/features/auth/hooks/use-auth"

vi.mock("../hooks/use-settings")
vi.mock("@/features/auth/hooks/use-auth")

function createQueryWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
}

function renderWithRouter(ui: React.ReactElement, initialEntries = ["/settings"]) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      {ui}
    </MemoryRouter>,
    { wrapper: createQueryWrapper() },
  )
}

function mockAuth() {
  vi.mocked(authHook.useAuth).mockReturnValue({
    user: { user_id: "u1", username: "admin", email: "admin@test.com", role: "ADMIN", is_active: true, created_at: "2025-01-01T00:00:00Z" },
    login: vi.fn(),
    logout: vi.fn(),
    register: vi.fn(),
    isLoading: false,
    isAuthenticated: true,
  } as any)
}

describe("SettingsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockAuth()
  })

  it("renders settings header", () => {
    vi.mocked(settingsHooks.useProfileSettings).mockReturnValue({
      data: undefined, isLoading: true, error: null, refetch: vi.fn(),
    } as any)

    renderWithRouter(<SettingsPage />)

    expect(screen.getByText("Settings")).toBeInTheDocument()
    expect(screen.getByText("Configure your KingSec instance.")).toBeInTheDocument()
  })

  it("renders sidebar navigation", () => {
    vi.mocked(settingsHooks.useProfileSettings).mockReturnValue({
      data: undefined, isLoading: true, error: null, refetch: vi.fn(),
    } as any)

    renderWithRouter(<SettingsPage />)

    expect(screen.getByText("Profile")).toBeInTheDocument()
    expect(screen.getByText("Appearance")).toBeInTheDocument()
    expect(screen.getByText("Security")).toBeInTheDocument()
    expect(screen.getByText("Notifications")).toBeInTheDocument()
    expect(screen.getByText("Scanner")).toBeInTheDocument()
    expect(screen.getByText("API Keys")).toBeInTheDocument()
    expect(screen.getByText("Advanced")).toBeInTheDocument()
  })

  it("renders loading skeletons", () => {
    vi.mocked(settingsHooks.useProfileSettings).mockReturnValue({
      data: undefined, isLoading: true, error: null, refetch: vi.fn(),
    } as any)

    const { container } = renderWithRouter(<SettingsPage />)
    expect(container.querySelectorAll(".skeleton").length).toBeGreaterThan(0)
  })
})

describe("SettingsSection", () => {
  it("renders title and description", () => {
    renderWithRouter(
      <SettingsSection title="Test Section" description="Test description">
        <div>Content</div>
      </SettingsSection>,
    )
    expect(screen.getByText("Test Section")).toBeInTheDocument()
    expect(screen.getByText("Test description")).toBeInTheDocument()
    expect(screen.getByText("Content")).toBeInTheDocument()
  })

  it("renders loading state", () => {
    const { container } = renderWithRouter(
      <SettingsSection title="Test" description="Desc" isLoading>
        <div>Content</div>
      </SettingsSection>,
    )
    expect(container.querySelectorAll(".skeleton").length).toBeGreaterThan(0)
  })

  it("renders error state with retry", () => {
    const onRetry = vi.fn()
    renderWithRouter(
      <SettingsSection title="Test" description="Desc" error="Something failed" onRetry={onRetry}>
        <div>Content</div>
      </SettingsSection>,
    )
    expect(screen.getByText("Something failed")).toBeInTheDocument()
    expect(screen.getByText("Retry")).toBeInTheDocument()
  })

  it("renders save button", () => {
    const onSave = vi.fn()
    renderWithRouter(
      <SettingsSection title="Test" description="Desc" onSave={onSave}>
        <div>Content</div>
      </SettingsSection>,
    )
    expect(screen.getByText("Save Changes")).toBeInTheDocument()
  })
})

describe("SettingsPlaceholder", () => {
  it("renders placeholder content", () => {
    renderWithRouter(
      <SettingsPlaceholder title="Not Available" description="Coming soon" />,
    )
    expect(screen.getByText("Not Available")).toBeInTheDocument()
    expect(screen.getByText("Coming soon")).toBeInTheDocument()
    expect(screen.getByText("Ready for backend integration")).toBeInTheDocument()
  })

  it("renders loading state", () => {
    renderWithRouter(
      <SettingsPlaceholder title="Loading" description="Wait" isLoading />,
    )
    expect(screen.getByText("Loading...")).toBeInTheDocument()
  })

  it("renders error state", () => {
    const onRetry = vi.fn()
    renderWithRouter(
      <SettingsPlaceholder title="Error" description="Failed" error="404" onRetry={onRetry} />,
    )
    expect(screen.getByText("404")).toBeInTheDocument()
    expect(screen.getByText("Retry")).toBeInTheDocument()
  })
})
