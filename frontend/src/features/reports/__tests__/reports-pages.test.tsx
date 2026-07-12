import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen, fireEvent, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { ReportsListPage } from "../pages/reports-list-page"
import { ReportViewerPage } from "../pages/report-viewer-page"
import * as assessmentsHooks from "@/features/assessments/hooks/use-assessments"
import * as reportsHooks from "../hooks/use-reports"
import * as authHook from "@/features/auth/hooks/use-auth"

vi.mock("@/features/assessments/hooks/use-assessments")
vi.mock("../hooks/use-reports")
vi.mock("@/features/auth/hooks/use-auth")

function createQueryWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
}

function renderWithRouter(ui: React.ReactElement, initialEntries = ["/reports"]) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      {ui}
    </MemoryRouter>,
    { wrapper: createQueryWrapper() },
  )
}

const mockAssessments = {
  items: [
    { assessment_id: "1", target: "https://example.com", status: "COMPLETED", findings_count: 3, created_at: "2025-01-01T00:00:00Z", authorized_by: "admin" },
    { assessment_id: "2", target: "https://test.com", status: "COMPLETED", findings_count: 0, created_at: "2025-01-02T00:00:00Z", authorized_by: "admin" },
    { assessment_id: "3", target: "https://pending.com", status: "RUNNING", findings_count: 0, created_at: "2025-01-03T00:00:00Z", authorized_by: "admin" },
  ],
  total: 3,
}

const mockAssessmentDetail = {
  assessment_id: "1",
  target: "https://example.com",
  status: "COMPLETED",
  findings: [
    { title: "XSS", severity: "HIGH", category: "web", description: "Reflected XSS", recommendation: "Fix it", evidence: [], references: [] },
    { title: "Info Leak", severity: "MEDIUM", category: "web", description: "Leak", recommendation: "Fix", evidence: [], references: [] },
  ],
  created_at: "2025-01-01T00:00:00Z",
  authorized_by: "admin",
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

describe("ReportsListPage", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockAuth()
  })

  it("renders page header", () => {
    vi.mocked(assessmentsHooks.useAssessments).mockReturnValue({
      data: mockAssessments, isLoading: false, error: null, refetch: vi.fn(), isFetching: false,
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({ mutate: vi.fn(), isPending: false, progress: null } as any)

    renderWithRouter(<ReportsListPage />)

    expect(screen.getByText("Reports")).toBeInTheDocument()
  })

  it("shows completed assessments with findings", () => {
    vi.mocked(assessmentsHooks.useAssessments).mockReturnValue({
      data: mockAssessments, isLoading: false, error: null, refetch: vi.fn(), isFetching: false,
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({ mutate: vi.fn(), isPending: false, progress: null } as any)

    renderWithRouter(<ReportsListPage />)

    expect(screen.getByText("https://example.com")).toBeInTheDocument()
    expect(screen.getByText("https://test.com")).toBeInTheDocument()
    expect(screen.queryByText("https://pending.com")).not.toBeInTheDocument()
  })

  it("shows empty state when no reports", () => {
    vi.mocked(assessmentsHooks.useAssessments).mockReturnValue({
      data: { items: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn(), isFetching: false,
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({ mutate: vi.fn(), isPending: false, progress: null } as any)

    renderWithRouter(<ReportsListPage />)

    expect(screen.getByText("No reports found")).toBeInTheDocument()
  })

  it("filters by search", async () => {
    vi.mocked(assessmentsHooks.useAssessments).mockReturnValue({
      data: mockAssessments, isLoading: false, error: null, refetch: vi.fn(), isFetching: false,
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({ mutate: vi.fn(), isPending: false, progress: null } as any)

    renderWithRouter(<ReportsListPage />)

    const searchInput = screen.getByPlaceholderText("Search by target or ID...")
    fireEvent.change(searchInput, { target: { value: "example" } })

    await waitFor(() => {
      expect(screen.queryByText("https://test.com")).not.toBeInTheDocument()
    })
    expect(screen.getByText("https://example.com")).toBeInTheDocument()
  })

  it("shows loading skeletons", () => {
    vi.mocked(assessmentsHooks.useAssessments).mockReturnValue({
      data: undefined, isLoading: true, error: null, refetch: vi.fn(), isFetching: false,
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({ mutate: vi.fn(), isPending: false, progress: null } as any)

    const { container } = renderWithRouter(<ReportsListPage />)

    expect(container.querySelectorAll(".skeleton").length).toBeGreaterThan(0)
  })

  it("shows error state on fetch failure", () => {
    const error = new Error("Forbidden") as any
    error.status = 403
    vi.mocked(assessmentsHooks.useAssessments).mockReturnValue({
      data: undefined, isLoading: false, error, refetch: vi.fn(), isFetching: false,
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({ mutate: vi.fn(), isPending: false, progress: null } as any)

    renderWithRouter(<ReportsListPage />)

    expect(screen.getByRole("alert")).toBeInTheDocument()
  })
})

describe("ReportViewerPage", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockAuth()
  })

  it("shows loading state", () => {
    vi.mocked(assessmentsHooks.useAssessmentDetail).mockReturnValue({
      data: undefined, isLoading: true, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({ mutate: vi.fn(), isPending: false, progress: null } as any)

    const { container } = renderWithRouter(
      <ReportViewerPage />,
      ["/reports/1"],
    )

    expect(container.querySelectorAll(".skeleton").length).toBeGreaterThan(0)
  })

  it("shows error state", async () => {
    const error = new Error("Not found") as any
    error.status = 404
    vi.mocked(assessmentsHooks.useAssessmentDetail).mockReturnValue({
      data: undefined, isLoading: false, error, refetch: vi.fn(),
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({ mutate: vi.fn(), isPending: false, progress: null } as any)

    renderWithRouter(<ReportViewerPage />, ["/reports/1"])

    await waitFor(() => {
      expect(screen.getByText("Not found")).toBeInTheDocument()
    })
  })

  it("renders report detail with tabs", async () => {
    vi.mocked(assessmentsHooks.useAssessmentDetail).mockReturnValue({
      data: mockAssessmentDetail, isLoading: false, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({ mutate: vi.fn(), isPending: false, progress: null } as any)

    renderWithRouter(<ReportViewerPage />, ["/reports/1"])

    expect(screen.getByText("Report: https://example.com")).toBeInTheDocument()
    expect(screen.getByText("Preview")).toBeInTheDocument()
    expect(screen.getByText("Metadata")).toBeInTheDocument()
    expect(screen.getByText("History")).toBeInTheDocument()
  })

  it("shows download and regenerate buttons for ADMIN", async () => {
    vi.mocked(assessmentsHooks.useAssessmentDetail).mockReturnValue({
      data: mockAssessmentDetail, isLoading: false, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({ mutate: vi.fn(), isPending: false, progress: null } as any)

    renderWithRouter(<ReportViewerPage />, ["/reports/1"])

    expect(screen.getByText("Download")).toBeInTheDocument()
    expect(screen.getByText("Regenerate")).toBeInTheDocument()
  })

  it("hides regenerate button for VIEWER role", async () => {
    mockAuth("VIEWER")
    vi.mocked(assessmentsHooks.useAssessmentDetail).mockReturnValue({
      data: mockAssessmentDetail, isLoading: false, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({ mutate: vi.fn(), isPending: false, progress: null } as any)

    renderWithRouter(<ReportViewerPage />, ["/reports/1"])

    expect(screen.getByText("Download")).toBeInTheDocument()
    expect(screen.queryByText("Regenerate")).not.toBeInTheDocument()
  })

  it("shows download progress bar when downloading", async () => {
    vi.mocked(assessmentsHooks.useAssessmentDetail).mockReturnValue({
      data: mockAssessmentDetail, isLoading: false, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({
      mutate: vi.fn(),
      isPending: true,
      progress: { loaded: 512, total: 1024, percent: 50 },
    } as any)

    renderWithRouter(<ReportViewerPage />, ["/reports/1"])

    expect(screen.getByText("50%")).toBeInTheDocument()
    expect(screen.getByText("Downloading report...")).toBeInTheDocument()
  })

  it("shows retry button on download failure", async () => {
    vi.mocked(assessmentsHooks.useAssessmentDetail).mockReturnValue({
      data: mockAssessmentDetail, isLoading: false, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({
      mutate: vi.fn(),
      isPending: false,
      isError: true,
      error: new Error("Download failed"),
      progress: null,
    } as any)

    renderWithRouter(<ReportViewerPage />, ["/reports/1"])

    expect(screen.getByText("Download failed.")).toBeInTheDocument()
    expect(screen.getByText("Retry")).toBeInTheDocument()
  })

  it("shows PDF preview iframe for completed assessment", async () => {
    vi.mocked(assessmentsHooks.useAssessmentDetail).mockReturnValue({
      data: mockAssessmentDetail, isLoading: false, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({ mutate: vi.fn(), isPending: false, progress: null } as any)

    renderWithRouter(<ReportViewerPage />, ["/reports/1"])

    expect(screen.getByTitle("Report PDF preview")).toBeInTheDocument()
    expect(screen.getByText("PDF Preview")).toBeInTheDocument()
  })

  it("shows 'no report' message for non-completed assessment", async () => {
    vi.mocked(assessmentsHooks.useAssessmentDetail).mockReturnValue({
      data: { ...mockAssessmentDetail, status: "RUNNING", findings: [] },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({ mutate: vi.fn(), isPending: false, progress: null } as any)

    renderWithRouter(<ReportViewerPage />, ["/reports/1"])

    expect(screen.getByText("No report generated")).toBeInTheDocument()
  })

  it("shows metadata tab with all fields", async () => {
    const user = userEvent.setup()
    vi.mocked(assessmentsHooks.useAssessmentDetail).mockReturnValue({
      data: mockAssessmentDetail, isLoading: false, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({ mutate: vi.fn(), isPending: false, progress: null } as any)

    renderWithRouter(<ReportViewerPage />, ["/reports/1"])

    await user.click(screen.getByRole("tab", { name: "Metadata" }))

    await waitFor(() => {
      expect(screen.getByText("Assessment ID")).toBeInTheDocument()
    })
    expect(screen.getByText("Target")).toBeInTheDocument()
    expect(screen.getByText("Status")).toBeInTheDocument()
    expect(screen.getByText("Findings")).toBeInTheDocument()
    expect(screen.getByText("Created")).toBeInTheDocument()
    expect(screen.getByText("Severity Breakdown")).toBeInTheDocument()
  })

  it("shows history tab with backend integration placeholder", async () => {
    const user = userEvent.setup()
    vi.mocked(assessmentsHooks.useAssessmentDetail).mockReturnValue({
      data: mockAssessmentDetail, isLoading: false, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({ mutate: vi.fn(), isPending: false, progress: null } as any)

    renderWithRouter(<ReportViewerPage />, ["/reports/1"])

    await user.click(screen.getByRole("tab", { name: "History" }))

    await waitFor(() => {
      expect(screen.getByText("Report History")).toBeInTheDocument()
    })
    expect(screen.getByText("Ready for backend integration")).toBeInTheDocument()
  })
})
