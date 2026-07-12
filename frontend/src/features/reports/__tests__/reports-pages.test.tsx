import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen, fireEvent, waitFor } from "@testing-library/react"
import { MemoryRouter } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { ReportsListPage } from "../pages/reports-list-page"
import { ReportViewerPage } from "../pages/report-viewer-page"
import * as assessmentsHooks from "@/features/assessments/hooks/use-assessments"
import * as reportsHooks from "../hooks/use-reports"

vi.mock("@/features/assessments/hooks/use-assessments")
vi.mock("../hooks/use-reports")

function createQueryWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
}

function renderWithRouter(ui: React.ReactElement) {
  return render(
    <MemoryRouter initialEntries={["/reports"]}>
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

describe("ReportsListPage", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("renders page header", () => {
    vi.mocked(assessmentsHooks.useAssessments).mockReturnValue({
      data: mockAssessments, isLoading: false, error: null, refetch: vi.fn(), isFetching: false,
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)

    renderWithRouter(<ReportsListPage />)

    expect(screen.getByText("Reports")).toBeInTheDocument()
  })

  it("shows completed assessments with findings", () => {
    vi.mocked(assessmentsHooks.useAssessments).mockReturnValue({
      data: mockAssessments, isLoading: false, error: null, refetch: vi.fn(), isFetching: false,
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)

    renderWithRouter(<ReportsListPage />)

    expect(screen.getByText("https://example.com")).toBeInTheDocument()
    expect(screen.getByText("https://test.com")).toBeInTheDocument()
    // Running assessment filtered out
    expect(screen.queryByText("https://pending.com")).not.toBeInTheDocument()
  })

  it("shows empty state when no reports", () => {
    vi.mocked(assessmentsHooks.useAssessments).mockReturnValue({
      data: { items: [], total: 0 }, isLoading: false, error: null, refetch: vi.fn(), isFetching: false,
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)

    renderWithRouter(<ReportsListPage />)

    expect(screen.getByText("No reports found")).toBeInTheDocument()
  })

  it("filters by search", async () => {
    vi.mocked(assessmentsHooks.useAssessments).mockReturnValue({
      data: mockAssessments, isLoading: false, error: null, refetch: vi.fn(), isFetching: false,
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)

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
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)

    const { container } = renderWithRouter(<ReportsListPage />)

    expect(container.querySelectorAll(".skeleton").length).toBeGreaterThan(0)
  })
})

describe("ReportViewerPage", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("shows loading state", () => {
    vi.mocked(assessmentsHooks.useAssessmentDetail).mockReturnValue({
      data: undefined, isLoading: true, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)

    const { container } = render(
      <MemoryRouter initialEntries={["/reports/1"]}>
        <ReportViewerPage />
      </MemoryRouter>,
      { wrapper: createQueryWrapper() },
    )

    expect(container.querySelectorAll(".skeleton").length).toBeGreaterThan(0)
  })

  it("shows error state", async () => {
    const error = new Error("Not found") as any
    error.status = 404
    vi.mocked(assessmentsHooks.useAssessmentDetail).mockReturnValue({
      data: undefined, isLoading: false, error, refetch: vi.fn(),
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)

    render(
      <MemoryRouter initialEntries={["/reports/1"]}>
        <ReportViewerPage />
      </MemoryRouter>,
      { wrapper: createQueryWrapper() },
    )

    await waitFor(() => {
      expect(screen.getByText("Not found")).toBeInTheDocument()
    })
  })

  it("renders report detail with tabs", async () => {
    vi.mocked(assessmentsHooks.useAssessmentDetail).mockReturnValue({
      data: mockAssessmentDetail, isLoading: false, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)

    render(
      <MemoryRouter initialEntries={["/reports/1"]}>
        <ReportViewerPage />
      </MemoryRouter>,
      { wrapper: createQueryWrapper() },
    )

    expect(screen.getByText("Report: https://example.com")).toBeInTheDocument()
    expect(screen.getByText("Preview")).toBeInTheDocument()
    expect(screen.getByText("Metadata")).toBeInTheDocument()
    expect(screen.getByText("History")).toBeInTheDocument()
  })

  it("shows download and generate buttons", async () => {
    vi.mocked(assessmentsHooks.useAssessmentDetail).mockReturnValue({
      data: mockAssessmentDetail, isLoading: false, error: null, refetch: vi.fn(),
    } as any)
    vi.mocked(reportsHooks.useGenerateReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)
    vi.mocked(reportsHooks.useDownloadReport).mockReturnValue({
      mutate: vi.fn(), isPending: false,
    } as any)

    render(
      <MemoryRouter initialEntries={["/reports/1"]}>
        <ReportViewerPage />
      </MemoryRouter>,
      { wrapper: createQueryWrapper() },
    )

    expect(screen.getByText("Download")).toBeInTheDocument()
    expect(screen.getByText("Regenerate")).toBeInTheDocument()
  })
})
