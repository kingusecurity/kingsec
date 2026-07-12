import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen } from "@testing-library/react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { AnalyticsKPICards } from "../components/analytics-kpi-cards"
import { AnalyticsSeverityChart } from "../components/analytics-severity-chart"
import { AnalyticsStatusChart } from "../components/analytics-status-chart"
import { AnalyticsTopTargets } from "../components/analytics-top-targets"
import { AnalyticsExecutiveSummary } from "../components/analytics-executive-summary"
import { AnalyticsExport } from "../components/analytics-export"
import type { ExecutiveKPIs, RiskAnalytics } from "../types"

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

const MOCK_KPIs: ExecutiveKPIs = {
  totalAssessments: 150,
  running: 5,
  completed: 120,
  failed: 15,
  cancelled: 10,
  criticalFindings: 25,
  highFindings: 45,
  reportsGenerated: 120,
  averageScanDuration: 420,
  successRate: 80,
  lastUpdated: "2025-01-01T00:00:00Z",
}

describe("AnalyticsKPICards", () => {
  beforeEach(() => vi.clearAllMocks())

  it("renders all KPI values", () => {
    render(<AnalyticsKPICards kpis={MOCK_KPIs} />, { wrapper: createWrapper() })
    expect(screen.getByText("150")).toBeInTheDocument()
    expect(screen.getByText("5")).toBeInTheDocument()
    expect(screen.getAllByText("120").length).toBe(2)
    expect(screen.getByText("15")).toBeInTheDocument()
    expect(screen.getByText("80%")).toBeInTheDocument()
    expect(screen.getByText("25")).toBeInTheDocument()
    expect(screen.getByText("45")).toBeInTheDocument()
  })

  it("renders KPI labels", () => {
    render(<AnalyticsKPICards kpis={MOCK_KPIs} />, { wrapper: createWrapper() })
    expect(screen.getByText("Total Assessments")).toBeInTheDocument()
    expect(screen.getByText("Running")).toBeInTheDocument()
    expect(screen.getByText("Completed")).toBeInTheDocument()
    expect(screen.getByText("Failed")).toBeInTheDocument()
    expect(screen.getByText("Success Rate")).toBeInTheDocument()
    expect(screen.getByText("Critical Findings")).toBeInTheDocument()
    expect(screen.getByText("High Findings")).toBeInTheDocument()
    expect(screen.getByText("Reports Generated")).toBeInTheDocument()
  })

  it("renders average scan duration in minutes", () => {
    render(<AnalyticsKPICards kpis={MOCK_KPIs} />, { wrapper: createWrapper() })
    expect(screen.getByText("7m")).toBeInTheDocument()
  })
})

describe("AnalyticsSeverityChart", () => {
  beforeEach(() => vi.clearAllMocks())

  it("renders chart with data", () => {
    const data = [
      { name: "Critical", count: 10, fill: "red" },
      { name: "High", count: 20, fill: "orange" },
    ]
    render(<AnalyticsSeverityChart data={data} />, { wrapper: createWrapper() })
    expect(screen.getByText("Severity Distribution")).toBeInTheDocument()
  })

  it("renders empty state when no data", () => {
    render(<AnalyticsSeverityChart data={[]} />, { wrapper: createWrapper() })
    expect(screen.getByText("No data available")).toBeInTheDocument()
  })
})

describe("AnalyticsStatusChart", () => {
  beforeEach(() => vi.clearAllMocks())

  it("renders chart with data", () => {
    const data = [
      { name: "Completed", value: 100, color: "green" },
      { name: "Failed", value: 10, color: "red" },
    ]
    render(<AnalyticsStatusChart data={data} />, { wrapper: createWrapper() })
    expect(screen.getByText("Status Distribution")).toBeInTheDocument()
  })

  it("renders empty state when no data", () => {
    render(<AnalyticsStatusChart data={[]} />, { wrapper: createWrapper() })
    expect(screen.getByText("No data available")).toBeInTheDocument()
  })
})

describe("AnalyticsTopTargets", () => {
  beforeEach(() => vi.clearAllMocks())

  it("renders targets list", () => {
    const data = [
      { target: "192.168.1.1", findings: 15, riskLevel: "high" },
      { target: "10.0.0.1", findings: 5, riskLevel: "low" },
    ]
    render(<AnalyticsTopTargets data={data} />, { wrapper: createWrapper() })
    expect(screen.getByText("192.168.1.1")).toBeInTheDocument()
    expect(screen.getByText("10.0.0.1")).toBeInTheDocument()
    expect(screen.getByText("15 findings")).toBeInTheDocument()
    expect(screen.getByText("5 findings")).toBeInTheDocument()
  })

  it("renders empty state when no data", () => {
    render(<AnalyticsTopTargets data={[]} />, { wrapper: createWrapper() })
    expect(screen.getByText("No data available")).toBeInTheDocument()
  })
})

describe("AnalyticsExecutiveSummary", () => {
  beforeEach(() => vi.clearAllMocks())

  it("renders summary cards with values", () => {
    const summary = {
      biggestImprovement: "Scan time reduced 20%",
      biggestRegression: null,
      highestRiskTarget: "192.168.1.1",
      mostActiveAnalyst: "admin",
    }
    render(<AnalyticsExecutiveSummary summary={summary} />, { wrapper: createWrapper() })
    expect(screen.getByText("Executive Summary")).toBeInTheDocument()
    expect(screen.getByText("Scan time reduced 20%")).toBeInTheDocument()
    expect(screen.getByText("192.168.1.1")).toBeInTheDocument()
    expect(screen.getByText("admin")).toBeInTheDocument()
  })

  it("shows placeholder for null values", () => {
    const summary = {
      biggestImprovement: null,
      biggestRegression: null,
      highestRiskTarget: null,
      mostActiveAnalyst: null,
    }
    render(<AnalyticsExecutiveSummary summary={summary} />, { wrapper: createWrapper() })
    expect(screen.getAllByText("Ready for backend analytics").length).toBe(4)
  })
})

describe("AnalyticsExport", () => {
  beforeEach(() => vi.clearAllMocks())

  it("renders export buttons", () => {
    render(
      <AnalyticsExport kpis={MOCK_KPIs} trends={[]} risk={null} />,
      { wrapper: createWrapper() },
    )
    expect(screen.getByText("KPIs CSV")).toBeInTheDocument()
    expect(screen.getByText("Trends CSV")).toBeInTheDocument()
    expect(screen.getByText("Full JSON")).toBeInTheDocument()
  })

  it("disables buttons when no data", () => {
    render(
      <AnalyticsExport kpis={null} trends={[]} risk={null} />,
      { wrapper: createWrapper() },
    )
    expect(screen.getByText("KPIs CSV")).toBeDisabled()
    expect(screen.getByText("Trends CSV")).toBeDisabled()
    expect(screen.getByText("Full JSON")).toBeDisabled()
  })
})
