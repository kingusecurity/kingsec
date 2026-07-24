import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AdminDashboardPage } from '../AdminDashboardPage'

vi.mock('@/hooks/use-admin', () => ({
  useAdminStats: vi.fn(),
}))

import { useAdminStats } from '@/hooks/use-admin'

const queryClient = new QueryClient()

function renderPage() {
  return render(
    <QueryClientProvider client={queryClient}>
      <AdminDashboardPage />
    </QueryClientProvider>,
  )
}

describe('AdminDashboardPage', () => {
  beforeEach(() => {
    vi.mocked(useAdminStats).mockReturnValue({
      data: { total_users: 100, active_users: 80, disabled_users: 20, admin_count: 5, analyst_count: 30, viewer_count: 65 },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
  })

  it('renders page title', () => {
    renderPage()
    expect(screen.getByText('Administration')).toBeInTheDocument()
  })

  it('renders all stat cards', () => {
    renderPage()
    expect(screen.getByText('Total Users')).toBeInTheDocument()
    expect(screen.getByText('Active Users')).toBeInTheDocument()
    expect(screen.getByText('Disabled Users')).toBeInTheDocument()
    expect(screen.getByText('Administrators')).toBeInTheDocument()
    expect(screen.getByText('Analysts')).toBeInTheDocument()
    expect(screen.getByText('Viewers')).toBeInTheDocument()
  })

  it('renders stat values', () => {
    renderPage()
    expect(screen.getByText('100')).toBeInTheDocument()
    expect(screen.getByText('80')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()
    expect(screen.getByText('30')).toBeInTheDocument()
    expect(screen.getByText('65')).toBeInTheDocument()
  })
})
