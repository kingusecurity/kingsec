import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuditLogPage } from '../AuditLogPage'

vi.mock('@/hooks/use-audit', () => ({
  useAuditLog: vi.fn(),
}))

import { useAuditLog } from '@/hooks/use-audit'

const queryClient = new QueryClient()

function renderPage() {
  return render(
    <QueryClientProvider client={queryClient}>
      <AuditLogPage />
    </QueryClientProvider>,
  )
}

describe('AuditLogPage', () => {
  beforeEach(() => {
    vi.mocked(useAuditLog).mockReturnValue({
      data: { items: [], total: 0, limit: 20, offset: 0 },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
  })

  it('renders page title', () => {
    renderPage()
    expect(screen.getByText('Audit Log')).toBeInTheDocument()
  })

  it('shows empty state when no entries', () => {
    renderPage()
    expect(screen.getByText('No audit entries')).toBeInTheDocument()
  })

  it('renders filter selects', () => {
    renderPage()
    expect(screen.getByLabelText('Filter by action')).toBeInTheDocument()
    expect(screen.getByLabelText('Filter by resource type')).toBeInTheDocument()
    expect(screen.getByLabelText('Filter by result')).toBeInTheDocument()
  })
})
