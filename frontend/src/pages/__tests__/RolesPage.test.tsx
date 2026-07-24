import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RolesPage } from '../RolesPage'

vi.mock('@/hooks/use-admin', () => ({
  useRoles: vi.fn(),
}))

import { useRoles } from '@/hooks/use-admin'

const queryClient = new QueryClient()

function renderPage() {
  return render(
    <QueryClientProvider client={queryClient}>
      <RolesPage />
    </QueryClientProvider>,
  )
}

describe('RolesPage', () => {
  beforeEach(() => {
    vi.mocked(useRoles).mockReturnValue({
      data: { roles: [] },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
  })

  it('renders page title', () => {
    renderPage()
    expect(screen.getAllByText('Roles & Permissions').length).toBeGreaterThanOrEqual(1)
  })

  it('renders page description', () => {
    renderPage()
    expect(screen.getByText('View system roles and their access permissions')).toBeInTheDocument()
  })
})
