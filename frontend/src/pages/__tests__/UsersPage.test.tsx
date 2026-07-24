import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { UsersPage } from '../UsersPage'

vi.mock('@/hooks/use-admin', () => ({
  useUsers: vi.fn(),
  useCreateUser: vi.fn(),
}))

import { useUsers, useCreateUser } from '@/hooks/use-admin'

const queryClient = new QueryClient()

function renderPage() {
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <UsersPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('UsersPage', () => {
  beforeEach(() => {
    vi.mocked(useUsers).mockReturnValue({
      data: { items: [], total: 0, limit: 20, offset: 0 },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
    vi.mocked(useCreateUser).mockReturnValue({
      mutate: vi.fn(),
      isPending: false,
    } as any)
  })

  it('renders page title', () => {
    renderPage()
    expect(screen.getByText('Users')).toBeInTheDocument()
  })

  it('renders search input', () => {
    renderPage()
    expect(screen.getByLabelText('Search users')).toBeInTheDocument()
  })

  it('renders filter selects', () => {
    renderPage()
    expect(screen.getByLabelText('Filter by role')).toBeInTheDocument()
    expect(screen.getByLabelText('Filter by status')).toBeInTheDocument()
  })

  it('renders create user button', () => {
    renderPage()
    expect(screen.getByText('Create User')).toBeInTheDocument()
  })

  it('shows empty state when no users', () => {
    renderPage()
    expect(screen.getByText('No users found')).toBeInTheDocument()
  })
})
