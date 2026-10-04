import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RoleGuard, BootstrapGuard } from '../shared/RouteGuards'
import { useAuthStore } from '@/store/auth'

vi.mock('@/hooks/use-settings', () => ({
  useHealth: vi.fn(),
}))

import { useHealth } from '@/hooks/use-settings'

const queryClient = new QueryClient()

function Wrapper({ children }: { children: React.ReactNode }) {
  return (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('RouteGuard', () => {
  beforeEach(() => {
    useAuthStore.setState({ user: null, isAuthenticated: false })
  })

  it('renders children when role is sufficient', () => {
    useAuthStore.setState({
      user: { user_id: '1', username: 'admin', role: 'admin', email: '', is_active: true, created_at: '', last_login_at: null },
      isAuthenticated: true,
    })

    render(
      <Wrapper>
        <RoleGuard roles={['viewer', 'analyst', 'admin']}>
          <div>Protected Content</div>
        </RoleGuard>
      </Wrapper>,
    )

    expect(screen.getByText('Protected Content')).toBeInTheDocument()
  })

  it('shows fallback when role is insufficient', () => {
    useAuthStore.setState({
      user: { user_id: '1', username: 'viewer', role: 'viewer', email: '', is_active: true, created_at: '', last_login_at: null },
      isAuthenticated: true,
    })

    render(
      <Wrapper>
        <RoleGuard roles={['admin']} fallback={<div>No Access</div>}>
          <div>Admin Only</div>
        </RoleGuard>
      </Wrapper>,
    )

    expect(screen.getByText('No Access')).toBeInTheDocument()
    expect(screen.queryByText('Admin Only')).not.toBeInTheDocument()
  })
})

describe('BootstrapGuard', () => {
  function renderWithRoutes(initialPath: string) {
    return render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={[initialPath]}>
          <Routes>
            <Route path="/login" element={<BootstrapGuard><div>Login Form</div></BootstrapGuard>} />
            <Route path="/bootstrap-required" element={<div>Bootstrap Instructions</div>} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    )
  }

  it('renders children when bootstrap is not required', () => {
    vi.mocked(useHealth).mockReturnValue({ data: { status: 'ok', bootstrap_required: false }, isLoading: false } as any)
    renderWithRoutes('/login')
    expect(screen.getByText('Login Form')).toBeInTheDocument()
  })

  it('redirects to /bootstrap-required when no admin exists yet', () => {
    vi.mocked(useHealth).mockReturnValue({ data: { status: 'ok', bootstrap_required: true }, isLoading: false } as any)
    renderWithRoutes('/login')
    expect(screen.getByText('Bootstrap Instructions')).toBeInTheDocument()
    expect(screen.queryByText('Login Form')).not.toBeInTheDocument()
  })

  it('shows a loading state while checking, not the form', () => {
    vi.mocked(useHealth).mockReturnValue({ data: undefined, isLoading: true } as any)
    renderWithRoutes('/login')
    expect(screen.queryByText('Login Form')).not.toBeInTheDocument()
  })
})
