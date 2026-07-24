import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RoleGuard } from '../shared/RouteGuards'
import { useAuthStore } from '@/store/auth'

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
