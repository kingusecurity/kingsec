import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { UnauthorizedPage } from '@/pages/UnauthorizedPage'
import { useAuthStore } from '@/store/auth'

describe('UnauthorizedPage', () => {
  beforeEach(() => {
    useAuthStore.setState({ user: null, isAuthenticated: false })
  })

  it('renders access denied message', () => {
    render(
      <MemoryRouter>
        <UnauthorizedPage />
      </MemoryRouter>,
    )

    expect(screen.getByText('Access Denied')).toBeInTheDocument()
    expect(screen.getByText('Return to Dashboard')).toBeInTheDocument()
  })

  it('displays current user role', () => {
    useAuthStore.setState({
      user: { user_id: '1', username: 'viewer1', role: 'viewer', email: '', is_active: true, created_at: '', last_login_at: null },
      isAuthenticated: true,
    })

    render(
      <MemoryRouter>
        <UnauthorizedPage />
      </MemoryRouter>,
    )

    expect(screen.getByText('viewer')).toBeInTheDocument()
  })
})
