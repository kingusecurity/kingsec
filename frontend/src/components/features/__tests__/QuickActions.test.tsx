import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QuickActions } from '../dashboard/QuickActions'
import { useAuthStore } from '@/store/auth'

const analyst = {
  user_id: 'u-1',
  username: 'analyst',
  role: 'analyst',
  email: '',
  is_active: true,
  created_at: '',
  last_login_at: null,
}

describe('QuickActions', () => {
  beforeEach(() => {
    useAuthStore.setState({ user: analyst, isAuthenticated: true })
  })

  it('renders all action links', () => {
    render(
      <MemoryRouter>
        <QuickActions />
      </MemoryRouter>,
    )
    expect(screen.getByText('New Assessment')).toBeInTheDocument()
    expect(screen.getByText('View Reports')).toBeInTheDocument()
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Settings')).toBeInTheDocument()
  })

  it('links to correct routes', () => {
    render(
      <MemoryRouter>
        <QuickActions />
      </MemoryRouter>,
    )
    expect(screen.getByText('New Assessment').closest('a')).toHaveAttribute('href', '/assessments/new')
    expect(screen.getByText('View Reports').closest('a')).toHaveAttribute('href', '/reports')
    expect(screen.getByText('Dashboard').closest('a')).toHaveAttribute('href', '/dashboard')
  })

  it('does not lead viewers to the analyst-only assessment form', () => {
    useAuthStore.setState({ user: { ...analyst, role: 'viewer' }, isAuthenticated: true })
    render(
      <MemoryRouter>
        <QuickActions suggestFirst />
      </MemoryRouter>,
    )
    expect(screen.queryByText('New Assessment')).not.toBeInTheDocument()
    expect(screen.queryByText('Start here')).not.toBeInTheDocument()
    expect(screen.getByText('View Reports')).toBeInTheDocument()
  })

  it('does not suggest New Assessment by default', () => {
    render(
      <MemoryRouter>
        <QuickActions />
      </MemoryRouter>,
    )
    expect(screen.queryByText('Start here')).not.toBeInTheDocument()
  })

  it('marks New Assessment as the suggested first step when suggestFirst is true', () => {
    render(
      <MemoryRouter>
        <QuickActions suggestFirst />
      </MemoryRouter>,
    )
    expect(screen.getByText('Start here')).toBeInTheDocument()
  })
})
