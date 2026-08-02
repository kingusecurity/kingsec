import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Sidebar } from '../layout/Sidebar'
import { useAuthStore } from '@/store/auth'
import { useUIStore } from '@/store/ui'

const queryClient = new QueryClient()

function renderSidebar() {
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('Sidebar', () => {
  beforeEach(() => {
    useAuthStore.setState({ user: null, isAuthenticated: false })
    useUIStore.setState({ sidebarCollapsed: false, sidebarMobileOpen: false })
  })

  it('renders brand name', () => {
    renderSidebar()
    expect(screen.getByText('KingSec')).toBeInTheDocument()
  })

  it('shows navigation items', () => {
    useAuthStore.setState({
      user: { user_id: '1', username: 'admin', role: 'admin', email: '', is_active: true, created_at: '', last_login_at: null },
      isAuthenticated: true,
    })
    renderSidebar()
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Assessments')).toBeInTheDocument()
    expect(screen.getByText('Settings')).toBeInTheDocument()
  })

  it('shows username for authenticated user', () => {
    useAuthStore.setState({
      user: { user_id: '1', username: 'analyst1', role: 'ANALYST', email: '', is_active: true, created_at: '', last_login_at: null },
      isAuthenticated: true,
    })
    renderSidebar()
    expect(screen.getByText('analyst1')).toBeInTheDocument()
  })

  it('shows collapse button', () => {
    renderSidebar()
    expect(screen.getByLabelText('Collapse sidebar')).toBeInTheDocument()
  })

  it('shows sign out button', () => {
    renderSidebar()
    expect(screen.getByLabelText('Sign out')).toBeInTheDocument()
  })

  it('hides admin-only items for viewer', () => {
    useAuthStore.setState({
      user: { user_id: '1', username: 'viewer1', role: 'viewer', email: '', is_active: true, created_at: '', last_login_at: null },
      isAuthenticated: true,
    })
    renderSidebar()
    expect(screen.queryByText('Administration')).not.toBeInTheDocument()
  })
})
