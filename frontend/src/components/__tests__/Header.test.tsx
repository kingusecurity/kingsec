import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Header } from '../layout/Header'
import { useAuthStore } from '@/store/auth'
import { useUIStore } from '@/store/ui'

const queryClient = new QueryClient()

function renderHeader() {
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/dashboard']}>
        <Header />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('Header', () => {
  beforeEach(() => {
    useAuthStore.setState({ user: null, isAuthenticated: false })
    useUIStore.setState({ sidebarCollapsed: false, sidebarMobileOpen: false })
  })

  it('renders search input', () => {
    renderHeader()
    expect(screen.getByLabelText('Global search (coming soon)')).toBeInTheDocument()
  })

  it('renders notification bell', () => {
    renderHeader()
    expect(screen.getByLabelText('Notifications')).toBeInTheDocument()
  })

  it('shows username when authenticated', () => {
    useAuthStore.setState({
      user: { user_id: '1', username: 'testuser', role: 'admin', email: '', is_active: true, created_at: '', last_login_at: null },
      isAuthenticated: true,
    })
    renderHeader()
    expect(screen.getByText('testuser')).toBeInTheDocument()
  })

  it('shows mobile menu button', () => {
    renderHeader()
    expect(screen.getByLabelText('Open navigation menu')).toBeInTheDocument()
  })
})
