import { render, screen } from '@testing-library/react'
import { GeneralSection } from '../GeneralSection'
import { useAuthStore } from '@/store/auth'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

const queryClient = new QueryClient()

function renderSection() {
  return render(
    <QueryClientProvider client={queryClient}>
      <GeneralSection />
    </QueryClientProvider>,
  )
}

describe('GeneralSection', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: {
        user_id: 'u1',
        username: 'testuser',
        email: 'test@example.com',
        role: 'admin',
        is_active: true,
        created_at: '2025-01-15T10:00:00Z',
        last_login_at: '2025-06-15T08:30:00Z',
      },
      isAuthenticated: true,
    })
  })

  it('renders title', () => {
    renderSection()
    expect(screen.getByText('General')).toBeInTheDocument()
  })

  it('shows username', () => {
    renderSection()
    expect(screen.getByText('testuser')).toBeInTheDocument()
  })

  it('shows email', () => {
    renderSection()
    expect(screen.getByText('test@example.com')).toBeInTheDocument()
  })

  it('shows role badge', () => {
    renderSection()
    expect(screen.getByText('admin')).toBeInTheDocument()
  })

  it('shows active status', () => {
    renderSection()
    expect(screen.getByText('Active')).toBeInTheDocument()
  })

  it('shows member since date', () => {
    renderSection()
    expect(screen.getByText(/Jan \d{1,2}, 2025/)).toBeInTheDocument()
  })

  it('shows last login date', () => {
    renderSection()
    expect(screen.getByText(/Jun \d{1,2}, 2025/)).toBeInTheDocument()
  })

  it('shows Inactive badge when user is not active', () => {
    useAuthStore.setState({
      user: {
        user_id: 'u2',
        username: 'inactive',
        email: '',
        role: 'viewer',
        is_active: false,
        created_at: '',
        last_login_at: null,
      },
      isAuthenticated: true,
    })
    renderSection()
    expect(screen.getByText('Inactive')).toBeInTheDocument()
  })
})
