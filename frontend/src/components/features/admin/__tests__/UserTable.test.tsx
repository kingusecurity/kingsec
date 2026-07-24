import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { UserTable } from '../UserTable'
import type { AdminUser } from '@/api/admin'

const mockUsers: AdminUser[] = [
  {
    user_id: 'u1',
    username: 'admin1',
    email: 'admin@example.com',
    role: 'admin',
    is_active: true,
    created_at: '2025-01-15T10:00:00Z',
    last_login_at: '2025-06-15T08:30:00Z',
  },
  {
    user_id: 'u2',
    username: 'analyst1',
    email: 'analyst@example.com',
    role: 'analyst',
    is_active: false,
    created_at: '2025-03-01T12:00:00Z',
    last_login_at: null,
  },
]

function renderTable(props: Partial<React.ComponentProps<typeof UserTable>> = {}) {
  return render(
    <MemoryRouter>
      <UserTable
        users={mockUsers}
        isLoading={false}
        error={null}
        onRetry={vi.fn()}
        currentPage={1}
        totalPages={1}
        onPageChange={vi.fn()}
        sortBy="username"
        sortOrder="asc"
        onSortChange={vi.fn()}
        {...props}
      />
    </MemoryRouter>,
  )
}

describe('UserTable', () => {
  it('renders user rows', () => {
    renderTable()
    expect(screen.getByText('admin1')).toBeInTheDocument()
    expect(screen.getByText('analyst1')).toBeInTheDocument()
  })

  it('renders email addresses', () => {
    renderTable()
    expect(screen.getByText('admin@example.com')).toBeInTheDocument()
    expect(screen.getByText('analyst@example.com')).toBeInTheDocument()
  })

  it('renders role badges', () => {
    renderTable()
    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByText('analyst')).toBeInTheDocument()
  })

  it('renders status badges', () => {
    renderTable()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByText('Inactive')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    const { container } = renderTable({ users: undefined, isLoading: true })
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })

  it('shows error state', () => {
    renderTable({ users: undefined, error: new Error('API error') })
    expect(screen.getByText('Failed to load users')).toBeInTheDocument()
  })

  it('shows empty state', () => {
    renderTable({ users: [] })
    expect(screen.getByText('No users found')).toBeInTheDocument()
  })

  it('renders column headers', () => {
    renderTable()
    expect(screen.getByText('Username')).toBeInTheDocument()
    expect(screen.getByText('Email')).toBeInTheDocument()
    expect(screen.getByText('Role')).toBeInTheDocument()
    expect(screen.getByText('Last Login')).toBeInTheDocument()
    expect(screen.getByText('Created')).toBeInTheDocument()
    expect(screen.getByText('Status')).toBeInTheDocument()
  })

  it('shows pagination when multiple pages', () => {
    renderTable({ totalPages: 3, currentPage: 1 })
    expect(screen.getByLabelText('Pagination')).toBeInTheDocument()
  })

  it('hides pagination when single page', () => {
    renderTable({ totalPages: 1 })
    expect(screen.queryByLabelText('Pagination')).not.toBeInTheDocument()
  })
})
