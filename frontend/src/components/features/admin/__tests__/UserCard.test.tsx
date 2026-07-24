import { render, screen } from '@testing-library/react'
import { UserCard } from '../UserCard'
import type { AdminUser } from '@/api/admin'

const mockUser: AdminUser = {
  user_id: 'u1',
  username: 'testuser',
  email: 'test@example.com',
  role: 'admin',
  is_active: true,
  created_at: '2025-01-15T10:00:00Z',
  last_login_at: '2025-06-15T08:30:00Z',
}

describe('UserCard', () => {
  it('renders username and email', () => {
    render(<UserCard user={mockUser} isLoading={false} />)
    expect(screen.getByText('testuser')).toBeInTheDocument()
    expect(screen.getByText('test@example.com')).toBeInTheDocument()
  })

  it('renders Active badge', () => {
    render(<UserCard user={mockUser} isLoading={false} />)
    expect(screen.getByText('Active')).toBeInTheDocument()
  })

  it('renders role badge', () => {
    render(<UserCard user={mockUser} isLoading={false} />)
    expect(screen.getByText('admin')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    const { container } = render(<UserCard user={undefined} isLoading={true} />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })

  it('returns null when no user and not loading', () => {
    const { container } = render(<UserCard user={undefined} isLoading={false} />)
    expect(container.innerHTML).toBe('')
  })
})
