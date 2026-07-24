import { render, screen } from '@testing-library/react'
import { UserCard } from '../UserCard'
import type { AdminUser } from '@/api/admin'

const mockUser: AdminUser = {
  user_id: '1',
  username: 'johndoe',
  email: 'john@example.com',
  role: 'viewer',
  is_active: true,
  created_at: '2024-01-01T00:00:00Z',
  last_login_at: null,
}

describe('UserCard', () => {
  it('renders user info', () => {
    render(<UserCard user={mockUser} isLoading={false} />)
    expect(screen.getByText('johndoe')).toBeInTheDocument()
    expect(screen.getByText('john@example.com')).toBeInTheDocument()
  })
})
