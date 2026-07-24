import { render, screen } from '@testing-library/react'
import { UserCard } from '../UserCard'
import type { User } from '@/types/api'

const mockUser: User = {
  id: '1',
  username: 'johndoe',
  email: 'john@example.com',
  role: 'user',
  status: 'active',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
}

describe('UserCard', () => {
  it('renders user info', () => {
    render(<UserCard user={mockUser} />)
    expect(screen.getByText('johndoe')).toBeInTheDocument()
    expect(screen.getByText('john@example.com')).toBeInTheDocument()
  })
})
