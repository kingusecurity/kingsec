import { render, screen } from '@testing-library/react'
import { UserStatusBadge } from '../UserStatusBadge'

describe('UserStatusBadge', () => {
  it('renders Active for active users', () => {
    render(<UserStatusBadge isActive={true} />)
    expect(screen.getByText('Active')).toBeInTheDocument()
  })

  it('renders Inactive for inactive users', () => {
    render(<UserStatusBadge isActive={false} />)
    expect(screen.getByText('Inactive')).toBeInTheDocument()
  })
})
