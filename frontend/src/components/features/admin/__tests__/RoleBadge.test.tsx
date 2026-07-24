import { render, screen } from '@testing-library/react'
import { RoleBadge } from '../RoleBadge'

describe('RoleBadge', () => {
  it('renders admin role', () => {
    render(<RoleBadge role="admin" />)
    expect(screen.getByText('admin')).toBeInTheDocument()
  })

  it('renders analyst role', () => {
    render(<RoleBadge role="analyst" />)
    expect(screen.getByText('analyst')).toBeInTheDocument()
  })

  it('renders viewer role', () => {
    render(<RoleBadge role="viewer" />)
    expect(screen.getByText('viewer')).toBeInTheDocument()
  })
})
