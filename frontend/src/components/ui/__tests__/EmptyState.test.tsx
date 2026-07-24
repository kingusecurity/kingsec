import { render, screen } from '@testing-library/react'
import { EmptyState } from '../EmptyState'

describe('EmptyState', () => {
  it('renders title', () => {
    render(<EmptyState title="No data" />)
    expect(screen.getByText('No data')).toBeInTheDocument()
  })

  it('renders description', () => {
    render(<EmptyState title="No data" description="Nothing to show" />)
    expect(screen.getByText('Nothing to show')).toBeInTheDocument()
  })

  it('renders action button when provided', () => {
    render(<EmptyState title="No data" action={{ label: 'Create', onClick: vi.fn() }} />)
    expect(screen.getByText('Create')).toBeInTheDocument()
  })
})
