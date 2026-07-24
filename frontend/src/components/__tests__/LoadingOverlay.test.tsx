import { render, screen } from '@testing-library/react'
import { LoadingOverlay } from '../shared/LoadingOverlay'

describe('LoadingOverlay', () => {
  it('renders nothing when not loading', () => {
    const { container } = render(<LoadingOverlay loading={false} />)
    expect(container.firstChild).toBeNull()
  })

  it('renders spinner and message when loading', () => {
    render(<LoadingOverlay loading message="Loading data..." />)
    expect(screen.getByText('Loading data...')).toBeInTheDocument()
    expect(screen.getByRole('status', { name: 'Loading data...' })).toBeInTheDocument()
  })

  it('uses default message', () => {
    render(<LoadingOverlay loading />)
    const messages = screen.getAllByText('Loading...')
    expect(messages.length).toBeGreaterThanOrEqual(1)
  })
})
