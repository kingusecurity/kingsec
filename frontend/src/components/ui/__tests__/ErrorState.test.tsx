import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ErrorState } from '../ErrorState'

describe('ErrorState', () => {
  it('renders default title', () => {
    render(<ErrorState message="Something went wrong" />)
    expect(screen.getAllByText('Something went wrong').length).toBeGreaterThan(0)
  })

  it('renders custom title', () => {
    render(<ErrorState title="Custom Error" message="Details" />)
    expect(screen.getByText('Custom Error')).toBeInTheDocument()
  })

  it('renders retry button and calls onRetry', async () => {
    const onRetry = vi.fn()
    render(<ErrorState message="Error" onRetry={onRetry} />)
    await userEvent.click(screen.getByText('Try again'))
    expect(onRetry).toHaveBeenCalledOnce()
  })

  it('does not show retry button when no handler', () => {
    render(<ErrorState message="Error" />)
    expect(screen.queryByText('Try again')).not.toBeInTheDocument()
  })
})
