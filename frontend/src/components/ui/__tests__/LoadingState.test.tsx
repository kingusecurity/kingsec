import { render, screen } from '@testing-library/react'
import { LoadingState } from '../LoadingState'

describe('LoadingState', () => {
  it('renders default message', () => {
    render(<LoadingState />)
    expect(screen.getAllByText('Loading...').length).toBeGreaterThan(0)
  })

  it('renders custom message', () => {
    render(<LoadingState message="Please wait..." />)
    expect(screen.getByText('Please wait...')).toBeInTheDocument()
  })
})
