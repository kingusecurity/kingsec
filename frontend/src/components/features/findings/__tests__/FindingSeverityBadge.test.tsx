import { render, screen } from '@testing-library/react'
import { FindingSeverityBadge } from '../FindingSeverityBadge'

describe('FindingSeverityBadge', () => {
  it('renders severity text', () => {
    render(<FindingSeverityBadge severity="critical" />)
    expect(screen.getByText('critical')).toBeInTheDocument()
  })

  it('applies correct variant classes', () => {
    const { container, rerender } = render(<FindingSeverityBadge severity="critical" />)
    expect(container.firstChild).toHaveClass('bg-red-900/50', 'text-red-400')

    rerender(<FindingSeverityBadge severity="high" />)
    expect(container.firstChild).toHaveClass('bg-orange-900/50', 'text-orange-400')

    rerender(<FindingSeverityBadge severity="medium" />)
    expect(container.firstChild).toHaveClass('bg-yellow-900/50', 'text-yellow-400')

    rerender(<FindingSeverityBadge severity="low" />)
    expect(container.firstChild).toHaveClass('bg-blue-900/50', 'text-blue-400')
  })

  it('handles informational severity', () => {
    const { container } = render(<FindingSeverityBadge severity="informational" />)
    expect(container.firstChild).toHaveClass('bg-gray-800', 'text-gray-400')
  })
})
