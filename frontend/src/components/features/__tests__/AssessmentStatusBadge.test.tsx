import { render, screen } from '@testing-library/react'
import { AssessmentStatusBadge } from '../assessment/AssessmentStatusBadge'

describe('AssessmentStatusBadge', () => {
  it('renders status text', () => {
    render(<AssessmentStatusBadge status="completed" />)
    expect(screen.getByText('completed')).toBeInTheDocument()
  })

  it('maps statuses to correct badge variants', () => {
    const { container, rerender } = render(<AssessmentStatusBadge status="completed" />)
    expect(container.firstChild).toHaveClass('bg-emerald-900/50', 'text-emerald-400')

    rerender(<AssessmentStatusBadge status="failed" />)
    expect(container.firstChild).toHaveClass('bg-red-900/50', 'text-red-400')

    rerender(<AssessmentStatusBadge status="running" />)
    expect(container.firstChild).toHaveClass('bg-gray-800', 'text-gray-400')

    rerender(<AssessmentStatusBadge status="pending" />)
    expect(container.firstChild).toHaveClass('bg-yellow-900/50', 'text-yellow-400')
  })
})
