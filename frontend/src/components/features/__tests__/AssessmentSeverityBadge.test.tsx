import { render, screen } from '@testing-library/react'
import { AssessmentSeverityBadge } from '../assessment/AssessmentSeverityBadge'

describe('AssessmentSeverityBadge', () => {
  it('renders severity text', () => {
    render(<AssessmentSeverityBadge severity="critical" />)
    expect(screen.getByText('critical')).toBeInTheDocument()
  })

  it('maps severities to correct badge variants', () => {
    const { container, rerender } = render(<AssessmentSeverityBadge severity="critical" />)
    expect(container.firstChild).toHaveClass('bg-red-900/50', 'text-red-400')

    rerender(<AssessmentSeverityBadge severity="high" />)
    expect(container.firstChild).toHaveClass('bg-orange-900/50', 'text-orange-400')

    rerender(<AssessmentSeverityBadge severity="medium" />)
    expect(container.firstChild).toHaveClass('bg-yellow-900/50', 'text-yellow-400')

    rerender(<AssessmentSeverityBadge severity="low" />)
    expect(container.firstChild).toHaveClass('bg-blue-900/50', 'text-blue-400')
  })
})
