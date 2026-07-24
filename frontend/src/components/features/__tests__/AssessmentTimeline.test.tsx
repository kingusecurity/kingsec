import { render, screen } from '@testing-library/react'
import { AssessmentTimeline } from '../assessment/AssessmentTimeline'

describe('AssessmentTimeline', () => {
  it('renders all steps', () => {
    const steps = [
      { label: 'Draft', status: 'completed' as const },
      { label: 'Running', status: 'current' as const },
      { label: 'Completed', status: 'upcoming' as const },
    ]
    render(<AssessmentTimeline steps={steps} />)
    expect(screen.getByText('Draft')).toBeInTheDocument()
    expect(screen.getByText('Running')).toBeInTheDocument()
    expect(screen.getByText('Completed')).toBeInTheDocument()
  })

  it('renders timestamps when provided', () => {
    const steps = [
      { label: 'Draft', status: 'completed' as const, timestamp: '2024-01-01' },
      { label: 'Running', status: 'current' as const },
    ]
    render(<AssessmentTimeline steps={steps} />)
    expect(screen.getByText('2024-01-01')).toBeInTheDocument()
  })

  it('shows failed step with red styling', () => {
    const steps = [
      { label: 'Draft', status: 'completed' as const },
      { label: 'Running', status: 'failed' as const },
    ]
    render(<AssessmentTimeline steps={steps} />)
    expect(screen.getByText('Running')).toHaveClass('text-red-400')
  })
})
