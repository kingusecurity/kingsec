import { render, screen } from '@testing-library/react'
import { AssessmentStatusBadge } from '../AssessmentStatusBadge'

describe('AssessmentStatusBadge', () => {
  it('renders completed status', () => {
    render(<AssessmentStatusBadge status="completed" />)
    expect(screen.getByText('completed')).toBeInTheDocument()
  })

  it('renders completed-with-gaps status', () => {
    render(<AssessmentStatusBadge status="completed_with_gaps" />)
    expect(screen.getByText('completed with gaps')).toBeInTheDocument()
  })

  it('renders running status', () => {
    render(<AssessmentStatusBadge status="running" />)
    expect(screen.getByText('running')).toBeInTheDocument()
  })

  it('renders failed status', () => {
    render(<AssessmentStatusBadge status="failed" />)
    expect(screen.getByText('failed')).toBeInTheDocument()
  })

  it('renders pending status', () => {
    render(<AssessmentStatusBadge status="pending" />)
    expect(screen.getByText('pending')).toBeInTheDocument()
  })

  it('renders unknown status as neutral', () => {
    render(<AssessmentStatusBadge status="unknown" />)
    expect(screen.getByText('unknown')).toBeInTheDocument()
  })
})
