import { render, screen } from '@testing-library/react'
import { AssessmentSeverityBadge } from '../AssessmentSeverityBadge'

describe('AssessmentSeverityBadge', () => {
  it('renders critical severity', () => {
    render(<AssessmentSeverityBadge severity="critical" />)
    expect(screen.getByText('critical')).toBeInTheDocument()
  })

  it('renders high severity', () => {
    render(<AssessmentSeverityBadge severity="high" />)
    expect(screen.getByText('high')).toBeInTheDocument()
  })

  it('renders medium severity', () => {
    render(<AssessmentSeverityBadge severity="medium" />)
    expect(screen.getByText('medium')).toBeInTheDocument()
  })

  it('renders low severity', () => {
    render(<AssessmentSeverityBadge severity="low" />)
    expect(screen.getByText('low')).toBeInTheDocument()
  })

  it('renders info severity', () => {
    render(<AssessmentSeverityBadge severity="info" />)
    expect(screen.getByText('info')).toBeInTheDocument()
  })

  it('renders informational severity as info variant', () => {
    render(<AssessmentSeverityBadge severity="informational" />)
    expect(screen.getByText('informational')).toBeInTheDocument()
  })
})
