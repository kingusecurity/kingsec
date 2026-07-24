import { render, screen } from '@testing-library/react'
import { FindingsTable } from '../FindingsTable'

const sampleFindings = [
  { finding_id: '1', title: 'Open SSH', severity: 'critical', status: 'open', evidence_count: 2, recommendation_count: 1 },
  { finding_id: '2', title: 'Weak Password', severity: 'high', status: 'confirmed', evidence_count: 1, recommendation_count: 3 },
]

describe('FindingsTable', () => {
  it('renders findings with severity and status badges', () => {
    render(<FindingsTable findings={sampleFindings} />)
    expect(screen.getByText('Open SSH')).toBeInTheDocument()
    expect(screen.getByText('Weak Password')).toBeInTheDocument()
    expect(screen.getByText('critical')).toBeInTheDocument()
    expect(screen.getByText('high')).toBeInTheDocument()
    expect(screen.getByText('open')).toBeInTheDocument()
    expect(screen.getByText('confirmed')).toBeInTheDocument()
  })

  it('renders empty state when no findings', () => {
    render(<FindingsTable findings={[]} />)
    expect(screen.getByText('No findings found.')).toBeInTheDocument()
  })

  it('shows evidence and recommendation counts', () => {
    render(<FindingsTable findings={sampleFindings} />)
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
  })
})
