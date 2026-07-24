import { render, screen } from '@testing-library/react'
import { FindingsSummaryTable } from '../assessment/FindingsSummaryTable'

const sampleFindings = [
  { finding_id: '1', title: 'Open SSH Port', severity: 'critical', status: 'open', evidence_count: 3, recommendation_count: 2 },
  { finding_id: '2', title: 'Weak Password Policy', severity: 'high', status: 'confirmed', evidence_count: 1, recommendation_count: 1 },
]

describe('FindingsSummaryTable', () => {
  it('renders findings with severity badges', () => {
    render(<FindingsSummaryTable findings={sampleFindings} />)
    expect(screen.getByText('Open SSH Port')).toBeInTheDocument()
    expect(screen.getByText('Weak Password Policy')).toBeInTheDocument()
    expect(screen.getByText('critical')).toBeInTheDocument()
    expect(screen.getByText('high')).toBeInTheDocument()
  })

  it('renders empty state when no findings', () => {
    render(<FindingsSummaryTable findings={[]} />)
    expect(screen.getByText('No findings found.')).toBeInTheDocument()
  })

  it('shows evidence and recommendation counts', () => {
    render(<FindingsSummaryTable findings={sampleFindings} />)
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getAllByText('1')).toHaveLength(2)
  })
})
