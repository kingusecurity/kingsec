import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { FindingsSummaryTable } from '../FindingsSummaryTable'
import type { FindingResponse } from '@/types/api'

const mockFindings: FindingResponse[] = [
  { finding_id: 'f1', title: 'SQL Injection', severity: 'critical', status: 'open', evidence_count: 3, recommendation_count: 2 },
  { finding_id: 'f2', title: 'Weak Password', severity: 'high', status: 'confirmed', evidence_count: 1, recommendation_count: 1 },
]

describe('FindingsSummaryTable', () => {
  it('renders findings', () => {
    render(<FindingsSummaryTable findings={mockFindings} />)
    expect(screen.getByText('SQL Injection')).toBeInTheDocument()
    expect(screen.getByText('Weak Password')).toBeInTheDocument()
  })

  it('renders severity badges', () => {
    render(<FindingsSummaryTable findings={mockFindings} />)
    expect(screen.getByText('critical')).toBeInTheDocument()
    expect(screen.getByText('high')).toBeInTheDocument()
  })

  it('renders column headers', () => {
    render(<FindingsSummaryTable findings={mockFindings} />)
    expect(screen.getByText('Title')).toBeInTheDocument()
    expect(screen.getByText('Affected Asset')).toBeInTheDocument()
    expect(screen.getByText('Severity')).toBeInTheDocument()
    expect(screen.getByText('Status')).toBeInTheDocument()
    expect(screen.getByText('Evidence')).toBeInTheDocument()
    expect(screen.getByText('Recommendations')).toBeInTheDocument()
  })

  it('shows empty message when no findings', () => {
    render(<FindingsSummaryTable findings={[]} />)
    expect(screen.getByText('No findings found.')).toBeInTheDocument()
  })

  it('links a finding to its detail page when assessment context is available', () => {
    render(
      <MemoryRouter>
        <FindingsSummaryTable findings={mockFindings} assessmentId="asmt/one" />
      </MemoryRouter>,
    )
    expect(screen.getByRole('link', { name: 'SQL Injection' })).toHaveAttribute(
      'href',
      '/assessments/asmt%2Fone/findings/f1',
    )
  })

  it('shows the concrete affected asset and an honest fallback when it is absent', () => {
    render(
      <FindingsSummaryTable
        findings={[
          { ...mockFindings[0]!, affected_asset: '192.0.2.10' },
          mockFindings[1]!,
        ]}
      />,
    )
    expect(screen.getByText('192.0.2.10')).toBeInTheDocument()
    expect(screen.getByText('—')).toBeInTheDocument()
  })
})
