import { render, screen } from '@testing-library/react'
import { FindingDetailCard } from '../FindingDetailCard'

const finding = {
  finding_id: 'f1',
  title: 'SQL Injection',
  severity: 'critical',
  status: 'open',
  evidence_count: 5,
  recommendation_count: 2,
}

describe('FindingDetailCard', () => {
  it('renders finding title and badges', () => {
    render(<FindingDetailCard finding={finding} />)
    expect(screen.getByText('SQL Injection')).toBeInTheDocument()
    expect(screen.getByText('critical')).toBeInTheDocument()
    expect(screen.getByText('open')).toBeInTheDocument()
  })

  it('renders evidence and recommendation counts', () => {
    render(<FindingDetailCard finding={finding} />)
    expect(screen.getByText('5')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
  })

  it('shows target when provided', () => {
    render(<FindingDetailCard finding={{ ...finding, target: '10.0.0.5' }} />)
    expect(screen.getByText('Asset: 10.0.0.5')).toBeInTheDocument()
  })

  it('shows loading skeleton when loading', () => {
    const { container } = render(<FindingDetailCard finding={finding} loading />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })
})
