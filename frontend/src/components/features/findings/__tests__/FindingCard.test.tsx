import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { FindingCard } from '../FindingCard'
import type { FindingDetail } from '@/types/api'

const sampleFinding: FindingDetail = {
  finding_id: 'f1',
  title: 'Open SSH',
  severity: 'critical',
  status: 'open',
  evidence_count: 2,
  recommendation_count: 1,
  assessment_id: 'a1',
  target: '10.0.0.1',
  asset: 'web-server-01',
  port: 22,
  protocol: 'tcp',
  cvss_score: 9.5,
  cve: ['CVE-2024-12345'],
  description: 'SSH service exposed with weak configuration.',
}

describe('FindingCard', () => {
  it('renders finding info', () => {
    render(
      <MemoryRouter>
        <FindingCard finding={sampleFinding} assessmentId="a1" />
      </MemoryRouter>,
    )
    expect(screen.getByText('Open SSH')).toBeInTheDocument()
    expect(screen.getByText('critical')).toBeInTheDocument()
    expect(screen.getByText('open')).toBeInTheDocument()
    expect(screen.getByText('web-server-01')).toBeInTheDocument()
  })

  it('renders link to finding detail with assessment context', () => {
    render(
      <MemoryRouter>
        <FindingCard finding={sampleFinding} assessmentId="a1" />
      </MemoryRouter>,
    )
    const link = screen.getByText('View details').closest('a')
    expect(link).toHaveAttribute('href', '/assessments/a1/findings/f1')
  })

  it('renders link to global finding detail when no assessment context', () => {
    render(
      <MemoryRouter>
        <FindingCard finding={sampleFinding} />
      </MemoryRouter>,
    )
    const link = screen.getByText('View details').closest('a')
    expect(link).toHaveAttribute('href', '/findings/f1')
  })

  it('renders loading state', () => {
    const { container } = render(
      <MemoryRouter>
        <FindingCard finding={sampleFinding} loading />
      </MemoryRouter>,
    )
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })

  it('shows CVSS score and CVE count', () => {
    render(
      <MemoryRouter>
        <FindingCard finding={sampleFinding} />
      </MemoryRouter>,
    )
    expect(screen.getByText(/CVSS: 9.5/)).toBeInTheDocument()
    expect(screen.getByText(/CVE: 1/)).toBeInTheDocument()
    expect(screen.getByText(/Port: 22\/tcp/)).toBeInTheDocument()
  })
})
