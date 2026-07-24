import { render, screen } from '@testing-library/react'
import { ReportSummary } from '../ReportSummary'

const severityCounts = [
  { severity: 'critical', count: 2 },
  { severity: 'high', count: 5 },
  { severity: 'medium', count: 3 },
]

describe('ReportSummary', () => {
  it('renders severity breakdown', () => {
    render(<ReportSummary severityCounts={severityCounts} totalFindings={10} highestSeverity="critical" />)
    expect(screen.getByText('Severity Breakdown')).toBeInTheDocument()
    expect(screen.getByText('Highest Severity')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
  })

  it('renders executive summary', () => {
    render(<ReportSummary executiveSummary="Critical vulnerabilities found in the network." />)
    expect(screen.getByText('Critical vulnerabilities found in the network.')).toBeInTheDocument()
  })

  it('renders recommendations', () => {
    render(<ReportSummary recommendations={['Patch all critical CVEs', 'Update firewall rules']} />)
    expect(screen.getByText('Recommendations')).toBeInTheDocument()
    expect(screen.getByText('Patch all critical CVEs')).toBeInTheDocument()
    expect(screen.getByText('Update firewall rules')).toBeInTheDocument()
  })

  it('renders loading state', () => {
    const { container } = render(<ReportSummary loading />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })

  it('renders nothing when no data provided', () => {
    const { container } = render(<ReportSummary />)
    expect(container.textContent).toBeFalsy()
  })
})
