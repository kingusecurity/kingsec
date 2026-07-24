import { render, screen } from '@testing-library/react'
import { ReportMetadataCard } from '../ReportMetadataCard'

const report = {
  assessment_id: 'a1',
  verdict: 'moderate',
  action_required: true,
  highest_severity: 'high',
  total_findings: 10,
  severity_counts: [
    { severity: 'critical', count: 2 },
    { severity: 'high', count: 3 },
    { severity: 'medium', count: 4 },
    { severity: 'low', count: 1 },
  ],
  artifact_media_type: 'application/pdf',
  artifact_filename: 'report-a1.pdf',
  artifact_bytes: 102400,
}

describe('ReportMetadataCard', () => {
  it('renders target and created date', () => {
    render(<ReportMetadataCard target="10.0.0.1" createdAt="2024-01-01T00:00:00Z" />)
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
  })

  it('renders report verdict and severity distribution', () => {
    render(<ReportMetadataCard target="10.0.0.1" createdAt="2024-01-01T00:00:00Z" report={report} />)
    expect(screen.getByText('moderate')).toBeInTheDocument()
    expect(screen.getAllByText('high').length).toBeGreaterThanOrEqual(1)
  })

  it('shows action required indicator', () => {
    render(<ReportMetadataCard target="10.0.0.1" createdAt="2024-01-01T00:00:00Z" report={report} />)
    expect(screen.getByText('Yes')).toBeInTheDocument()
  })

  it('shows loading skeleton when loading', () => {
    const { container } = render(<ReportMetadataCard target="10.0.0.1" createdAt="2024-01-01T00:00:00Z" loading />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })
})
