import { render, screen } from '@testing-library/react'
import { ReportDownloadCard } from '../ReportDownloadCard'

const report = {
  assessment_id: 'a1',
  verdict: 'critical',
  action_required: true,
  highest_severity: 'critical',
  total_findings: 10,
  severity_counts: [{ severity: 'critical', count: 3 }],
  artifact_media_type: 'application/pdf',
  artifact_filename: 'report-a1.pdf',
  artifact_bytes: 204800,
}

describe('ReportDownloadCard', () => {
  it('renders report filename and size when report provided', () => {
    render(<ReportDownloadCard assessmentId="a1" report={report} />)
    expect(screen.getByText('report-a1.pdf')).toBeInTheDocument()
    expect(screen.getByText('200.0 KB')).toBeInTheDocument()
  })

  it('renders empty state when no report', () => {
    render(<ReportDownloadCard assessmentId="a1" />)
    expect(screen.getByText('No report generated yet.')).toBeInTheDocument()
  })

  it('shows generate button in empty state when onRegenerate provided', () => {
    render(<ReportDownloadCard assessmentId="a1" onRegenerate={vi.fn()} />)
    expect(screen.getByText('Generate Report')).toBeInTheDocument()
  })

  it('shows loading skeleton when loading', () => {
    const { container } = render(<ReportDownloadCard assessmentId="a1" loading />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })
})
