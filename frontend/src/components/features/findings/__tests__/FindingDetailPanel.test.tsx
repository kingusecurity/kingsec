import { render, screen } from '@testing-library/react'
import { FindingDetailPanel } from '../FindingDetailPanel'
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
  description: 'SSH service is exposed with weak configuration.',
  remediation: 'Disable SSH or restrict access to trusted IPs.',
  scanner: 'nmap',
  asset: 'web-server-01',
  port: 22,
  protocol: 'tcp',
  cvss_score: 9.5,
  cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
}

describe('FindingDetailPanel', () => {
  it('renders finding details', () => {
    render(<FindingDetailPanel finding={sampleFinding} />)
    expect(screen.getByText('Open SSH')).toBeInTheDocument()
    expect(screen.getByText('critical')).toBeInTheDocument()
    expect(screen.getByText('open')).toBeInTheDocument()
    expect(screen.getByText('SSH service is exposed with weak configuration.')).toBeInTheDocument()
    expect(screen.getByText('Disable SSH or restrict access to trusted IPs.')).toBeInTheDocument()
    expect(screen.getByText('nmap')).toBeInTheDocument()
    expect(screen.getByText('web-server-01')).toBeInTheDocument()
    expect(screen.getByText('22/tcp')).toBeInTheDocument()
  })

  it('renders CVSS score and vector', () => {
    render(<FindingDetailPanel finding={sampleFinding} />)
    expect(screen.getByText('9.5')).toBeInTheDocument()
    expect(screen.getByText('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBeInTheDocument()
  })

  it('prefers the concrete affected asset over the assessment target', () => {
    render(
      <FindingDetailPanel
        finding={{ ...sampleFinding, target: '10.0.0.0/24', affected_asset: '10.0.0.9' }}
      />,
    )
    expect(screen.getByText('Asset: 10.0.0.9')).toBeInTheDocument()
    expect(screen.queryByText('Asset: 10.0.0.0/24')).not.toBeInTheDocument()
  })

  it('renders loading state', () => {
    const { container } = render(<FindingDetailPanel loading />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })

  it('returns null when no finding', () => {
    const { container } = render(<FindingDetailPanel />)
    expect(container.textContent).toBeFalsy()
  })
})
