import { render, screen } from '@testing-library/react'
import { EvidencePanel } from '../EvidencePanel'

const evidence = [
  { label: 'Command Output', content: 'SSH-2.0-OpenSSH_8.9p1' },
  { label: 'Screenshot', content: 'attachment: ssh-banner.png' },
]

describe('EvidencePanel', () => {
  it('renders evidence items', () => {
    render(<EvidencePanel evidence={evidence} />)
    expect(screen.getByText('Evidence (2)')).toBeInTheDocument()
    expect(screen.getByText('Command Output')).toBeInTheDocument()
    expect(screen.getByText('Screenshot')).toBeInTheDocument()
  })

  it('renders empty state when no evidence', () => {
    render(<EvidencePanel evidence={[]} />)
    expect(screen.getByText('No evidence available for this finding.')).toBeInTheDocument()
  })

  it('renders empty state when evidence undefined', () => {
    render(<EvidencePanel />)
    expect(screen.getByText('No evidence recorded')).toBeInTheDocument()
  })

  it('renders loading state', () => {
    const { container } = render(<EvidencePanel loading />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })

  it('renders evidence content in details', () => {
    render(<EvidencePanel evidence={evidence} />)
    expect(screen.getByText('SSH-2.0-OpenSSH_8.9p1')).toBeInTheDocument()
  })
})
