import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { GrantCoverageNotice } from '../GrantCoverageNotice'
import type { CheckGrantCoverageResponse } from '@/api/grants'

function renderNotice(result: CheckGrantCoverageResponse) {
  return render(
    <MemoryRouter>
      <GrantCoverageNotice result={result} />
    </MemoryRouter>,
  )
}

const base: CheckGrantCoverageResponse = {
  enforced: true,
  target_type: 'ip_address',
  target_value: '10.0.0.5',
  profile_id: 'quick-scan',
  required_tiers: [{ tier: 'host_any_port', covered: false, grant_id: null }],
  fully_covered: false,
}

describe('GrantCoverageNotice', () => {
  it('renders nothing when fully covered', () => {
    const { container } = renderNotice({ ...base, fully_covered: true, required_tiers: [{ tier: 'host_any_port', covered: true, grant_id: 'agrt-1' }] })
    expect(container).toBeEmptyDOMElement()
  })

  it('renders nothing when enforcement is off', () => {
    const { container } = renderNotice({ ...base, enforced: false, fully_covered: true })
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the no-grant-at-all message when nothing covers the target', () => {
    renderNotice(base)
    expect(screen.getByText('No authorization grant covers this target')).toBeInTheDocument()
    expect(screen.queryByText('A grant exists, but not at the tier this scan needs')).not.toBeInTheDocument()
  })

  it('shows the distinct Blocking-1 message when a grant covers a different tier', () => {
    renderNotice({
      ...base,
      required_tiers: [
        { tier: 'host_port_path', covered: true, grant_id: 'agrt-url' },
        { tier: 'host_any_port', covered: false, grant_id: null },
      ],
    })
    expect(screen.getByText('A grant exists, but not at the tier this scan needs')).toBeInTheDocument()
    expect(screen.queryByText('No authorization grant covers this target')).not.toBeInTheDocument()
    expect(screen.getByText(/the web application at that URL only/)).toBeInTheDocument()
  })

  it('always offers a link to create a covering grant', () => {
    renderNotice(base)
    expect(screen.getByRole('link', { name: /Create a covering grant/ })).toHaveAttribute('href', '/grants')
  })
})
