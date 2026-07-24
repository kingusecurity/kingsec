import { render, screen } from '@testing-library/react'
import { ApiSettingsSection } from '../ApiSettingsSection'

vi.mock('@/hooks/use-settings', () => ({
  useHealth: vi.fn(),
  useHealthz: vi.fn(),
  useApiKeys: vi.fn(),
}))

import { useHealth, useHealthz, useApiKeys } from '@/hooks/use-settings'

describe('ApiSettingsSection', () => {
  beforeEach(() => {
    vi.mocked(useHealth).mockReturnValue({
      data: { status: 'ok', version: '1.0.0' },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
    vi.mocked(useHealthz).mockReturnValue({
      data: { status: 'healthy', uptime: 3600, version: '1.0.0' },
      isLoading: false,
      error: null,
    } as any)
    vi.mocked(useApiKeys).mockReturnValue({
      data: [{ id: 'k1', name: 'My Key', key_prefix: 'ks_abc', created_at: '', last_used_at: null }],
      isLoading: false,
      error: null,
    } as any)
  })

  it('renders API status section', () => {
    render(<ApiSettingsSection />)
    expect(screen.getByText('API Status')).toBeInTheDocument()
  })

  it('shows backend version', () => {
    render(<ApiSettingsSection />)
    const versions = screen.getAllByText('1.0.0')
    expect(versions.length).toBeGreaterThanOrEqual(1)
  })

  it('shows API version', () => {
    render(<ApiSettingsSection />)
    expect(screen.getByText('v1')).toBeInTheDocument()
  })

  it('shows connection status', () => {
    render(<ApiSettingsSection />)
    expect(screen.getByText('Connected')).toBeInTheDocument()
  })

  it('shows health status', () => {
    render(<ApiSettingsSection />)
    expect(screen.getByText('healthy')).toBeInTheDocument()
  })

  it('shows API keys', () => {
    render(<ApiSettingsSection />)
    expect(screen.getByText('My Key')).toBeInTheDocument()
  })

  it('renders API keys section', () => {
    render(<ApiSettingsSection />)
    expect(screen.getByText('API Keys')).toBeInTheDocument()
  })

  it('shows no keys message when empty', () => {
    vi.mocked(useApiKeys).mockReturnValue({
      data: [],
      isLoading: false,
      error: null,
    } as any)
    render(<ApiSettingsSection />)
    expect(screen.getByText('No API keys configured')).toBeInTheDocument()
  })
})
