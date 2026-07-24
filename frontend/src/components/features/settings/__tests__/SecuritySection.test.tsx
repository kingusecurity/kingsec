import { render, screen } from '@testing-library/react'
import { SecuritySection } from '../SecuritySection'

vi.mock('@/hooks/use-settings', () => ({
  useSessions: vi.fn(),
  useDeleteSession: vi.fn(),
  useDeleteAllSessions: vi.fn(),
  useMfaStatus: vi.fn(),
}))

import { useSessions, useMfaStatus } from '@/hooks/use-settings'
import type { SessionInfo } from '@/api/settings'

const mockSessions: SessionInfo[] = [
  {
    id: 's1',
    user_id: 'u1',
    session_type: 'web',
    jti: 'jti1',
    issued_at: '2025-06-15T10:00:00Z',
    expires_at: '2025-06-16T10:00:00Z',
    last_activity: '2025-06-15T10:30:00Z',
    client_ip: '192.168.1.1',
    user_agent: 'Chrome 120',
    device_name: 'Desktop',
    platform: 'Windows',
    browser: 'Chrome 120',
    status: 'active',
  },
  {
    id: 's2',
    user_id: 'u1',
    session_type: 'web',
    jti: 'jti2',
    issued_at: '2025-06-14T08:00:00Z',
    expires_at: '2025-06-15T08:00:00Z',
    last_activity: '2025-06-14T12:00:00Z',
    client_ip: '10.0.0.1',
    user_agent: 'Firefox 110',
    device_name: 'Desktop',
    platform: 'Windows',
    browser: 'Firefox 110',
    status: 'inactive',
  },
]

describe('SecuritySection', () => {
  beforeEach(() => {
    vi.mocked(useSessions).mockReturnValue({
      data: mockSessions,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
    vi.mocked(useMfaStatus).mockReturnValue({
      data: { enabled: false, method: null },
      isLoading: false,
      error: null,
    } as any)
  })

  it('renders account security section', () => {
    render(<SecuritySection />)
    expect(screen.getByText('Account Security')).toBeInTheDocument()
  })

  it('shows MFA status', () => {
    render(<SecuritySection />)
    expect(screen.getByText('Disabled')).toBeInTheDocument()
  })

  it('shows active sessions', () => {
    render(<SecuritySection />)
    expect(screen.getByText('Chrome 120')).toBeInTheDocument()
    expect(screen.getByText('Firefox 110')).toBeInTheDocument()
  })

  it('shows current session badge', () => {
    render(<SecuritySection />)
    expect(screen.getByText('Current')).toBeInTheDocument()
  })

  it('shows empty state when no sessions', () => {
    vi.mocked(useSessions).mockReturnValue({
      data: [],
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
    render(<SecuritySection />)
    expect(screen.getByText('No active sessions')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    vi.mocked(useSessions).mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
      refetch: vi.fn(),
    } as any)
    const { container } = render(<SecuritySection />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })
})
