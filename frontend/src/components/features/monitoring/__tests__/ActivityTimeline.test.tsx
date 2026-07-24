import { render, screen } from '@testing-library/react'
import { ActivityTimeline } from '../ActivityTimeline'

vi.mock('@/hooks/use-activity', () => ({
  useLiveActivity: vi.fn(),
}))

import { useLiveActivity } from '@/hooks/use-activity'

const mockActivity = {
  activity: [
    {
      id: 'e1',
      type: 'scan_started',
      message: 'Scan started on web-server-01',
      severity: 'info',
      created_at: '2025-06-15T10:30:00Z',
      user: 'admin',
      assessment_id: 'a1',
    },
    {
      id: 'e2',
      type: 'finding_created',
      message: 'Critical finding: SQL Injection',
      severity: 'critical',
      created_at: '2025-06-15T10:25:00Z',
    },
  ],
}

describe('ActivityTimeline', () => {
  beforeEach(() => {
    vi.mocked(useLiveActivity).mockReturnValue({
      data: mockActivity,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
  })

  it('renders activity events', () => {
    render(<ActivityTimeline />)
    expect(screen.getByText('Scan started on web-server-01')).toBeInTheDocument()
    expect(screen.getByText('Critical finding: SQL Injection')).toBeInTheDocument()
  })

  it('shows user attribution', () => {
    render(<ActivityTimeline />)
    expect(screen.getByText('by admin')).toBeInTheDocument()
  })

  it('shows empty state when no activity', () => {
    vi.mocked(useLiveActivity).mockReturnValue({
      data: { activity: [] },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)

    render(<ActivityTimeline />)
    expect(screen.getByText('No recent activity')).toBeInTheDocument()
  })

  it('shows error state', () => {
    vi.mocked(useLiveActivity).mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new Error('Failed to fetch'),
      refetch: vi.fn(),
    } as any)

    render(<ActivityTimeline />)
    expect(screen.getByText('Failed to load activity')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    vi.mocked(useLiveActivity).mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
      refetch: vi.fn(),
    } as any)

    const { container } = render(<ActivityTimeline />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })

  it('shows Live Activity title by default', () => {
    render(<ActivityTimeline />)
    expect(screen.getByText('Live Activity')).toBeInTheDocument()
  })

  it('hides title when showTitle is false', () => {
    render(<ActivityTimeline showTitle={false} />)
    expect(screen.queryByText('Live Activity')).not.toBeInTheDocument()
  })
})
