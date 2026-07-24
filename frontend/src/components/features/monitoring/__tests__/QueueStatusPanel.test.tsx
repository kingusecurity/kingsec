import { render, screen } from '@testing-library/react'
import { QueueStatusPanel } from '../QueueStatusPanel'

vi.mock('@/hooks/use-activity', () => ({
  useQueueStatus: vi.fn(),
}))

import { useQueueStatus } from '@/hooks/use-activity'

const mockQueue = {
  pending: 5,
  running: 3,
  completed: 45,
  failed: 2,
}

describe('QueueStatusPanel', () => {
  beforeEach(() => {
    vi.mocked(useQueueStatus).mockReturnValue({
      data: mockQueue,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
  })

  it('renders queue stats', () => {
    render(<QueueStatusPanel />)
    expect(screen.getByText('Total Jobs')).toBeInTheDocument()
    expect(screen.getByText('55')).toBeInTheDocument()
  })

  it('renders all job counts', () => {
    render(<QueueStatusPanel />)
    expect(screen.getAllByText('5')).toHaveLength(1)
    expect(screen.getAllByText('3')).toHaveLength(1)
    expect(screen.getAllByText('45')).toHaveLength(1)
    expect(screen.getAllByText('2')).toHaveLength(1)
  })

  it('shows section labels', () => {
    render(<QueueStatusPanel />)
    expect(screen.getByText('Pending')).toBeInTheDocument()
    expect(screen.getByText('Running')).toBeInTheDocument()
    expect(screen.getByText('Completed')).toBeInTheDocument()
    expect(screen.getByText('Failed')).toBeInTheDocument()
  })

  it('shows error state', () => {
    vi.mocked(useQueueStatus).mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new Error('Queue unavailable'),
      refetch: vi.fn(),
    } as any)

    render(<QueueStatusPanel />)
    expect(screen.getByText('Failed to load queue status')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    vi.mocked(useQueueStatus).mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
      refetch: vi.fn(),
    } as any)

    const { container } = render(<QueueStatusPanel />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })

  it('renders panel title', () => {
    render(<QueueStatusPanel />)
    expect(screen.getByText('Queue Status')).toBeInTheDocument()
  })

  it('handles zero total jobs gracefully', () => {
    vi.mocked(useQueueStatus).mockReturnValue({
      data: { pending: 0, running: 0, completed: 0, failed: 0 },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)

    render(<QueueStatusPanel />)
    expect(screen.getAllByText('0').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('Total Jobs')).toBeInTheDocument()
  })
})
