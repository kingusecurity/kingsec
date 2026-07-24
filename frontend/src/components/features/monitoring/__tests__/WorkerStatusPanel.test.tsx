import { render, screen } from '@testing-library/react'
import { WorkerStatusPanel } from '../WorkerStatusPanel'

vi.mock('@/hooks/use-activity', () => ({
  useWorkerStatus: vi.fn(),
}))

import { useWorkerStatus } from '@/hooks/use-activity'

const mockWorkers = {
  workers: [
    {
      id: 'w1',
      name: 'worker-01',
      status: 'healthy',
      task: 'scan-a1',
      cpu: 45,
      memory: 62,
      last_seen: '2025-06-15T10:30:00Z',
    },
    {
      id: 'w2',
      name: 'worker-02',
      status: 'degraded',
      task: null,
      cpu: 88,
      memory: 91,
      last_seen: '2025-06-15T10:28:00Z',
    },
  ],
}

describe('WorkerStatusPanel', () => {
  beforeEach(() => {
    vi.mocked(useWorkerStatus).mockReturnValue({
      data: mockWorkers,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
  })

  it('renders worker list', () => {
    render(<WorkerStatusPanel />)
    expect(screen.getByText('worker-01')).toBeInTheDocument()
    expect(screen.getByText('worker-02')).toBeInTheDocument()
  })

  it('shows worker status badges', () => {
    render(<WorkerStatusPanel />)
    expect(screen.getByText('healthy')).toBeInTheDocument()
    expect(screen.getByText('degraded')).toBeInTheDocument()
  })

  it('shows CPU and memory usage', () => {
    render(<WorkerStatusPanel />)
    expect(screen.getByText('CPU: 45%')).toBeInTheDocument()
    expect(screen.getByText('MEM: 62%')).toBeInTheDocument()
    expect(screen.getByText('CPU: 88%')).toBeInTheDocument()
    expect(screen.getByText('MEM: 91%')).toBeInTheDocument()
  })

  it('shows task info when worker has task', () => {
    render(<WorkerStatusPanel />)
    expect(screen.getByText('Task: scan-a1')).toBeInTheDocument()
  })

  it('shows empty state when no workers', () => {
    vi.mocked(useWorkerStatus).mockReturnValue({
      data: { workers: [] },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)

    render(<WorkerStatusPanel />)
    expect(screen.getByText('No workers')).toBeInTheDocument()
  })

  it('shows error state', () => {
    vi.mocked(useWorkerStatus).mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new Error('Connection failed'),
      refetch: vi.fn(),
    } as any)

    render(<WorkerStatusPanel />)
    expect(screen.getByText('Failed to load worker status')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    vi.mocked(useWorkerStatus).mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
      refetch: vi.fn(),
    } as any)

    const { container } = render(<WorkerStatusPanel />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })

  it('renders panel title', () => {
    render(<WorkerStatusPanel />)
    expect(screen.getByText('Worker Status')).toBeInTheDocument()
  })

  it('shows offline status for offline workers', () => {
    const workers = {
      workers: [{
        id: 'w3',
        name: 'worker-03',
        status: 'offline',
        task: null,
        cpu: 0,
        memory: 0,
        last_seen: '2025-06-15T08:00:00Z',
      }],
    }

    vi.mocked(useWorkerStatus).mockReturnValue({
      data: workers,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)

    render(<WorkerStatusPanel />)
    expect(screen.getByText('offline')).toBeInTheDocument()
  })

  it('shows down status for down workers', () => {
    const workers = {
      workers: [{
        id: 'w4',
        name: 'worker-04',
        status: 'down',
        task: null,
        cpu: 0,
        memory: 0,
        last_seen: '2025-06-15T07:00:00Z',
      }],
    }

    vi.mocked(useWorkerStatus).mockReturnValue({
      data: workers,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)

    render(<WorkerStatusPanel />)
    expect(screen.getByText('down')).toBeInTheDocument()
  })
})
