import { render, screen } from '@testing-library/react'
import { NotificationList } from '../NotificationList'

vi.mock('@/hooks/use-notifications', () => ({
  useNotifications: vi.fn(),
  useMarkNotificationRead: vi.fn(),
  useDeleteNotification: vi.fn(),
}))

import { useNotifications, useMarkNotificationRead, useDeleteNotification } from '@/hooks/use-notifications'

const mockNotifications = {
  items: [
    {
      id: 'n1',
      title: 'Critical vulnerability found',
      message: 'SQL injection detected',
      type: 'finding',
      severity: 'critical',
      read: false,
      created_at: '2025-06-15T10:30:00Z',
      assessment_id: 'a1',
    },
    {
      id: 'n2',
      title: 'Scan completed',
      message: 'Assessment web-server-01 completed',
      type: 'scan',
      severity: 'info',
      read: true,
      created_at: '2025-06-15T09:00:00Z',
    },
  ],
  total: 2,
}

describe('NotificationList', () => {
  beforeEach(() => {
    vi.mocked(useNotifications).mockReturnValue({
      data: mockNotifications,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
    vi.mocked(useMarkNotificationRead).mockReturnValue({ mutate: vi.fn() } as any)
    vi.mocked(useDeleteNotification).mockReturnValue({ mutate: vi.fn() } as any)
  })

  it('renders notifications', () => {
    render(<NotificationList />)
    expect(screen.getByText('Critical vulnerability found')).toBeInTheDocument()
    expect(screen.getByText('Scan completed')).toBeInTheDocument()
    expect(screen.getByText('2 total')).toBeInTheDocument()
  })

  it('shows empty state when no notifications', () => {
    vi.mocked(useNotifications).mockReturnValue({
      data: { items: [], total: 0 },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)

    render(<NotificationList />)
    expect(screen.getByText('No notifications')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    vi.mocked(useNotifications).mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
      refetch: vi.fn(),
    } as any)

    render(<NotificationList />)
    expect(screen.getByRole('status')).toBeInTheDocument()
  })

  it('shows error state', () => {
    vi.mocked(useNotifications).mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new Error('Network error'),
      refetch: vi.fn(),
    } as any)

    render(<NotificationList />)
    expect(screen.getByText('Failed to load notifications')).toBeInTheDocument()
  })

  it('renders notifications in a list', () => {
    render(<NotificationList />)
    expect(screen.getByRole('list')).toHaveAttribute('aria-label', 'Notifications')
  })
})
