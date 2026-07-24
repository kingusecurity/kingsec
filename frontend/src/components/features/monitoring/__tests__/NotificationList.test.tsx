import { render, screen } from '@testing-library/react'
import { NotificationList } from '../NotificationList'

vi.mock('@/hooks/use-notifications', () => ({
  useNotifications: vi.fn(),
  useMarkNotificationRead: vi.fn(),
  useDeleteNotification: vi.fn(),
}))

import { useNotifications, useMarkNotificationRead, useDeleteNotification } from '@/hooks/use-notifications'

const mockNotifications = {
  notifications: [
    {
      id: 'n1',
      user_id: 'u1',
      title: 'Critical vulnerability found',
      message: 'SQL injection detected',
      channel: 'in_app',
      status: 'pending',
      priority: 'critical',
      event_type: 'finding',
      retry_count: 0,
      max_retries: 3,
      created_at: '2025-06-15T10:30:00Z',
      updated_at: '2025-06-15T10:30:00Z',
      read_at: null,
      error_message: null,
    },
    {
      id: 'n2',
      user_id: 'u1',
      title: 'Scan completed',
      message: 'Assessment web-server-01 completed',
      channel: 'in_app',
      status: 'sent',
      priority: 'info',
      event_type: 'scan',
      retry_count: 0,
      max_retries: 3,
      created_at: '2025-06-15T09:00:00Z',
      updated_at: '2025-06-15T09:00:00Z',
      read_at: '2025-06-15T10:00:00Z',
      error_message: null,
    },
  ],
  total: 2,
  limit: 20,
  offset: 0,
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
      data: { notifications: [], total: 0, limit: 20, offset: 0 },
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
