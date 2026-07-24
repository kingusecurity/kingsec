import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { NotificationItem } from '../NotificationItem'
import type { Notification } from '@/api/notifications'

const baseNotification: Notification = {
  id: 'n1',
  user_id: 'u1',
  title: 'Critical vulnerability found',
  message: 'SQL injection detected on web-server-01',
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
}

describe('NotificationItem', () => {
  it('renders title and severity badge', () => {
    render(<NotificationItem notification={baseNotification} />)
    expect(screen.getByText('Critical vulnerability found')).toBeInTheDocument()
    expect(screen.getByText('critical')).toBeInTheDocument()
  })

  it('shows message when provided', () => {
    render(<NotificationItem notification={baseNotification} />)
    expect(screen.getByText('SQL injection detected on web-server-01')).toBeInTheDocument()
  })

  it('shows unread styling when read_at is null', () => {
    const { container } = render(<NotificationItem notification={baseNotification} />)
    expect(container.querySelector('.border-accent\\/20')).toBeInTheDocument()
  })

  it('shows read styling when read_at is set', () => {
    const n = { ...baseNotification, read_at: '2025-06-15T11:00:00Z' }
    const { container } = render(<NotificationItem notification={n} />)
    expect(container.querySelector('.border-accent\\/20')).not.toBeInTheDocument()
  })

  it('calls onMarkRead when mark read button clicked', async () => {
    const onMarkRead = vi.fn()
    render(<NotificationItem notification={baseNotification} onMarkRead={onMarkRead} />)
    const btn = screen.getByLabelText('Mark as read')
    await userEvent.click(btn)
    expect(onMarkRead).toHaveBeenCalledWith('n1')
  })

  it('does not show mark read button when notification is already read', () => {
    const n = { ...baseNotification, read_at: '2025-06-15T11:00:00Z' }
    render(<NotificationItem notification={n} onMarkRead={vi.fn()} />)
    expect(screen.queryByLabelText('Mark as read')).not.toBeInTheDocument()
  })

  it('calls onDelete when delete button clicked', async () => {
    const onDelete = vi.fn()
    render(<NotificationItem notification={baseNotification} onDelete={onDelete} />)
    const btn = screen.getByLabelText('Delete notification')
    await userEvent.click(btn)
    expect(onDelete).toHaveBeenCalledWith('n1')
  })

  it('renders in listitem role', () => {
    render(<NotificationItem notification={baseNotification} />)
    expect(screen.getByRole('listitem')).toHaveAttribute('aria-label', 'Critical vulnerability found')
  })
})
