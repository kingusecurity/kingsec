import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { NotificationItem } from '../NotificationItem'
import type { Notification } from '@/api/notifications'

const baseNotification: Notification = {
  id: 'n1',
  title: 'Critical vulnerability found',
  message: 'SQL injection detected on web-server-01',
  type: 'finding',
  severity: 'critical',
  read: false,
  created_at: '2025-06-15T10:30:00Z',
  assessment_id: 'a1',
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

  it('does not show message when not provided', () => {
    const n = { ...baseNotification, message: undefined }
    render(<NotificationItem notification={n} />)
    expect(screen.queryByText('SQL injection detected on web-server-01')).not.toBeInTheDocument()
  })

  it('shows unread styling when notification is unread', () => {
    const { container } = render(<NotificationItem notification={baseNotification} />)
    expect(container.querySelector('.border-accent\\/20')).toBeInTheDocument()
  })

  it('shows read styling when notification is read', () => {
    const n = { ...baseNotification, read: true }
    const { container } = render(<NotificationItem notification={n} />)
    expect(container.querySelector('.border-accent\\/20')).not.toBeInTheDocument()
  })

  it('shows view assessment link when assessment_id is present', () => {
    render(<NotificationItem notification={baseNotification} />)
    expect(screen.getByText('View assessment')).toBeInTheDocument()
  })

  it('does not show view assessment link when no assessment_id', () => {
    const n = { ...baseNotification, assessment_id: undefined }
    render(<NotificationItem notification={n} />)
    expect(screen.queryByText('View assessment')).not.toBeInTheDocument()
  })

  it('calls onMarkRead when mark read button clicked', async () => {
    const onMarkRead = vi.fn()
    render(<NotificationItem notification={baseNotification} onMarkRead={onMarkRead} />)
    const btn = screen.getByLabelText('Mark as read')
    await userEvent.click(btn)
    expect(onMarkRead).toHaveBeenCalledWith('n1')
  })

  it('does not show mark read button when notification is already read', () => {
    const n = { ...baseNotification, read: true }
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

  it('calls onNavigate when view assessment clicked', async () => {
    const onNavigate = vi.fn()
    render(<NotificationItem notification={baseNotification} onNavigate={onNavigate} />)
    await userEvent.click(screen.getByText('View assessment'))
    expect(onNavigate).toHaveBeenCalledWith('a1')
  })

  it('renders in listitem role', () => {
    render(<NotificationItem notification={baseNotification} />)
    expect(screen.getByRole('listitem')).toHaveAttribute('aria-label', 'Critical vulnerability found')
  })
})
