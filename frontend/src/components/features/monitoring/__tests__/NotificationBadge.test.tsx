import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { NotificationBadge } from '../NotificationBadge'

vi.mock('@/hooks/use-notifications', () => ({
  useNotifications: vi.fn(),
}))

import { useNotifications } from '@/hooks/use-notifications'

describe('NotificationBadge', () => {
  beforeEach(() => {
    vi.mocked(useNotifications).mockReturnValue({
      data: { items: [], total: 0 },
      isLoading: false,
      error: null,
    } as any)
  })

  it('renders bell icon', () => {
    render(<NotificationBadge />)
    expect(screen.getByRole('button')).toBeInTheDocument()
  })

  it('shows unread count when there are notifications', () => {
    vi.mocked(useNotifications).mockReturnValue({
      data: { items: [{ id: '1' }], total: 3 },
      isLoading: false,
      error: null,
    } as any)

    render(<NotificationBadge />)
    expect(screen.getByText('3')).toBeInTheDocument()
  })

  it('does not show badge when count is 0', () => {
    render(<NotificationBadge />)
    expect(screen.queryByText('0')).not.toBeInTheDocument()
  })

  it('shows 99+ for large counts', () => {
    vi.mocked(useNotifications).mockReturnValue({
      data: { items: [], total: 150 },
      isLoading: false,
      error: null,
    } as any)

    render(<NotificationBadge />)
    expect(screen.getByText('99+')).toBeInTheDocument()
  })

  it('calls onClick when clicked', async () => {
    const onClick = vi.fn()
    render(<NotificationBadge onClick={onClick} />)
    await userEvent.click(screen.getByRole('button'))
    expect(onClick).toHaveBeenCalledOnce()
  })

  it('has correct aria-label with unread count', () => {
    render(<NotificationBadge />)
    expect(screen.getByRole('button')).toHaveAttribute('aria-label', 'No unread notifications')
  })

  it('has correct aria-label with unread count > 0', () => {
    vi.mocked(useNotifications).mockReturnValue({
      data: { items: [{ id: '1' }], total: 5 },
      isLoading: false,
      error: null,
    } as any)

    render(<NotificationBadge />)
    expect(screen.getByRole('button')).toHaveAttribute('aria-label', '5 unread notifications')
  })
})
