import { render, screen } from '@testing-library/react'
import { AuditDetailDrawer } from '../AuditDetailDrawer'
import type { AuditEntry } from '@/api/audit'

const mockEntry: AuditEntry = {
  action: 'login',
  resource_type: 'session',
  resource_id: null,
  success: true,
  reason: 'Successful login',
  timestamp: '2025-06-15T10:30:00Z',
  user_id: 'u1',
  username: 'admin',
  role: 'admin',
  ip_address: '192.168.1.1',
  correlation_id: null,
}

describe('AuditDetailDrawer', () => {
  const onClose = vi.fn()

  it('renders entry details when open', () => {
    render(<AuditDetailDrawer entry={mockEntry} open={true} onClose={onClose} />)
    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByText('u1')).toBeInTheDocument()
    expect(screen.getByText('login')).toBeInTheDocument()
    expect(screen.getByText('192.168.1.1')).toBeInTheDocument()
  })

  it('shows reason text when present', () => {
    render(<AuditDetailDrawer entry={mockEntry} open={true} onClose={onClose} />)
    expect(screen.getByText('Successful login')).toBeInTheDocument()
  })

  it('shows N/A for empty resource_id', () => {
    render(<AuditDetailDrawer entry={mockEntry} open={true} onClose={onClose} />)
    const naElements = screen.getAllByText('N/A')
    expect(naElements.length).toBeGreaterThanOrEqual(1)
  })

  it('does not render when closed', () => {
    render(<AuditDetailDrawer entry={mockEntry} open={false} onClose={onClose} />)
    expect(screen.queryByText('admin')).not.toBeInTheDocument()
  })
})
