import { render, screen } from '@testing-library/react'
import { AuditDetailDrawer } from '../AuditDetailDrawer'

vi.mock('@/hooks/use-audit', () => ({
  useAuditEntry: vi.fn(),
}))

import { useAuditEntry } from '@/hooks/use-audit'
import type { AuditEntry } from '@/api/audit'

const mockEntry: AuditEntry = {
  id: 'e1',
  user_id: 'u1',
  username: 'admin',
  action: 'login',
  resource_type: 'session',
  resource_id: null,
  details: 'Successful login',
  severity: 'info',
  ip_address: '192.168.1.1',
  success: true,
  created_at: '2025-06-15T10:30:00Z',
}

describe('AuditDetailDrawer', () => {
  const onClose = vi.fn()

  beforeEach(() => {
    vi.mocked(useAuditEntry).mockReturnValue({
      data: undefined,
      isLoading: false,
      error: null,
    } as any)
  })

  it('renders entry details when open', () => {
    render(<AuditDetailDrawer entry={mockEntry} open={true} onClose={onClose} />)
    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByText('u1')).toBeInTheDocument()
    expect(screen.getByText('login')).toBeInTheDocument()
    expect(screen.getByText('192.168.1.1')).toBeInTheDocument()
  })

  it('shows details text when present', () => {
    render(<AuditDetailDrawer entry={mockEntry} open={true} onClose={onClose} />)
    expect(screen.getByText('Successful login')).toBeInTheDocument()
  })

  it('shows N/A for null resource_id', () => {
    render(<AuditDetailDrawer entry={mockEntry} open={true} onClose={onClose} />)
    const naElements = screen.getAllByText('N/A')
    expect(naElements.length).toBeGreaterThanOrEqual(1)
  })

  it('does not render when closed', () => {
    render(<AuditDetailDrawer entry={mockEntry} open={false} onClose={onClose} />)
    expect(screen.queryByText('admin')).not.toBeInTheDocument()
  })
})
