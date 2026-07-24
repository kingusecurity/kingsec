import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AuditTable } from '../AuditTable'
import type { AuditEntry } from '@/api/audit'

const mockEntries: AuditEntry[] = [
  {
    action: 'login',
    resource_type: 'session',
    resource_id: '',
    success: true,
    reason: '',
    timestamp: '2025-06-15T10:30:00Z',
    user_id: 'u1',
    username: 'admin',
    role: 'admin',
    ip_address: '192.168.1.1',
    correlation_id: '',
  },
  {
    action: 'create',
    resource_type: 'assessment',
    resource_id: 'a1',
    success: true,
    reason: 'Created assessment for web-server-01',
    timestamp: '2025-06-15T09:00:00Z',
    user_id: 'u2',
    username: 'analyst1',
    role: 'analyst',
    ip_address: '10.0.0.1',
    correlation_id: '',
  },
]

describe('AuditTable', () => {
  const defaultProps = {
    entries: mockEntries,
    isLoading: false,
    error: null,
    onRetry: vi.fn(),
    currentPage: 1,
    totalPages: 1,
    onPageChange: vi.fn(),
    onSelect: vi.fn(),
  }

  it('renders audit entries', () => {
    render(<AuditTable {...defaultProps} />)
    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByText('analyst1')).toBeInTheDocument()
  })

  it('renders action codes', () => {
    render(<AuditTable {...defaultProps} />)
    expect(screen.getByText('login')).toBeInTheDocument()
    expect(screen.getByText('create')).toBeInTheDocument()
  })

  it('renders resource types', () => {
    render(<AuditTable {...defaultProps} />)
    expect(screen.getByText('session')).toBeInTheDocument()
    expect(screen.getByText('assessment')).toBeInTheDocument()
  })

  it('shows success badges', () => {
    render(<AuditTable {...defaultProps} />)
    const successBadges = screen.getAllByText('Success')
    expect(successBadges.length).toBe(2)
  })

  it('calls onSelect when row clicked', async () => {
    const onSelect = vi.fn()
    render(<AuditTable {...defaultProps} onSelect={onSelect} />)
    const rows = screen.getAllByRole('row')
    if (rows[1]) await userEvent.click(rows[1])
    expect(onSelect).toHaveBeenCalledWith(mockEntries[0])
  })

  it('shows loading state', () => {
    const { container } = render(<AuditTable {...defaultProps} isLoading={true} entries={undefined} />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })

  it('shows error state', () => {
    render(<AuditTable {...defaultProps} error={new Error('API error')} entries={undefined} />)
    expect(screen.getByText('Failed to load audit log')).toBeInTheDocument()
  })

  it('shows empty state', () => {
    render(<AuditTable {...defaultProps} entries={[]} />)
    expect(screen.getByText('No audit entries')).toBeInTheDocument()
  })

  it('renders column headers', () => {
    render(<AuditTable {...defaultProps} />)
    expect(screen.getByText('User')).toBeInTheDocument()
    expect(screen.getByText('Action')).toBeInTheDocument()
    expect(screen.getByText('Resource')).toBeInTheDocument()
    expect(screen.getByText('Status')).toBeInTheDocument()
    expect(screen.getByText('Timestamp')).toBeInTheDocument()
  })

  it('shows pagination when multiple pages', () => {
    render(<AuditTable {...defaultProps} totalPages={3} currentPage={1} />)
    expect(screen.getByLabelText('Pagination')).toBeInTheDocument()
  })

  it('hides pagination when single page', () => {
    render(<AuditTable {...defaultProps} totalPages={1} />)
    expect(screen.queryByLabelText('Pagination')).not.toBeInTheDocument()
  })
})
