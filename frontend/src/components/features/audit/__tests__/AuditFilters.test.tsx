import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AuditFilters } from '../AuditFilters'

describe('AuditFilters', () => {
  const defaultProps = {
    search: '',
    action: '',
    resourceType: '',
    severity: '',
    success: '',
    onSearchChange: vi.fn(),
    onActionChange: vi.fn(),
    onResourceTypeChange: vi.fn(),
    onSeverityChange: vi.fn(),
    onSuccessChange: vi.fn(),
    onClear: vi.fn(),
    hasFilters: false,
  }

  it('renders search input', () => {
    render(<AuditFilters {...defaultProps} />)
    expect(screen.getByLabelText('Search audit log')).toBeInTheDocument()
  })

  it('renders all filter selects', () => {
    render(<AuditFilters {...defaultProps} />)
    expect(screen.getByLabelText('Filter by action')).toBeInTheDocument()
    expect(screen.getByLabelText('Filter by resource type')).toBeInTheDocument()
    expect(screen.getByLabelText('Filter by severity')).toBeInTheDocument()
    expect(screen.getByLabelText('Filter by result')).toBeInTheDocument()
  })

  it('does not show clear button when no filters active', () => {
    render(<AuditFilters {...defaultProps} />)
    expect(screen.queryByText('Clear')).not.toBeInTheDocument()
  })

  it('shows clear button when filters are active', () => {
    render(<AuditFilters {...defaultProps} hasFilters={true} />)
    expect(screen.getByText('Clear')).toBeInTheDocument()
  })

  it('calls onSearchChange when typing', async () => {
    const onSearchChange = vi.fn()
    render(<AuditFilters {...defaultProps} onSearchChange={onSearchChange} />)
    const input = screen.getByLabelText('Search audit log')
    await userEvent.type(input, 'test')
    expect(onSearchChange).toHaveBeenCalled()
  })

  it('calls onClear when clear button clicked', async () => {
    const onClear = vi.fn()
    render(<AuditFilters {...defaultProps} hasFilters={true} onClear={onClear} />)
    await userEvent.click(screen.getByText('Clear'))
    expect(onClear).toHaveBeenCalledOnce()
  })
})
