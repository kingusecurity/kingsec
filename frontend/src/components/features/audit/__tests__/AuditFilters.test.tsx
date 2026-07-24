import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AuditFilters } from '../AuditFilters'

describe('AuditFilters', () => {
  const defaultProps = {
    action: '',
    resourceType: '',
    success: '',
    onActionChange: vi.fn(),
    onResourceTypeChange: vi.fn(),
    onSuccessChange: vi.fn(),
    onClear: vi.fn(),
    hasFilters: false,
  }

  it('renders all filter selects', () => {
    render(<AuditFilters {...defaultProps} />)
    expect(screen.getByLabelText('Filter by action')).toBeInTheDocument()
    expect(screen.getByLabelText('Filter by resource type')).toBeInTheDocument()
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

  it('calls onClear when clear button clicked', async () => {
    const onClear = vi.fn()
    render(<AuditFilters {...defaultProps} hasFilters={true} onClear={onClear} />)
    await userEvent.click(screen.getByText('Clear'))
    expect(onClear).toHaveBeenCalledOnce()
  })
})
