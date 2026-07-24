import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { UserFilters } from '../UserFilters'

describe('UserFilters', () => {
  const defaultProps = {
    search: '',
    roleFilter: '',
    statusFilter: '',
    onSearchChange: vi.fn(),
    onRoleFilterChange: vi.fn(),
    onStatusFilterChange: vi.fn(),
    onClear: vi.fn(),
    hasFilters: false,
  }

  it('renders search input', () => {
    render(<UserFilters {...defaultProps} />)
    expect(screen.getByLabelText('Search users')).toBeInTheDocument()
  })

  it('renders role filter', () => {
    render(<UserFilters {...defaultProps} />)
    expect(screen.getByLabelText('Filter by role')).toBeInTheDocument()
  })

  it('renders status filter', () => {
    render(<UserFilters {...defaultProps} />)
    expect(screen.getByLabelText('Filter by status')).toBeInTheDocument()
  })

  it('does not show clear button when no filters active', () => {
    render(<UserFilters {...defaultProps} />)
    expect(screen.queryByText('Clear')).not.toBeInTheDocument()
  })

  it('shows clear button when filters are active', () => {
    render(<UserFilters {...defaultProps} hasFilters={true} />)
    expect(screen.getByText('Clear')).toBeInTheDocument()
  })

  it('calls onSearchChange when typing', async () => {
    const onSearchChange = vi.fn()
    render(<UserFilters {...defaultProps} onSearchChange={onSearchChange} />)
    const input = screen.getByLabelText('Search users')
    await userEvent.type(input, 'test')
    expect(onSearchChange).toHaveBeenCalled()
  })

  it('calls onClear when clear button clicked', async () => {
    const onClear = vi.fn()
    render(<UserFilters {...defaultProps} hasFilters={true} onClear={onClear} />)
    await userEvent.click(screen.getByText('Clear'))
    expect(onClear).toHaveBeenCalledOnce()
  })
})
