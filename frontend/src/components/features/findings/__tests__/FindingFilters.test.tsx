import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FindingFilters } from '../FindingFilters'

describe('FindingFilters', () => {
  const defaultProps = {
    search: '',
    onSearchChange: vi.fn(),
    severityFilter: '',
    onSeverityFilterChange: vi.fn(),
    statusFilter: '',
    onStatusFilterChange: vi.fn(),
    onClear: vi.fn(),
    hasFilters: false,
  }

  it('renders search input and filter selects', () => {
    render(<FindingFilters {...defaultProps} />)
    expect(screen.getByPlaceholderText('Search findings...')).toBeInTheDocument()
    expect(screen.getByLabelText('Filter by severity')).toBeInTheDocument()
    expect(screen.getByLabelText('Filter by status')).toBeInTheDocument()
  })

  it('calls onSearchChange when typing', async () => {
    const onSearchChange = vi.fn()
    render(<FindingFilters {...defaultProps} onSearchChange={onSearchChange} />)
    const input = screen.getByPlaceholderText('Search findings...')
    await userEvent.type(input, 'SQL')
    expect(onSearchChange).toHaveBeenCalledTimes(3)
  })

  it('shows clear button when filters are active', () => {
    render(<FindingFilters {...defaultProps} hasFilters />)
    expect(screen.getByText('Clear')).toBeInTheDocument()
  })

  it('calls onClear when clear button clicked', async () => {
    const onClear = vi.fn()
    render(<FindingFilters {...defaultProps} hasFilters onClear={onClear} />)
    await userEvent.click(screen.getByText('Clear'))
    expect(onClear).toHaveBeenCalledOnce()
  })
})
