import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ReportFilters } from '../ReportFilters'

describe('ReportFilters', () => {
  const defaultProps = {
    search: '',
    onSearchChange: vi.fn(),
    sortBy: 'created_at',
    onSortByChange: vi.fn(),
    sortOrder: 'desc',
    onSortOrderChange: vi.fn(),
    onClear: vi.fn(),
    hasFilters: false,
  }

  it('renders search and sort controls', () => {
    render(<ReportFilters {...defaultProps} />)
    expect(screen.getByPlaceholderText('Search reports...')).toBeInTheDocument()
    expect(screen.getByLabelText('Sort by')).toBeInTheDocument()
    expect(screen.getByLabelText('Sort order')).toBeInTheDocument()
  })

  it('shows clear button when filters active', () => {
    render(<ReportFilters {...defaultProps} hasFilters />)
    expect(screen.getByText('Clear')).toBeInTheDocument()
  })

  it('calls onClear when clicked', async () => {
    const onClear = vi.fn()
    render(<ReportFilters {...defaultProps} hasFilters onClear={onClear} />)
    await userEvent.click(screen.getByText('Clear'))
    expect(onClear).toHaveBeenCalledOnce()
  })
})
