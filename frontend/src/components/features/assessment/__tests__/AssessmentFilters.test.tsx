import { fireEvent, render, screen } from '@testing-library/react'
import type { ComponentProps } from 'react'
import { AssessmentFilters } from '../AssessmentFilters'

function renderFilters(overrides: Partial<ComponentProps<typeof AssessmentFilters>> = {}) {
  const props: ComponentProps<typeof AssessmentFilters> = {
    search: '',
    onSearchChange: vi.fn(),
    statusFilter: '',
    onStatusFilterChange: vi.fn(),
    sortBy: 'created_at',
    onSortByChange: vi.fn(),
    sortOrder: 'desc',
    onSortOrderChange: vi.fn(),
    onClear: vi.fn(),
    hasFilters: false,
    ...overrides,
  }

  return { ...render(<AssessmentFilters {...props} />), props }
}

describe('AssessmentFilters', () => {
  it('offers only real assessment lifecycle statuses', () => {
    const onStatusFilterChange = vi.fn()
    renderFilters({ onStatusFilterChange })

    expect(screen.getByRole('option', { name: 'Authorized' })).toHaveValue('authorized')
    expect(screen.getByRole('option', { name: 'Completed with gaps' })).toHaveValue('completed_with_gaps')
    expect(screen.queryByRole('option', { name: 'Pending' })).not.toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Filter by status'), {
      target: { value: 'completed_with_gaps' },
    })
    expect(onStatusFilterChange).toHaveBeenCalledWith('completed_with_gaps')
  })

  it('uses meaningful direction labels for the active sort field', () => {
    const { rerender, props } = renderFilters({ sortBy: 'findings_count' })

    expect(screen.getByRole('option', { name: 'Most first' })).toHaveValue('desc')
    expect(screen.getByRole('option', { name: 'Fewest first' })).toHaveValue('asc')

    rerender(<AssessmentFilters {...props} sortBy="target" />)
    expect(screen.getByRole('option', { name: 'Z to A' })).toHaveValue('desc')
    expect(screen.getByRole('option', { name: 'A to Z' })).toHaveValue('asc')
  })

  it('caps search text at the API boundary limit', () => {
    renderFilters()

    expect(screen.getByLabelText('Search assessments')).toHaveAttribute('maxlength', '256')
  })
})
