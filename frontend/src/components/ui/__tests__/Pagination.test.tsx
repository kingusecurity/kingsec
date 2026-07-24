import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Pagination } from '../Pagination'

describe('Pagination', () => {
  it('renders page info', () => {
    render(<Pagination currentPage={1} totalPages={5} onPageChange={vi.fn()} />)
    expect(screen.getByText('1')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()
  })

  it('disables previous on first page', () => {
    render(<Pagination currentPage={1} totalPages={5} onPageChange={vi.fn()} />)
    expect(screen.getByLabelText('Previous page')).toBeDisabled()
  })

  it('disables next on last page', () => {
    render(<Pagination currentPage={5} totalPages={5} onPageChange={vi.fn()} />)
    expect(screen.getByLabelText('Next page')).toBeDisabled()
  })

  it('calls onPageChange when next clicked', async () => {
    const onPageChange = vi.fn()
    render(<Pagination currentPage={1} totalPages={5} onPageChange={onPageChange} />)
    await userEvent.click(screen.getByLabelText('Next page'))
    expect(onPageChange).toHaveBeenCalledWith(2)
  })

  it('calls onPageChange when previous clicked', async () => {
    const onPageChange = vi.fn()
    render(<Pagination currentPage={3} totalPages={5} onPageChange={onPageChange} />)
    await userEvent.click(screen.getByLabelText('Previous page'))
    expect(onPageChange).toHaveBeenCalledWith(2)
  })

  it('returns null when totalPages <= 1', () => {
    const { container } = render(<Pagination currentPage={1} totalPages={1} onPageChange={vi.fn()} />)
    expect(container.innerHTML).toBe('')
  })
})
