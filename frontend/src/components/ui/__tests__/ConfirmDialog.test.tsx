import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ConfirmDialog } from '../ConfirmDialog'

describe('ConfirmDialog', () => {
  it('renders with title and message', () => {
    render(
      <ConfirmDialog open onConfirm={vi.fn()} onClose={vi.fn()} title="Delete?" message="Are you sure?" />
    )
    expect(screen.getByText('Delete?')).toBeInTheDocument()
    expect(screen.getByText('Are you sure?')).toBeInTheDocument()
  })

  it('calls onConfirm when confirm button clicked', async () => {
    const onConfirm = vi.fn()
    render(
      <ConfirmDialog open onConfirm={onConfirm} onClose={vi.fn()} title="Sure?" message="Sure?" />
    )
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(onConfirm).toHaveBeenCalled()
  })

  it('calls onClose when cancel button clicked', async () => {
    const onClose = vi.fn()
    render(
      <ConfirmDialog open onConfirm={vi.fn()} onClose={onClose} title="Sure?" message="Sure?" />
    )
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onClose).toHaveBeenCalled()
  })
})
