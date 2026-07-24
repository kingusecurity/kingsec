import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Modal } from '../Modal'

describe('Modal', () => {
  it('renders when open', () => {
    render(
      <Modal open onClose={vi.fn()}>
        <p>Content</p>
      </Modal>
    )
    expect(screen.getByText('Content')).toBeInTheDocument()
  })

  it('does not render when closed', () => {
    render(
      <Modal open={false} onClose={vi.fn()}>
        <p>Content</p>
      </Modal>
    )
    expect(screen.queryByText('Content')).not.toBeInTheDocument()
  })

  it('renders title when provided', () => {
    render(
      <Modal open onClose={vi.fn()} title="My Modal">
        <p>Content</p>
      </Modal>
    )
    expect(screen.getByText('My Modal')).toBeInTheDocument()
  })

  it('calls onClose when close button clicked', async () => {
    const onClose = vi.fn()
    render(
      <Modal open onClose={onClose}>
        <p>Content</p>
      </Modal>
    )
    await userEvent.click(screen.getByLabelText('Close modal'))
    expect(onClose).toHaveBeenCalled()
  })
})
