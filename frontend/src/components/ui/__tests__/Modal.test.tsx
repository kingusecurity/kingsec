import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Modal } from '../Modal'

describe('Modal', () => {
  it('renders content when open', () => {
    render(
      <Modal open={true} onClose={vi.fn()} title="Test Modal">
        Content
      </Modal>,
    )
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByText('Test Modal')).toBeInTheDocument()
    expect(screen.getByText('Content')).toBeInTheDocument()
  })

  it('does not render when closed', () => {
    render(
      <Modal open={false} onClose={vi.fn()}>
        Content
      </Modal>,
    )
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('calls onClose when close button is clicked', async () => {
    const onClose = vi.fn()
    render(
      <Modal open={true} onClose={onClose} title="Modal">
        Content
      </Modal>,
    )
    await userEvent.click(screen.getByLabelText('Close modal'))
    expect(onClose).toHaveBeenCalled()
  })

  it('calls onClose when Escape key is pressed', async () => {
    const onClose = vi.fn()
    render(
      <Modal open={true} onClose={onClose}>
        Content
      </Modal>,
    )
    await userEvent.keyboard('{Escape}')
    expect(onClose).toHaveBeenCalled()
  })

  it('renders footer', () => {
    render(
      <Modal open={true} onClose={vi.fn()} footer={<button>Save</button>}>
        Content
      </Modal>,
    )
    expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
  })
})
