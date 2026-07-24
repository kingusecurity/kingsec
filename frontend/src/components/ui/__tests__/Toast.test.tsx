import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ToastProvider, useToast } from '../Toast'

function ToastTrigger() {
  const { addToast } = useToast()
  return (
    <div>
      <button onClick={() => addToast({ variant: 'success', title: 'Success toast' })}>
        Show success
      </button>
      <button onClick={() => addToast({ variant: 'error', title: 'Error toast' })}>
        Show error
      </button>
    </div>
  )
}

describe('Toast', () => {
  it('renders provider without crashing', () => {
    render(
      <ToastProvider>
        <p>Content</p>
      </ToastProvider>
    )
    expect(screen.getByText('Content')).toBeInTheDocument()
  })

  it('shows toast on trigger', async () => {
    render(
      <ToastProvider>
        <ToastTrigger />
      </ToastProvider>
    )
    await userEvent.click(screen.getByText('Show success'))
    expect(screen.getByText('Success toast')).toBeInTheDocument()
  })

  it('supports error toast', async () => {
    render(
      <ToastProvider>
        <ToastTrigger />
      </ToastProvider>
    )
    await userEvent.click(screen.getByText('Show error'))
    expect(screen.getByText('Error toast')).toBeInTheDocument()
  })
})
