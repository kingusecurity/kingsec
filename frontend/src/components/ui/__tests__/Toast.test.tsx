import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ToastProvider, useToast, ToastListener } from '../Toast'
import { Button } from '../Button'

function ToastButton() {
  const { addToast } = useToast()
  return (
    <Button onClick={() => addToast({ variant: 'success', title: 'Test Toast', message: 'Toast message' })}>
      Show Toast
    </Button>
  )
}

describe('Toast', () => {
  it('shows toast when triggered', async () => {
    render(
      <ToastProvider>
        <ToastListener />
        <ToastButton />
      </ToastProvider>,
    )

    await userEvent.click(screen.getByRole('button', { name: /show toast/i }))
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.getByText('Test Toast')).toBeInTheDocument()
    expect(screen.getByText('Toast message')).toBeInTheDocument()
  })

  it('renders dismiss button on toast', async () => {
    function Test() {
      const { addToast } = useToast()
      return <Button onClick={() => addToast({ variant: 'info', title: 'Dismiss me' })}>Trigger</Button>
    }

    render(
      <ToastProvider>
        <ToastListener />
        <Test />
      </ToastProvider>,
    )

    await userEvent.click(screen.getByText('Trigger'))
    expect(screen.getByLabelText('Dismiss')).toBeInTheDocument()
  })
})
