import { render, screen, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ToastProvider, useToast, ToastListener } from '@/components/ui/Toast'
import { Button } from '@/components/ui'

function TestButton() {
  const { addToast } = useToast()
  return (
    <Button onClick={() => addToast({ variant: 'success', title: 'Test Toast', message: 'Works' })}>
      Show Toast
    </Button>
  )
}

describe('ToastProvider', () => {
  it('renders children', () => {
    render(
      <ToastProvider>
        <div>Child Content</div>
      </ToastProvider>,
    )

    expect(screen.getByText('Child Content')).toBeInTheDocument()
  })

  it('shows toast via useToast hook', async () => {
    render(
      <ToastProvider>
        <ToastListener />
        <TestButton />
      </ToastProvider>,
    )

    await userEvent.click(screen.getByText('Show Toast'))
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.getByText('Test Toast')).toBeInTheDocument()
    expect(screen.getByText('Works')).toBeInTheDocument()
  })

  it('supports global toast events', async () => {
    render(
      <ToastProvider>
        <ToastListener />
      </ToastProvider>,
    )

    act(() => {
      window.dispatchEvent(
        new CustomEvent('kingsec-toast', {
          detail: { variant: 'info', title: 'Global Toast' },
        }),
      )
    })

    expect(screen.getByText('Global Toast')).toBeInTheDocument()
  })
})
