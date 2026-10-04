import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BootstrapRequiredPage } from '../BootstrapRequiredPage'

vi.mock('@/hooks/use-settings', () => ({
  useHealth: vi.fn(),
}))

import { useHealth } from '@/hooks/use-settings'

const queryClient = new QueryClient()

function renderPage() {
  return render(
    <QueryClientProvider client={queryClient}>
      <BootstrapRequiredPage />
    </QueryClientProvider>,
  )
}

describe('BootstrapRequiredPage', () => {
  beforeEach(() => {
    vi.mocked(useHealth).mockReturnValue({ refetch: vi.fn(), isFetching: false } as any)
  })

  it('is an honest instruction screen, not a form', () => {
    renderPage()
    expect(screen.getByText('Instance needs initializing')).toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('form')).not.toBeInTheDocument()
  })

  it('shows the exact remediation command', () => {
    renderPage()
    expect(screen.getByText(/kingsec-bootstrap --username/)).toBeInTheDocument()
  })

  it('offers a recheck control that calls refetch, not a submit', () => {
    const refetch = vi.fn()
    vi.mocked(useHealth).mockReturnValue({ refetch, isFetching: false } as any)
    renderPage()
    const button = screen.getByRole('button', { name: "I've run it - check again" })
    expect(button).toHaveAttribute('type', 'button')
  })
})
