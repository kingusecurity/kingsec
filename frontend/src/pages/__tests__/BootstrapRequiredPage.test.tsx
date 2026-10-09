import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { BootstrapRequiredPage } from '../BootstrapRequiredPage'

vi.mock('@/hooks/use-settings', () => ({
  useHealth: vi.fn(),
}))

import { useHealth } from '@/hooks/use-settings'

const queryClient = new QueryClient()

function LocationDisplay() {
  const location = useLocation()
  return <div data-testid="location-display">{location.pathname}</div>
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/bootstrap-required']}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/bootstrap-required" element={<BootstrapRequiredPage />} />
          <Route path="*" element={<LocationDisplay />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
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

  it('redirects to /login when health shows an admin already exists', async () => {
    vi.mocked(useHealth).mockReturnValue({
      data: { status: 'ok', bootstrap_required: false },
      refetch: vi.fn(),
      isFetching: false,
    } as any)
    renderPage()
    await waitFor(() => {
      expect(screen.getByTestId('location-display')).toHaveTextContent('/login')
    })
  })

  it('stays on the bootstrap screen while no admin exists', () => {
    vi.mocked(useHealth).mockReturnValue({
      data: { status: 'ok', bootstrap_required: true },
      refetch: vi.fn(),
      isFetching: false,
    } as any)
    renderPage()
    expect(screen.getByText('Instance needs initializing')).toBeInTheDocument()
    expect(screen.queryByTestId('location-display')).not.toBeInTheDocument()
  })
})
