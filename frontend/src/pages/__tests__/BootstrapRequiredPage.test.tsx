import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { settingsApi } from '@/api/settings'
import { BootstrapGuard } from '@/components/shared/RouteGuards'
import { BootstrapRequiredPage } from '../BootstrapRequiredPage'

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/bootstrap-required']}>
        <Routes>
          <Route path="/bootstrap-required" element={<BootstrapRequiredPage />} />
          <Route
            path="/login"
            element={
              <BootstrapGuard>
                <div>Sign in to KingSec</div>
              </BootstrapGuard>
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('BootstrapRequiredPage', () => {
  beforeEach(() => {
    vi.spyOn(settingsApi, 'health').mockResolvedValue({ status: 'ok', bootstrap_required: true })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('is an honest instruction screen, not a form', async () => {
    renderPage()
    expect(await screen.findByText('Instance needs initializing')).toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('form')).not.toBeInTheDocument()
  })

  it('shows the exact remediation command', async () => {
    renderPage()
    expect(await screen.findByText(/kingsec-bootstrap --username/)).toBeInTheDocument()
  })

  it('redirects to login when bootstrap is already complete on mount', async () => {
    vi.mocked(settingsApi.health).mockResolvedValue({ status: 'ok', bootstrap_required: false })

    renderPage()

    expect(await screen.findByText('Sign in to KingSec')).toBeInTheDocument()
    expect(screen.queryByText('Instance needs initializing')).not.toBeInTheDocument()
  })

  it('rechecks health and redirects to login after bootstrap completes', async () => {
    vi.mocked(settingsApi.health)
      .mockResolvedValueOnce({ status: 'ok', bootstrap_required: true })
      .mockResolvedValueOnce({ status: 'ok', bootstrap_required: false })
    renderPage()

    const button = await screen.findByRole('button', { name: "I've run it - check again" })
    expect(button).toHaveAttribute('type', 'button')
    fireEvent.click(button)

    await waitFor(() => expect(settingsApi.health).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(screen.getByText('Sign in to KingSec')).toBeInTheDocument())
    expect(screen.queryByText('Instance needs initializing')).not.toBeInTheDocument()
  })
})
