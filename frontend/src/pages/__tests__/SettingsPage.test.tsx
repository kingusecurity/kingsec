import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SettingsPage } from '../SettingsPage'

const queryClient = new QueryClient()

function renderPage() {
  return render(
    <QueryClientProvider client={queryClient}>
      <SettingsPage />
    </QueryClientProvider>,
  )
}

describe('SettingsPage', () => {
  it('renders page title', () => {
    renderPage()
    expect(screen.getByText('Settings')).toBeInTheDocument()
  })

  it('renders all tab triggers', () => {
    renderPage()
    expect(screen.getByRole('tab', { name: 'General' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Appearance' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Security' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'API' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'About' })).toBeInTheDocument()
  })

  it('does not render the Dashboard/Notifications preference tabs (hidden - saved values had no effect)', () => {
    renderPage()
    expect(screen.queryByRole('tab', { name: 'Dashboard' })).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Notifications' })).not.toBeInTheDocument()
  })

  it('shows General section by default', () => {
    renderPage()
    expect(screen.getByText('Your account information')).toBeInTheDocument()
  })
})
