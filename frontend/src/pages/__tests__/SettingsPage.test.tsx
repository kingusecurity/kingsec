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
    expect(screen.getByRole('tab', { name: 'Dashboard' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Notifications' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Security' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'API' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'About' })).toBeInTheDocument()
  })

  it('shows General section by default', () => {
    renderPage()
    expect(screen.getByText('Your account information')).toBeInTheDocument()
  })
})
