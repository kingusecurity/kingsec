import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DashboardPreferencesSection } from '../DashboardPreferencesSection'

describe('DashboardPreferencesSection', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('renders title', () => {
    render(<DashboardPreferencesSection />)
    expect(screen.getByText('Dashboard Preferences')).toBeInTheDocument()
  })

  it('renders default page select', () => {
    render(<DashboardPreferencesSection />)
    expect(screen.getByLabelText('Default Landing Page')).toBeInTheDocument()
  })

  it('renders refresh interval select', () => {
    render(<DashboardPreferencesSection />)
    expect(screen.getByLabelText('Dashboard Refresh Interval')).toBeInTheDocument()
  })

  it('renders all widget toggles', () => {
    render(<DashboardPreferencesSection />)
    expect(screen.getByText('Show Quick Actions')).toBeInTheDocument()
    expect(screen.getByText('Show Recent Assessments')).toBeInTheDocument()
    expect(screen.getByText('Show System Status')).toBeInTheDocument()
    expect(screen.getByText('Show Job Status')).toBeInTheDocument()
  })

  it('allows toggling a widget', async () => {
    render(<DashboardPreferencesSection />)
    const toggle = screen.getByLabelText('Show Quick Actions')
    expect(toggle).toBeChecked()
    await userEvent.click(toggle)
    expect(toggle).not.toBeChecked()
  })
})
