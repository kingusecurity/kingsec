import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { NotificationPreferencesSection } from '../NotificationPreferencesSection'

describe('NotificationPreferencesSection', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('renders title', () => {
    render(<NotificationPreferencesSection />)
    expect(screen.getByText('Notification Preferences')).toBeInTheDocument()
  })

  it('renders all notification toggles', () => {
    render(<NotificationPreferencesSection />)
    expect(screen.getByText('Assessment Notifications')).toBeInTheDocument()
    expect(screen.getByText('Report Notifications')).toBeInTheDocument()
    expect(screen.getByText('System Notifications')).toBeInTheDocument()
    expect(screen.getByText('Email Notifications')).toBeInTheDocument()
  })

  it('defaults email notifications to off', () => {
    render(<NotificationPreferencesSection />)
    const emailToggle = screen.getByLabelText('Email Notifications')
    expect(emailToggle).not.toBeChecked()
  })

  it('allows toggling notifications', async () => {
    render(<NotificationPreferencesSection />)
    const toggle = screen.getByLabelText('Report Notifications')
    expect(toggle).toBeChecked()
    await userEvent.click(toggle)
    expect(toggle).not.toBeChecked()
  })
})
