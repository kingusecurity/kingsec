import { render, screen } from '@testing-library/react'
import { AboutSection } from '../AboutSection'
import { useAuthStore } from '@/store/auth'

describe('AboutSection', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: { user_id: 'u1', username: 'testadmin', role: 'admin', email: '', is_active: true, created_at: '', last_login_at: null },
      isAuthenticated: true,
    })
  })

  it('renders app name', () => {
    render(<AboutSection />)
    expect(screen.getByText('KingSec')).toBeInTheDocument()
  })

  it('renders version', () => {
    render(<AboutSection />)
    expect(screen.getByText('1.0.0')).toBeInTheDocument()
  })

  it('shows current user', () => {
    render(<AboutSection />)
    expect(screen.getByText('testadmin')).toBeInTheDocument()
  })
})
