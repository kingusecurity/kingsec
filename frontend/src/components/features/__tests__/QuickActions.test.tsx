import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QuickActions } from '../dashboard/QuickActions'

describe('QuickActions', () => {
  it('renders all action links', () => {
    render(
      <MemoryRouter>
        <QuickActions />
      </MemoryRouter>,
    )
    expect(screen.getByText('New Assessment')).toBeInTheDocument()
    expect(screen.getByText('View Reports')).toBeInTheDocument()
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Settings')).toBeInTheDocument()
  })

  it('links to correct routes', () => {
    render(
      <MemoryRouter>
        <QuickActions />
      </MemoryRouter>,
    )
    expect(screen.getByText('New Assessment').closest('a')).toHaveAttribute('href', '/assessments/new')
    expect(screen.getByText('Dashboard').closest('a')).toHaveAttribute('href', '/dashboard')
  })

  it('does not suggest New Assessment by default', () => {
    render(
      <MemoryRouter>
        <QuickActions />
      </MemoryRouter>,
    )
    expect(screen.queryByText('Start here')).not.toBeInTheDocument()
  })

  it('marks New Assessment as the suggested first step when suggestFirst is true', () => {
    render(
      <MemoryRouter>
        <QuickActions suggestFirst />
      </MemoryRouter>,
    )
    expect(screen.getByText('Start here')).toBeInTheDocument()
  })
})
