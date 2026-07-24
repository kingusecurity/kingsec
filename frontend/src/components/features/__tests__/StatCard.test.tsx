import { render, screen } from '@testing-library/react'
import { Shield } from 'lucide-react'
import { StatCard } from '../dashboard/StatCard'

describe('StatCard', () => {
  it('renders label and value', () => {
    render(<StatCard icon={Shield} label="Total Scans" value={42} />)
    expect(screen.getByText('Total Scans')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
  })

  it('shows description when provided', () => {
    render(<StatCard icon={Shield} label="Critical" value={5} description="High risk findings" />)
    expect(screen.getByText('High risk findings')).toBeInTheDocument()
  })

  it('shows skeleton when loading', () => {
    const { container } = render(<StatCard icon={Shield} label="Total" value={10} loading />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })
})
