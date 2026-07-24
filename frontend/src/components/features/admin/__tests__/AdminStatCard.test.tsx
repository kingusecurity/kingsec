import { render, screen } from '@testing-library/react'
import { Shield } from 'lucide-react'
import { AdminStatCard } from '../AdminStatCard'

describe('AdminStatCard', () => {
  it('renders label and value', () => {
    render(<AdminStatCard label="Users" value={42} icon={Shield} />)
    expect(screen.getByText('Users')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
  })

  it('renders skeleton when loading', () => {
    const { container } = render(<AdminStatCard label="Users" value={42} icon={Shield} loading />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })

  it('shows 0 when value is undefined', () => {
    render(<AdminStatCard label="Users" icon={Shield} />)
    expect(screen.getByText('0')).toBeInTheDocument()
  })
})
