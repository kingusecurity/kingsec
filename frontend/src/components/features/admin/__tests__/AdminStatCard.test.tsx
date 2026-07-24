import { render, screen } from '@testing-library/react'
import { Users } from 'lucide-react'
import { AdminStatCard } from '../AdminStatCard'

describe('AdminStatCard', () => {
  it('renders label and value', () => {
    render(<AdminStatCard label="Total Users" value={42} icon={Users} />)
    expect(screen.getByText('Total Users')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
  })

  it('renders 0 when value is undefined', () => {
    render(<AdminStatCard label="Total Users" value={undefined} icon={Users} />)
    expect(screen.getByText('0')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    const { container } = render(<AdminStatCard label="Total Users" value={undefined} icon={Users} loading={true} />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })

  it('renders icon', () => {
    render(<AdminStatCard label="Total Users" value={10} icon={Users} />)
    expect(screen.getByText('Total Users')).toBeInTheDocument()
  })
})
