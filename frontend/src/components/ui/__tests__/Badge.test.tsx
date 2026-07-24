import { render, screen } from '@testing-library/react'
import { Badge } from '../Badge'

describe('Badge', () => {
  it('renders children', () => {
    render(<Badge>Critical</Badge>)
    expect(screen.getByText('Critical')).toBeInTheDocument()
  })

  it('applies variant classes', () => {
    const { rerender } = render(<Badge variant="critical">Critical</Badge>)
    expect(screen.getByText('Critical')).toHaveClass('bg-red-900/50', 'text-red-400')

    rerender(<Badge variant="success">Success</Badge>)
    expect(screen.getByText('Success')).toHaveClass('bg-emerald-900/50', 'text-emerald-400')
  })

  it('applies size classes', () => {
    render(<Badge size="lg">Large</Badge>)
    expect(screen.getByText('Large')).toHaveClass('px-2.5', 'py-1', 'text-sm')
  })
})
