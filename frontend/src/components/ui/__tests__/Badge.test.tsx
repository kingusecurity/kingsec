import { render, screen } from '@testing-library/react'
import { Badge } from '../Badge'

describe('Badge', () => {
  it('renders children', () => {
    render(<Badge>Test</Badge>)
    expect(screen.getByText('Test')).toBeInTheDocument()
  })

  it('renders with different variants', () => {
    const { container, rerender } = render(<Badge variant="critical">Critical</Badge>)
    expect(screen.getByText('Critical')).toBeInTheDocument()
    rerender(<Badge variant="success">Success</Badge>)
    expect(screen.getByText('Success')).toBeInTheDocument()
    rerender(<Badge variant="warning">Warning</Badge>)
    expect(screen.getByText('Warning')).toBeInTheDocument()
  })

  it('renders with different sizes', () => {
    const { container, rerender } = render(<Badge size="sm">Small</Badge>)
    expect(screen.getByText('Small')).toBeInTheDocument()
    rerender(<Badge size="lg">Large</Badge>)
    expect(screen.getByText('Large')).toBeInTheDocument()
  })
})
