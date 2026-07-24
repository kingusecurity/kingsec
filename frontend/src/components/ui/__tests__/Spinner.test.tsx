import { render } from '@testing-library/react'
import { Spinner } from '../Spinner'

describe('Spinner', () => {
  it('renders with default size', () => {
    const { container } = render(<Spinner />)
    expect(container.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('renders with sm size', () => {
    const { container } = render(<Spinner size="sm" />)
    expect(container.querySelector('.h-4')).toBeInTheDocument()
  })
})
