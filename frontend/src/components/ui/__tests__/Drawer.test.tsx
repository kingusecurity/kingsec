import { render, screen } from '@testing-library/react'
import { Drawer } from '../Drawer'

describe('Drawer', () => {
  it('renders when open', () => {
    render(
      <Drawer open onClose={vi.fn()}>
        <p>Drawer content</p>
      </Drawer>
    )
    expect(screen.getByText('Drawer content')).toBeInTheDocument()
  })

  it('renders title when provided', () => {
    render(
      <Drawer open onClose={vi.fn()} title="Details">
        <p>Content</p>
      </Drawer>
    )
    expect(screen.getByText('Details')).toBeInTheDocument()
  })
})
