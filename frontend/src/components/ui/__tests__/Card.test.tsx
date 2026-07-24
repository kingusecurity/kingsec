import { render, screen } from '@testing-library/react'
import { Card, CardHeader, CardTitle, CardDescription, CardActions, CardFooter } from '../Card'

describe('Card', () => {
  it('renders children', () => {
    render(<Card>Content</Card>)
    expect(screen.getByText('Content')).toBeInTheDocument()
  })

  it('applies variant classes', () => {
    const { rerender } = render(<Card variant="elevated">Elevated</Card>)
    expect(screen.getByText('Elevated')).toHaveClass('shadow-theme-md')

    rerender(<Card variant="danger">Danger</Card>)
    expect(screen.getByText('Danger')).toHaveClass('border-red-800/50')
  })

  it('renders CardHeader', () => {
    render(
      <Card>
        <CardHeader>Header</CardHeader>
      </Card>,
    )
    expect(screen.getByText('Header')).toBeInTheDocument()
  })

  it('renders CardTitle', () => {
    render(
      <Card>
        <CardTitle>Title</CardTitle>
      </Card>,
    )
    expect(screen.getByText('Title')).toBeInTheDocument()
  })

  it('renders CardDescription', () => {
    render(
      <Card>
        <CardDescription>Description</CardDescription>
      </Card>,
    )
    expect(screen.getByText('Description')).toBeInTheDocument()
  })

  it('renders CardActions', () => {
    render(
      <Card>
        <CardActions>
          <button>Action</button>
        </CardActions>
      </Card>,
    )
    expect(screen.getByRole('button', { name: /action/i })).toBeInTheDocument()
  })

  it('renders CardFooter with border', () => {
    render(
      <Card>
        <CardFooter>Footer</CardFooter>
      </Card>,
    )
    const footer = screen.getByText('Footer')
    expect(footer).toHaveClass('border-t')
  })
})
