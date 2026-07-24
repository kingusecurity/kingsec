import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { NotFoundPage } from '@/pages/NotFoundPage'

describe('NotFoundPage', () => {
  it('renders 404 message', () => {
    window.history.pushState({}, '', '/nonexistent')
    render(
      <MemoryRouter initialEntries={['/nonexistent']}>
        <NotFoundPage />
      </MemoryRouter>,
    )

    expect(screen.getByText('404')).toBeInTheDocument()
    expect(screen.getByText('Page not found')).toBeInTheDocument()
    expect(screen.getByText('/nonexistent')).toBeInTheDocument()
  })

  it('renders back to dashboard button', () => {
    render(
      <MemoryRouter>
        <NotFoundPage />
      </MemoryRouter>,
    )

    expect(screen.getByText('Back to Dashboard')).toBeInTheDocument()
  })
})
