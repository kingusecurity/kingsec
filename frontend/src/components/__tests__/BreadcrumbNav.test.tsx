import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Breadcrumb, BreadcrumbItem, BreadcrumbSeparator } from '@/components/ui/Breadcrumb'

describe('Breadcrumb', () => {
  it('renders breadcrumb items', () => {
    render(
      <MemoryRouter>
        <Breadcrumb>
          <BreadcrumbItem href="/dashboard">Dashboard</BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem isCurrent>Current</BreadcrumbItem>
        </Breadcrumb>
      </MemoryRouter>,
    )

    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Current')).toBeInTheDocument()
  })

  it('sets aria-current on current item', () => {
    render(
      <MemoryRouter>
        <Breadcrumb>
          <BreadcrumbItem isCurrent>Active</BreadcrumbItem>
        </Breadcrumb>
      </MemoryRouter>,
    )

    expect(screen.getByText('Active')).toHaveAttribute('aria-current', 'page')
  })

  it('renders separator', () => {
    const { container } = render(
      <MemoryRouter>
        <Breadcrumb>
          <BreadcrumbItem>First</BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>Second</BreadcrumbItem>
        </Breadcrumb>
      </MemoryRouter>,
    )

    const chevron = container.querySelector('svg')
    expect(chevron).toBeInTheDocument()
  })
})
