import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Breadcrumb, BreadcrumbItem, BreadcrumbSeparator } from '../Breadcrumb'

function renderBreadcrumb(children: React.ReactNode) {
  return render(<MemoryRouter>{children}</MemoryRouter>)
}

describe('Breadcrumb', () => {
  it('renders items', () => {
    renderBreadcrumb(
      <Breadcrumb>
        <BreadcrumbItem href="/">Home</BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem href="/assessments">Assessments</BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem isCurrent>Detail</BreadcrumbItem>
      </Breadcrumb>
    )
    expect(screen.getByText('Home')).toBeInTheDocument()
    expect(screen.getByText('Assessments')).toBeInTheDocument()
    expect(screen.getByText('Detail')).toBeInTheDocument()
  })

  it('renders last item without href as non-link', () => {
    renderBreadcrumb(
      <Breadcrumb>
        <BreadcrumbItem href="/">Home</BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem isCurrent>Current</BreadcrumbItem>
      </Breadcrumb>
    )
    const current = screen.getByText('Current')
    expect(current.tagName).toBe('SPAN')
  })
})
