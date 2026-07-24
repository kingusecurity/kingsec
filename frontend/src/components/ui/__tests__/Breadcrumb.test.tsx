import { render, screen } from '@testing-library/react'
import { Breadcrumb, BreadcrumbItem, BreadcrumbSeparator } from '../Breadcrumb'

describe('Breadcrumb', () => {
  it('renders items', () => {
    render(
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
    render(
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
