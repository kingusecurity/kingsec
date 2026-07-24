import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { ReportCard } from '../ReportCard'

describe('ReportCard', () => {
  const baseProps = {
    assessmentId: 'a1',
    target: '10.0.0.1',
    verdict: 'moderate',
    totalFindings: 10,
    highestSeverity: 'critical',
    createdAt: '2024-01-01T00:00:00Z',
  }

  it('renders report info', () => {
    render(
      <MemoryRouter>
        <ReportCard {...baseProps} />
      </MemoryRouter>,
    )
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
    expect(screen.getByText('10')).toBeInTheDocument()
    expect(screen.getByText('moderate')).toBeInTheDocument()
    expect(screen.getByText('critical')).toBeInTheDocument()
  })

  it('renders link to report detail', () => {
    render(
      <MemoryRouter>
        <ReportCard {...baseProps} />
      </MemoryRouter>,
    )
    const link = screen.getByRole('link', { name: /view report for 10.0.0.1/i })
    expect(link).toHaveAttribute('href', '/reports/a1')
  })

  it('renders loading state', () => {
    const { container } = render(
      <MemoryRouter>
        <ReportCard {...baseProps} loading />
      </MemoryRouter>,
    )
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })
})
