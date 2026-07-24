import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { ReportTable } from '../ReportTable'

const reports = [
  { assessment_id: 'a1', target: '10.0.0.1', status: 'completed', findings_count: 5, is_authorized: true, created_at: '2024-01-01T00:00:00Z' },
  { assessment_id: 'a2', target: 'example.com', status: 'completed', findings_count: 3, is_authorized: true, created_at: '2024-01-02T00:00:00Z' },
]

describe('ReportTable', () => {
  it('renders reports with links', () => {
    render(
      <MemoryRouter>
        <ReportTable reports={reports} />
      </MemoryRouter>,
    )
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
    expect(screen.getByText('example.com')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getAllByText('completed')).toHaveLength(2)
  })

  it('renders empty state when no reports', () => {
    render(
      <MemoryRouter>
        <ReportTable reports={[]} />
      </MemoryRouter>,
    )
    expect(screen.getByText('No reports found.')).toBeInTheDocument()
  })

  it('renders loading state', () => {
    const { container } = render(
      <MemoryRouter>
        <ReportTable loading />
      </MemoryRouter>,
    )
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })
})
