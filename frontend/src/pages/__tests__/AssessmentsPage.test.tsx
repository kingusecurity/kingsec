import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { AssessmentsPage } from '../AssessmentsPage'
import { useAuthStore } from '@/store/auth'

vi.mock('@/hooks/use-assessments', () => ({
  useAssessments: vi.fn(),
}))

import { useAssessments } from '@/hooks/use-assessments'

function renderPage(path = '/assessments') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AssessmentsPage />
    </MemoryRouter>,
  )
}

describe('AssessmentsPage', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: {
        user_id: 'user-1',
        username: 'analyst',
        role: 'analyst',
        email: '',
        is_active: true,
        created_at: '',
        last_login_at: null,
      },
      isAuthenticated: true,
    })
    vi.mocked(useAssessments).mockReturnValue({
      data: { items: [], total: 0, limit: 20, offset: 0, unreadable_ids: [] },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
  })

  it('forwards URL-backed search, status, sorting, and pagination to the API hook', () => {
    renderPage(
      '/assessments?search=example.com&status=completed_with_gaps&sort_by=findings_count&sort_order=asc&page=3',
    )

    expect(useAssessments).toHaveBeenCalledWith({
      limit: 20,
      offset: 40,
      search: 'example.com',
      status: 'completed_with_gaps',
      order_by: 'findings_count',
      order_dir: 'asc',
    })
  })

  it('shows the ownership-scoped IDs of unreadable assessment records', () => {
    vi.mocked(useAssessments).mockReturnValue({
      data: {
        items: [],
        total: 2,
        limit: 20,
        offset: 0,
        unreadable_ids: ['asmt-broken-1', 'asmt-broken-2'],
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)

    renderPage()

    expect(screen.getByRole('alert')).toHaveTextContent('2 assessment records were omitted')
    expect(screen.getByLabelText('Unreadable assessment IDs')).toHaveTextContent(
      'asmt-broken-1, asmt-broken-2',
    )
    expect(screen.getByText('Assessment records unavailable')).toBeInTheDocument()
  })

  it('keeps pagination available when the current page contains only unreadable rows', () => {
    vi.mocked(useAssessments).mockReturnValue({
      data: {
        items: [],
        total: 40,
        limit: 20,
        offset: 0,
        unreadable_ids: ['asmt-broken-1'],
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)

    renderPage()

    expect(screen.getByRole('navigation', { name: 'Pagination' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Next page' })).toBeEnabled()
  })

  it('ignores unsupported status and sort values from a shared URL', () => {
    renderPage('/assessments?status=pending&sort_by=drop-table&sort_order=sideways&page=-4')

    expect(useAssessments).toHaveBeenCalledWith({
      limit: 20,
      offset: 0,
      search: undefined,
      status: undefined,
      order_by: 'created_at',
      order_dir: 'desc',
    })
  })

  it('caps a shared URL search at the backend validation limit', () => {
    renderPage(`/assessments?search=${'x'.repeat(300)}`)

    expect(useAssessments).toHaveBeenCalledWith({
      limit: 20,
      offset: 0,
      search: 'x'.repeat(256),
      status: undefined,
      order_by: 'created_at',
      order_dir: 'desc',
    })
  })

  it('recovers an out-of-range shared page instead of trapping the pager', async () => {
    vi.mocked(useAssessments).mockReturnValue({
      data: { items: [], total: 21, limit: 20, offset: 1980, unreadable_ids: [] },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)

    renderPage('/assessments?page=100')

    await waitFor(() => {
      expect(useAssessments).toHaveBeenLastCalledWith({
        limit: 20,
        offset: 20,
        search: undefined,
        status: undefined,
        order_by: 'created_at',
        order_dir: 'desc',
      })
    })
  })
})
