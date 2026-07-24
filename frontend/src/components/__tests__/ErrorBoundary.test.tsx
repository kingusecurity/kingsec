import { render, screen } from '@testing-library/react'
import { AppErrorBoundary, PageErrorBoundary } from '../shared/ErrorBoundary'

const ThrowComponent = () => {
  throw new Error('Test error')
}

describe('AppErrorBoundary', () => {
  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders children when no error', () => {
    render(
      <AppErrorBoundary>
        <div>All good</div>
      </AppErrorBoundary>,
    )

    expect(screen.getByText('All good')).toBeInTheDocument()
  })

  it('renders error UI on error', () => {
    render(
      <AppErrorBoundary>
        <ThrowComponent />
      </AppErrorBoundary>,
    )

    expect(screen.getByText('Something went wrong')).toBeInTheDocument()
    expect(screen.getByText('Try Again')).toBeInTheDocument()
    expect(screen.getByText('Return to Dashboard')).toBeInTheDocument()
  })
})

describe('PageErrorBoundary', () => {
  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders children when no error', () => {
    render(
      <PageErrorBoundary>
        <div>Page content</div>
      </PageErrorBoundary>,
    )

    expect(screen.getByText('Page content')).toBeInTheDocument()
  })

  it('renders error UI on error', () => {
    render(
      <PageErrorBoundary>
        <ThrowComponent />
      </PageErrorBoundary>,
    )

    expect(screen.getByText('Page Error')).toBeInTheDocument()
    expect(screen.getByText('Try Again')).toBeInTheDocument()
  })
})
