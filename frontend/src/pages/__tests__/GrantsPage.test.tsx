import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { GrantsPage } from '../GrantsPage'
import { useAuthStore } from '@/store/auth'

vi.mock('@/hooks/use-grants', () => ({
  useGrants: vi.fn(),
  useCreateGrant: vi.fn(),
  useRevokeGrant: vi.fn(),
}))

import { useGrants, useCreateGrant, useRevokeGrant } from '@/hooks/use-grants'

const queryClient = new QueryClient()

function renderPage() {
  return render(
    <QueryClientProvider client={queryClient}>
      <GrantsPage />
    </QueryClientProvider>,
  )
}

function setRole(role: string | null) {
  useAuthStore.setState(
    role
      ? {
          user: { user_id: '1', username: 'u', role, email: '', is_active: true, created_at: '', last_login_at: null },
          isAuthenticated: true,
        }
      : { user: null, isAuthenticated: false },
  )
}

const activeGrant = {
  id: 'grant-1',
  authorized_by: 'ciso@example.com',
  authorizing_organization: 'Example Corp',
  target_specification_type: 'url_prefix' as const,
  target_specification_value: 'https://app.example.com/',
  valid_from: new Date(Date.now() - 1000).toISOString(),
  valid_until: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(),
  created_by: 'admin',
  revoked_at: null,
}

describe('GrantsPage', () => {
  beforeEach(() => {
    vi.mocked(useGrants).mockReturnValue({
      data: { items: [], limit: 50, offset: 0 },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
    vi.mocked(useCreateGrant).mockReturnValue({ mutateAsync: vi.fn(), isPending: false } as any)
    vi.mocked(useRevokeGrant).mockReturnValue({ mutate: vi.fn(), isPending: false } as any)
  })

  it('renders page title', () => {
    setRole('admin')
    renderPage()
    expect(screen.getByText('Authorization Grants')).toBeInTheDocument()
  })

  it('shows empty state when no grants', () => {
    setRole('admin')
    renderPage()
    expect(screen.getByText('No authorization grants')).toBeInTheDocument()
  })

  it('shows the Create Grant control to an admin', () => {
    setRole('admin')
    renderPage()
    expect(screen.getByRole('button', { name: 'Create Grant' })).toBeInTheDocument()
  })

  it('hides the Create Grant control from a non-admin and shows a read-only notice', () => {
    setRole('analyst')
    renderPage()
    expect(screen.queryByRole('button', { name: 'Create Grant' })).not.toBeInTheDocument()
    expect(screen.getByText('Read-only')).toBeInTheDocument()
  })

  it('shows the surface-tier warning only when URL Prefix is selected', () => {
    setRole('admin')
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Create Grant' }))

    // ip_address is the default selection - no host-scan warning yet.
    expect(screen.queryByText('This does not authorize a host scan')).not.toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Target Type *'), { target: { value: 'url_prefix' } })
    expect(screen.getByText('This does not authorize a host scan')).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Target Type *'), { target: { value: 'ip_address' } })
    expect(screen.queryByText('This does not authorize a host scan')).not.toBeInTheDocument()
  })

  it('renders an active grant with its target value and a Revoke control for admins', () => {
    setRole('admin')
    vi.mocked(useGrants).mockReturnValue({
      data: { items: [activeGrant], limit: 50, offset: 0 },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
    renderPage()
    expect(screen.getByText('https://app.example.com/')).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Revoke' })).toBeInTheDocument()
  })

  it('does not show a Revoke control to a non-admin', () => {
    setRole('analyst')
    vi.mocked(useGrants).mockReturnValue({
      data: { items: [activeGrant], limit: 50, offset: 0 },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
    renderPage()
    expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument()
  })

  it('shows Revoked status and no Revoke control for an already-revoked grant', () => {
    setRole('admin')
    vi.mocked(useGrants).mockReturnValue({
      data: { items: [{ ...activeGrant, revoked_at: new Date().toISOString() }], limit: 50, offset: 0 },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any)
    renderPage()
    expect(screen.getByText('Revoked')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument()
  })
})
