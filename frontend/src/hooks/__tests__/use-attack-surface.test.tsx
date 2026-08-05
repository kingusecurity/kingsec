import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { useMitigateExposure } from '../use-attack-surface'

vi.mock('@/api/attack-surface', () => ({
  attackSurfaceApi: {
    mitigate: vi.fn().mockResolvedValue({ id: 'exp-1', status: 'mitigated' }),
  },
}))

// Regression test: mitigating an exposure previously only invalidated the
// ['exposures'] list and ['attack-surface-summary'] - never this specific
// exposure's own ['exposure', id] query, so AttackSurfaceDetailPage kept
// showing the stale (pre-mitigation) status until navigating away and back.
describe('useMitigateExposure', () => {
  it('invalidates the specific exposure query, not just the list/summary', async () => {
    const queryClient = new QueryClient()
    const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries')

    function wrapper({ children }: { children: ReactNode }) {
      return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    }

    const { result } = renderHook(() => useMitigateExposure(), { wrapper })

    result.current.mutate('exp-1')

    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    const invalidatedKeys = invalidateSpy.mock.calls.map((call) => call[0]?.queryKey)
    expect(invalidatedKeys).toContainEqual(['exposures'])
    expect(invalidatedKeys).toContainEqual(['attack-surface-summary'])
    expect(invalidatedKeys).toContainEqual(['exposure', 'exp-1'])
  })
})
