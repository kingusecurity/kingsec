import { describe, it, expect, vi, afterEach } from 'vitest'
import { apiRequest, ApiError } from '../client'

function mockResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as Response
}

describe('apiRequest error parsing', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('surfaces the structured {error_code, message} shape used by registered exception handlers', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(mockResponse(403, { error_code: 'KS-LIC-001', message: 'Scheduling requires a Professional license' })),
    )

    await expect(apiRequest('/schedules')).rejects.toMatchObject({
      message: 'Scheduling requires a Professional license',
      errorCode: 'KS-LIC-001',
    })
  })

  it('surfaces a plain FastAPI HTTPException {detail: string} instead of a generic fallback', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(mockResponse(400, { detail: 'Not a signed license key' })),
    )

    await expect(apiRequest('/license/activate')).rejects.toMatchObject({
      message: 'Not a signed license key',
    })
  })

  it('formats a 422 validation-error array into a readable message instead of "[object Object]"', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        mockResponse(422, {
          detail: [
            { type: 'string_too_short', loc: ['body', 'username'], msg: 'String should have at least 3 characters' },
            { type: 'extra_forbidden', loc: ['body', 'unexpected_field'], msg: 'Extra inputs are not permitted' },
          ],
        }),
      ),
    )

    const error = await apiRequest('/auth/login').catch((e) => e as ApiError)
    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).message).toBe(
      'username: String should have at least 3 characters; unexpected_field: Extra inputs are not permitted',
    )
    expect((error as ApiError).message).not.toContain('[object Object]')
  })

  it('falls back to a generic message when the body has neither message nor detail', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockResponse(500, {})))

    await expect(apiRequest('/whatever')).rejects.toMatchObject({ message: 'Request failed' })
  })
})
