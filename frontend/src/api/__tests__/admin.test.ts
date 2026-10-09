import { afterEach, describe, expect, it, vi } from 'vitest'
import { adminApi } from '../admin'

function downloadResponse({
  filename,
  contentType,
}: {
  filename?: string
  contentType: string
}): Response {
  const headers = new Headers({ 'Content-Type': contentType })
  if (filename) headers.set('Content-Disposition', `attachment; filename="${filename}"`)
  return {
    ok: true,
    headers,
    blob: async () => new Blob(['report'], { type: contentType }),
  } as Response
}

describe('adminApi.downloadReport', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('uses the backend artifact filename for an HTML report', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        downloadResponse({
          filename: 'kingsec-report-asmt-123.html',
          contentType: 'text/html; charset=utf-8',
        }),
      ),
    )
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn().mockReturnValue('blob:report'),
      revokeObjectURL: vi.fn(),
    })
    const downloaded: string[] = []
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(function (this: HTMLAnchorElement) {
        downloaded.push(this.download)
      })

    await adminApi.downloadReport('asmt-123')

    expect(click).toHaveBeenCalledTimes(1)
    expect(downloaded).toEqual(['kingsec-report-asmt-123.html'])
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:report')
  })

  it('falls back to the response media type when no filename header is present', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(downloadResponse({ contentType: 'application/pdf' })),
    )
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn().mockReturnValue('blob:report'),
      revokeObjectURL: vi.fn(),
    })
    const downloaded: string[] = []
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      downloaded.push(this.download)
    })

    await adminApi.downloadReport('asmt-456')

    expect(downloaded).toEqual(['kingsec-report-asmt-456.pdf'])
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:report')
  })

  it('uses an HTML media-type fallback when the filename header is malformed', async () => {
    const response = downloadResponse({ contentType: 'text/html; charset=utf-8' })
    response.headers.set(
      'Content-Disposition',
      `attachment; filename*=UTF-8''bad%ZZ.html`,
    )
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response))
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn().mockReturnValue('blob:report'),
      revokeObjectURL: vi.fn(),
    })
    const downloaded: string[] = []
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      downloaded.push(this.download)
    })

    await adminApi.downloadReport('asmt-html')

    expect(downloaded).toEqual(['kingsec-report-asmt-html.html'])
  })

  it('does not create a browser download after an unsuccessful response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false } as Response))
    const createObjectURL = vi.fn()
    vi.stubGlobal('URL', { createObjectURL, revokeObjectURL: vi.fn() })

    await expect(adminApi.downloadReport('asmt-789')).rejects.toThrow('Download failed')
    expect(createObjectURL).not.toHaveBeenCalled()
  })
})
