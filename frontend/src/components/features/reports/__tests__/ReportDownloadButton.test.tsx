import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ReportDownloadButton } from '../ReportDownloadButton'

describe('ReportDownloadButton', () => {
  it('renders with default label', () => {
    render(<ReportDownloadButton downloadUrl="/api/v1/reports/a1/download" />)
    expect(screen.getByText('Download Report')).toBeInTheDocument()
  })

  it('renders with custom label', () => {
    render(<ReportDownloadButton downloadUrl="/api/v1/reports/a1/download" label="Export PDF" />)
    expect(screen.getByText('Export PDF')).toBeInTheDocument()
  })

  it('calls onDownload when clicked', async () => {
    const onDownload = vi.fn()
    render(<ReportDownloadButton downloadUrl="/api/v1/reports/a1/download" onDownload={onDownload} />)
    await userEvent.click(screen.getByText('Download Report'))
    expect(onDownload).toHaveBeenCalledOnce()
  })

  it('is disabled when no downloadUrl', () => {
    render(<ReportDownloadButton />)
    expect(screen.getByRole('button', { name: /download report/i })).toBeDisabled()
  })

  it('shows loading state', () => {
    render(<ReportDownloadButton downloadUrl="/api/v1/reports/a1/download" loading />)
    expect(screen.getByRole('button')).toBeDisabled()
  })
})
