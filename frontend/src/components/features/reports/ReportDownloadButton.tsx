import { Download } from 'lucide-react'
import { Button } from '@/components/ui/Button'

interface ReportDownloadButtonProps {
  downloadUrl?: string
  loading?: boolean
  disabled?: boolean
  label?: string
  onDownload?: () => void
}

export function ReportDownloadButton({
  downloadUrl,
  loading,
  disabled,
  label = 'Download Report',
  onDownload,
}: ReportDownloadButtonProps) {
  const handleClick = () => {
    if (onDownload) {
      onDownload()
    } else if (downloadUrl) {
      window.open(downloadUrl, '_blank')
    }
  }

  return (
    <Button
      variant="primary"
      className="w-full"
      onClick={handleClick}
      loading={loading}
      disabled={disabled || !downloadUrl}
      iconLeft={<Download className="h-4 w-4" />}
      aria-label={label}
    >
      {label}
    </Button>
  )
}
