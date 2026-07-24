import { X } from 'lucide-react'
import { Select } from '@/components/ui/Select'
import { Button } from '@/components/ui/Button'

const actionOptions = [
  { value: '', label: 'All Actions' },
  { value: 'login', label: 'Login' },
  { value: 'logout', label: 'Logout' },
  { value: 'create', label: 'Create' },
  { value: 'update', label: 'Update' },
  { value: 'delete', label: 'Delete' },
  { value: 'start', label: 'Start' },
  { value: 'cancel', label: 'Cancel' },
  { value: 'report', label: 'Report' },
  { value: 'assign_role', label: 'Role Change' },
]

const resourceOptions = [
  { value: '', label: 'All Resources' },
  { value: 'assessment', label: 'Assessment' },
  { value: 'finding', label: 'Finding' },
  { value: 'report', label: 'Report' },
  { value: 'user', label: 'User' },
  { value: 'schedule', label: 'Schedule' },
  { value: 'apikey', label: 'API Key' },
  { value: 'session', label: 'Session' },
]

const successOptions = [
  { value: '', label: 'All Results' },
  { value: 'true', label: 'Success' },
  { value: 'false', label: 'Failure' },
]

interface AuditFiltersProps {
  action: string
  resourceType: string
  success: string
  onActionChange: (v: string) => void
  onResourceTypeChange: (v: string) => void
  onSuccessChange: (v: string) => void
  onClear: () => void
  hasFilters: boolean
}

export function AuditFilters({
  action,
  resourceType,
  success,
  onActionChange,
  onResourceTypeChange,
  onSuccessChange,
  onClear,
  hasFilters,
}: AuditFiltersProps) {
  return (
    <div className="flex flex-wrap gap-3">
      <Select
        value={action}
        onChange={(e) => onActionChange(e.target.value)}
        options={actionOptions}
        aria-label="Filter by action"
      />
      <Select
        value={resourceType}
        onChange={(e) => onResourceTypeChange(e.target.value)}
        options={resourceOptions}
        aria-label="Filter by resource type"
      />
      <Select
        value={success}
        onChange={(e) => onSuccessChange(e.target.value)}
        options={successOptions}
        aria-label="Filter by result"
      />
      {hasFilters && (
        <Button variant="ghost" size="sm" onClick={onClear} iconLeft={<X className="h-4 w-4" />}>
          Clear
        </Button>
      )}
    </div>
  )
}
