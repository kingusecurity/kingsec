import { Search, X } from 'lucide-react'
import { Input } from '@/components/ui/Input'
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

const severityOptions = [
  { value: '', label: 'All Severities' },
  { value: 'info', label: 'Info' },
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' },
]

const successOptions = [
  { value: '', label: 'All Results' },
  { value: 'true', label: 'Success' },
  { value: 'false', label: 'Failure' },
]

interface AuditFiltersProps {
  search: string
  action: string
  resourceType: string
  severity: string
  success: string
  onSearchChange: (v: string) => void
  onActionChange: (v: string) => void
  onResourceTypeChange: (v: string) => void
  onSeverityChange: (v: string) => void
  onSuccessChange: (v: string) => void
  onClear: () => void
  hasFilters: boolean
}

export function AuditFilters({
  search,
  action,
  resourceType,
  severity,
  success,
  onSearchChange,
  onActionChange,
  onResourceTypeChange,
  onSeverityChange,
  onSuccessChange,
  onClear,
  hasFilters,
}: AuditFiltersProps) {
  return (
    <div className="flex flex-wrap gap-3">
      <div className="min-w-[200px] flex-1">
        <Input
          placeholder="Search audit log..."
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          prefix={<Search className="h-4 w-4" />}
          aria-label="Search audit log"
        />
      </div>
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
        value={severity}
        onChange={(e) => onSeverityChange(e.target.value)}
        options={severityOptions}
        aria-label="Filter by severity"
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
