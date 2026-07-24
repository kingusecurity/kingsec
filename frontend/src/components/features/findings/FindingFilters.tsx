import { Search, X } from 'lucide-react'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Button } from '@/components/ui/Button'

interface FindingFiltersProps {
  search: string
  onSearchChange: (value: string) => void
  severityFilter: string
  onSeverityFilterChange: (value: string) => void
  statusFilter: string
  onStatusFilterChange: (value: string) => void
  onClear: () => void
  hasFilters: boolean
}

export function FindingFilters({
  search,
  onSearchChange,
  severityFilter,
  onSeverityFilterChange,
  statusFilter,
  onStatusFilterChange,
  onClear,
  hasFilters,
}: FindingFiltersProps) {
  return (
    <div className="flex flex-wrap items-center gap-3">
      <div className="flex-1 min-w-[200px] max-w-sm">
        <Input
          placeholder="Search findings..."
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          prefix={<Search className="h-4 w-4 text-text-muted" />}
          aria-label="Search findings"
        />
      </div>
      <Select
        value={severityFilter}
        onChange={(e) => onSeverityFilterChange(e.target.value)}
        options={[
          { value: '', label: 'All Severities' },
          { value: 'critical', label: 'Critical' },
          { value: 'high', label: 'High' },
          { value: 'medium', label: 'Medium' },
          { value: 'low', label: 'Low' },
        ]}
        className="w-36"
        aria-label="Filter by severity"
      />
      <Select
        value={statusFilter}
        onChange={(e) => onStatusFilterChange(e.target.value)}
        options={[
          { value: '', label: 'All Statuses' },
          { value: 'open', label: 'Open' },
          { value: 'confirmed', label: 'Confirmed' },
          { value: 'false_positive', label: 'False Positive' },
          { value: 'remediated', label: 'Remediated' },
        ]}
        className="w-36"
        aria-label="Filter by status"
      />
      {hasFilters && (
        <Button variant="ghost" size="sm" onClick={onClear} iconLeft={<X className="h-4 w-4" />}>
          Clear
        </Button>
      )}
    </div>
  )
}
