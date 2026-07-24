import { Search, X } from 'lucide-react'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Button } from '@/components/ui/Button'

interface AssessmentFiltersProps {
  search: string
  onSearchChange: (value: string) => void
  statusFilter: string
  onStatusFilterChange: (value: string) => void
  sortBy: string
  onSortByChange: (value: string) => void
  sortOrder: string
  onSortOrderChange: (value: string) => void
  onClear: () => void
  hasFilters: boolean
}

export function AssessmentFilters({
  search,
  onSearchChange,
  statusFilter,
  onStatusFilterChange,
  sortBy,
  onSortByChange,
  sortOrder,
  onSortOrderChange,
  onClear,
  hasFilters,
}: AssessmentFiltersProps) {
  return (
    <div className="flex flex-wrap items-center gap-3">
      <div className="flex-1 min-w-[200px] max-w-sm">
        <Input
          placeholder="Search assessments..."
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          prefix={<Search className="h-4 w-4 text-text-muted" />}
        />
      </div>
      <Select
        value={statusFilter}
        onChange={(e) => onStatusFilterChange(e.target.value)}
        options={[
          { value: '', label: 'All Status' },
          { value: 'draft', label: 'Draft' },
          { value: 'pending', label: 'Pending' },
          { value: 'running', label: 'Running' },
          { value: 'completed', label: 'Completed' },
          { value: 'failed', label: 'Failed' },
          { value: 'cancelled', label: 'Cancelled' },
        ]}
        className="w-36"
      />
      <Select
        value={sortBy}
        onChange={(e) => onSortByChange(e.target.value)}
        options={[
          { value: 'created_at', label: 'Created' },
          { value: 'target', label: 'Target' },
          { value: 'status', label: 'Status' },
          { value: 'findings_count', label: 'Findings' },
        ]}
        className="w-36"
      />
      <Select
        value={sortOrder}
        onChange={(e) => onSortOrderChange(e.target.value)}
        options={[
          { value: 'desc', label: 'Newest' },
          { value: 'asc', label: 'Oldest' },
        ]}
        className="w-28"
      />
      {hasFilters && (
        <Button variant="ghost" size="sm" onClick={onClear} iconLeft={<X className="h-4 w-4" />}>
          Clear
        </Button>
      )}
    </div>
  )
}
