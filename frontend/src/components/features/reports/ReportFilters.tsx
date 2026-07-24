import { Search, X } from 'lucide-react'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Button } from '@/components/ui/Button'

interface ReportFiltersProps {
  search: string
  onSearchChange: (value: string) => void
  sortBy: string
  onSortByChange: (value: string) => void
  sortOrder: string
  onSortOrderChange: (value: string) => void
  onClear: () => void
  hasFilters: boolean
}

export function ReportFilters({
  search,
  onSearchChange,
  sortBy,
  onSortByChange,
  sortOrder,
  onSortOrderChange,
  onClear,
  hasFilters,
}: ReportFiltersProps) {
  return (
    <div className="flex flex-wrap items-center gap-3">
      <div className="flex-1 min-w-[200px] max-w-sm">
        <Input
          placeholder="Search reports..."
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          prefix={<Search className="h-4 w-4 text-text-muted" />}
          aria-label="Search reports"
        />
      </div>
      <Select
        value={sortBy}
        onChange={(e) => onSortByChange(e.target.value)}
        options={[
          { value: 'created_at', label: 'Date' },
          { value: 'target', label: 'Target' },
          { value: 'findings_count', label: 'Findings' },
        ]}
        className="w-32"
        aria-label="Sort by"
      />
      <Select
        value={sortOrder}
        onChange={(e) => onSortOrderChange(e.target.value)}
        options={[
          { value: 'desc', label: 'Newest' },
          { value: 'asc', label: 'Oldest' },
        ]}
        className="w-28"
        aria-label="Sort order"
      />
      {hasFilters && (
        <Button variant="ghost" size="sm" onClick={onClear} iconLeft={<X className="h-4 w-4" />}>
          Clear
        </Button>
      )}
    </div>
  )
}
