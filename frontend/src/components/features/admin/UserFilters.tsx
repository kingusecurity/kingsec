import { Search, X } from 'lucide-react'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Button } from '@/components/ui/Button'

interface UserFiltersProps {
  search: string
  roleFilter: string
  statusFilter: string
  onSearchChange: (value: string) => void
  onRoleFilterChange: (value: string) => void
  onStatusFilterChange: (value: string) => void
  onClear: () => void
  hasFilters: boolean
}

export function UserFilters({
  search,
  roleFilter,
  statusFilter,
  onSearchChange,
  onRoleFilterChange,
  onStatusFilterChange,
  onClear,
  hasFilters,
}: UserFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
      <div className="flex-1">
        <Input
          placeholder="Search users..."
          prefix={<Search className="h-4 w-4" />}
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          aria-label="Search users"
        />
      </div>
      <div className="w-full sm:w-40">
        <Select
          value={roleFilter}
          onChange={(e) => onRoleFilterChange(e.target.value)}
          aria-label="Filter by role"
          options={[
            { value: '', label: 'All Roles' },
            { value: 'admin', label: 'Admin' },
            { value: 'analyst', label: 'Analyst' },
            { value: 'viewer', label: 'Viewer' },
          ]}
        />
      </div>
      <div className="w-full sm:w-40">
        <Select
          value={statusFilter}
          onChange={(e) => onStatusFilterChange(e.target.value)}
          aria-label="Filter by status"
          options={[
            { value: '', label: 'All Status' },
            { value: 'active', label: 'Active' },
            { value: 'inactive', label: 'Inactive' },
          ]}
        />
      </div>
      {hasFilters && (
        <Button variant="ghost" size="sm" onClick={onClear} aria-label="Clear filters">
          <X className="h-4 w-4 mr-1" />
          Clear
        </Button>
      )}
    </div>
  )
}
