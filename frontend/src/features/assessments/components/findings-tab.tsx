import { useState, useMemo } from "react"
import { Search, AlertTriangle } from "lucide-react"
import { SeverityBadge } from "./severity-badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Input } from "@/shared/ui/input"
import { Select } from "@/shared/ui/select"
import type { AssessmentFinding } from "../types"
import { useDebounce } from "@/shared/hooks/use-debounce"

interface FindingsTabProps {
  findings: AssessmentFinding[]
}

const SEVERITY_OPTIONS = [
  { value: "", label: "All Severities" },
  { value: "CRITICAL", label: "Critical" },
  { value: "HIGH", label: "High" },
  { value: "MEDIUM", label: "Medium" },
  { value: "LOW", label: "Low" },
  { value: "INFO", label: "Info" },
] as const

const SORT_OPTIONS = [
  { value: "severity:desc", label: "Severity (High → Low)" },
  { value: "severity:asc", label: "Severity (Low → High)" },
  { value: "title:asc", label: "Title (A → Z)" },
  { value: "title:desc", label: "Title (Z → A)" },
] as const

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
}

function parseSortParam(param: string): { key: string; desc: boolean } {
  const [key, dir] = param.split(":")
  return { key: key ?? "severity", desc: dir !== "asc" }
}

export function FindingsTab({ findings }: FindingsTabProps): React.ReactElement {
  const [search, setSearch] = useState("")
  const [severityFilter, setSeverityFilter] = useState("")
  const [sortBy, setSortBy] = useState("severity:desc")
  const debouncedSearch = useDebounce(search, 300)

  const filtered = useMemo(() => {
    let result = [...findings]

    if (severityFilter) {
      result = result.filter((f) => f.severity === severityFilter)
    }

    if (debouncedSearch) {
      const q = debouncedSearch.toLowerCase()
      result = result.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.finding_id.toLowerCase().includes(q),
      )
    }

    const { key, desc } = parseSortParam(sortBy)
    result.sort((a, b) => {
      let cmp = 0
      if (key === "severity") {
        cmp = (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)
      } else if (key === "title") {
        cmp = a.title.localeCompare(b.title)
      }
      return desc ? -cmp : cmp
    })

    return result
  }, [findings, severityFilter, debouncedSearch, sortBy])

  const grouped = useMemo(() => {
    const groups: Record<string, AssessmentFinding[]> = {}
    for (const f of filtered) {
      const key = f.severity ?? "UNKNOWN"
      if (!groups[key]) groups[key] = []
      groups[key].push(f)
    }
    return groups
  }, [filtered])

  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-12 text-center">
        <AlertTriangle className="size-8 text-[hsl(var(--muted-fg))]" />
        <p className="text-sm text-[hsl(var(--fg-secondary))]">No findings yet.</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-[hsl(var(--muted-fg))]" aria-hidden="true" />
          <Input
            placeholder="Search findings..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
            aria-label="Search findings"
          />
        </div>
        <Select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className="w-40" aria-label="Filter by severity">
          {SEVERITY_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </Select>
        <Select value={sortBy} onChange={(e) => setSortBy(e.target.value)} className="w-52" aria-label="Sort findings">
          {SORT_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </Select>
      </div>

      {/* Results count */}
      <p className="text-sm text-[hsl(var(--fg-secondary))]" aria-live="polite">
        {filtered.length} finding{filtered.length !== 1 ? "s" : ""}
        {severityFilter && ` · ${severityFilter}`}
        {debouncedSearch && ` · matching "${debouncedSearch}"`}
      </p>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="flex flex-col items-center gap-2 py-12 text-center">
          <AlertTriangle className="size-8 text-[hsl(var(--muted-fg))]" />
          <p className="text-sm text-[hsl(var(--fg-secondary))]">No findings match your filters.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-[hsl(var(--border))]">
          <table className="w-full text-sm" role="table" aria-label="Findings">
            <thead>
              <tr className="border-b border-[hsl(var(--border))] bg-[hsl(var(--muted))]/50">
                <th scope="col" className="px-4 py-3 text-left font-medium text-[hsl(var(--muted-fg))]">Title</th>
                <th scope="col" className="px-4 py-3 text-left font-medium text-[hsl(var(--muted-fg))]">Severity</th>
                <th scope="col" className="px-4 py-3 text-left font-medium text-[hsl(var(--muted-fg))]">Status</th>
                <th scope="col" className="px-4 py-3 text-left font-medium text-[hsl(var(--muted-fg))]">Evidence</th>
                <th scope="col" className="px-4 py-3 text-left font-medium text-[hsl(var(--muted-fg))]">Recs</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((finding) => (
                <tr key={finding.finding_id} className="border-b border-[hsl(var(--border))] transition-colors hover:bg-[hsl(var(--accent))]/50">
                  <td className="px-4 py-3 font-medium text-[hsl(var(--fg))]">{finding.title}</td>
                  <td className="px-4 py-3"><SeverityBadge severity={finding.severity} /></td>
                  <td className="px-4 py-3 text-[hsl(var(--fg-secondary))]">{finding.status}</td>
                  <td className="px-4 py-3 text-[hsl(var(--fg-secondary))]">{finding.evidence_count}</td>
                  <td className="px-4 py-3 text-[hsl(var(--fg-secondary))]">{finding.recommendation_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Grouped cards */}
      {filtered.length > 0 && (
        <div className="space-y-4">
          {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const)
            .filter((s) => grouped[s]?.length)
            .map((severity) => (
              <Card key={severity}>
                <CardHeader className="pb-2">
                  <CardTitle className="flex items-center gap-2 text-base">
                    <SeverityBadge severity={severity} />
                    {grouped[severity].length} finding{grouped[severity].length !== 1 ? "s" : ""}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  {grouped[severity].map((f) => (
                    <div key={f.finding_id} className="rounded-lg border border-[hsl(var(--border))] p-3">
                      <div className="flex items-start justify-between">
                        <div>
                          <p className="font-medium text-[hsl(var(--fg))]">{f.title}</p>
                          <p className="mt-1 text-xs text-[hsl(var(--fg-secondary))]">
                            {f.evidence_count} evidence · {f.recommendation_count} recommendations
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            ))}
        </div>
      )}
    </div>
  )
}
