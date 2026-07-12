import { useCallback } from "react"
import { zodResolver } from "@hookform/resolvers/zod"
import { useForm } from "react-hook-form"
import { Loader2 } from "lucide-react"
import { useScannerSettings } from "../hooks/use-local-settings"
import { SettingsSection } from "../components/settings-section"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { Card, CardContent } from "@/shared/ui/card"
import { Label } from "@/shared/ui/label"
import { Input } from "@/shared/ui/input"
import { Select } from "@/shared/ui/select"
import { Button } from "@/shared/ui/button"
import { scannerSchema, type ScannerFormData } from "../validation"

const SCAN_PROFILES = [
  { value: "quick", label: "Quick Scan" },
  { value: "full", label: "Full Scan" },
  { value: "stealth", label: "Stealth Scan" },
  { value: "custom", label: "Custom" },
]

export function ScannerSettingsPage(): React.ReactElement {
  const { settings, update } = useScannerSettings()

  const { register, handleSubmit, formState: { isDirty, errors } } = useForm<ScannerFormData>({
    resolver: zodResolver(scannerSchema),
    values: settings,
  })

  const onSubmit = useCallback(
    (data: ScannerFormData) => {
      update(data)
    },
    [update],
  )

  return (
    <ErrorBoundary>
      <SettingsSection
        title="Scanner Settings"
        description="Configure default scan behavior."
        onSave={handleSubmit(onSubmit)}
        saveDisabled={!isDirty}
      >
        <Card>
          <CardContent className="p-6 space-y-4">
            <div className="space-y-2">
              <Label htmlFor="default_scan_profile">Default Scan Profile</Label>
              <Select id="default_scan_profile" {...register("default_scan_profile")}>
                {SCAN_PROFILES.map((p) => (
                  <option key={p.value} value={p.value}>{p.label}</option>
                ))}
              </Select>
              {errors.default_scan_profile && <p className="text-xs text-[hsl(var(--destructive))]">{errors.default_scan_profile.message}</p>}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="timeout_seconds">Timeout (seconds)</Label>
                <Input id="timeout_seconds" type="number" {...register("timeout_seconds", { valueAsNumber: true })} />
                {errors.timeout_seconds && <p className="text-xs text-[hsl(var(--destructive))]">{errors.timeout_seconds.message}</p>}
              </div>
              <div className="space-y-2">
                <Label htmlFor="concurrent_jobs">Concurrent Jobs</Label>
                <Input id="concurrent_jobs" type="number" {...register("concurrent_jobs", { valueAsNumber: true })} />
                {errors.concurrent_jobs && <p className="text-xs text-[hsl(var(--destructive))]">{errors.concurrent_jobs.message}</p>}
              </div>
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label htmlFor="auto_generate_report">Auto Generate Report</Label>
                <p className="text-xs text-[hsl(var(--muted-fg))]">
                  Automatically generate a report after scan completion.
                </p>
              </div>
              <input
                id="auto_generate_report"
                type="checkbox"
                {...register("auto_generate_report")}
                className="size-4 rounded border-[hsl(var(--border))] accent-[hsl(var(--primary))]"
              />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label htmlFor="auto_delete_reports">Auto Delete Reports</Label>
                <p className="text-xs text-[hsl(var(--muted-fg))]">
                  Automatically delete reports after 30 days.
                </p>
              </div>
              <input
                id="auto_delete_reports"
                type="checkbox"
                {...register("auto_delete_reports")}
                className="size-4 rounded border-[hsl(var(--border))] accent-[hsl(var(--primary))]"
              />
            </div>
          </CardContent>
        </Card>
      </SettingsSection>
    </ErrorBoundary>
  )
}
