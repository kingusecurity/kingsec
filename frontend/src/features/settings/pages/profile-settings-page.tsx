import { useState, useCallback, useEffect } from "react"
import { zodResolver } from "@hookform/resolvers/zod"
import { useForm } from "react-hook-form"
import { Loader2 } from "lucide-react"
import { useProfileSettings, useUpdateProfileSettings } from "../hooks/use-settings"
import { SettingsSection } from "../components/settings-section"
import { UnsavedChangesDialog } from "../components/unsaved-changes-dialog"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { Button } from "@/shared/ui/button"
import { Input } from "@/shared/ui/input"
import { Label } from "@/shared/ui/label"
import { Select } from "@/shared/ui/select"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { profileSchema, type ProfileFormData } from "../validation"
import { getApiError } from "@/shared/api/error-handler"

const TIMEZONES = [
  "UTC",
  "America/New_York",
  "America/Chicago",
  "America/Denver",
  "America/Los_Angeles",
  "Europe/London",
  "Europe/Berlin",
  "Asia/Tokyo",
  "Asia/Shanghai",
  "Australia/Sydney",
]

const LANGUAGES = [
  { value: "en", label: "English" },
  { value: "es", label: "Spanish" },
  { value: "fr", label: "French" },
  { value: "de", label: "German" },
  { value: "ja", label: "Japanese" },
  { value: "zh", label: "Chinese" },
]

export function ProfileSettingsPage(): React.ReactElement {
  const { data: profile, isLoading, error, refetch } = useProfileSettings()
  const updateMutation = useUpdateProfileSettings()
  const [showUnsaved, setShowUnsaved] = useState(false)

  const { register, handleSubmit, reset, formState: { isDirty, errors } } = useForm<ProfileFormData>({
    resolver: zodResolver(profileSchema),
    values: profile ? {
      full_name: profile.full_name ?? "",
      email: profile.email ?? "",
      timezone: profile.timezone ?? "UTC",
      language: profile.language ?? "en",
    } : undefined,
  })

  const onSubmit = useCallback(
    (data: ProfileFormData) => {
      updateMutation.mutate(data, {
        onSuccess: () => reset(data),
      })
    },
    [updateMutation, reset],
  )

  const handleDiscard = useCallback(() => {
    reset()
    setShowUnsaved(false)
  }, [reset])

  if (isLoading || error) {
    return (
      <ErrorBoundary>
        <SettingsSection
          title="Profile"
          description="Manage your personal information."
          isLoading={isLoading}
          error={error ? getApiError(error).detail : null}
          onRetry={refetch}
        />
      </ErrorBoundary>
    )
  }

  return (
    <ErrorBoundary>
      <SettingsSection
        title="Profile"
        description="Manage your personal information."
      >
        <Card>
          <CardContent className="p-6">
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="full_name">Full Name</Label>
                <Input id="full_name" {...register("full_name")} placeholder="John Doe" />
                {errors.full_name && <p className="text-xs text-[hsl(var(--destructive))]">{errors.full_name.message}</p>}
              </div>

              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input id="email" type="email" {...register("email")} placeholder="john@example.com" />
                {errors.email && <p className="text-xs text-[hsl(var(--destructive))]">{errors.email.message}</p>}
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="timezone">Timezone</Label>
                  <Select id="timezone" {...register("timezone")}>
                    {TIMEZONES.map((tz) => (
                      <option key={tz} value={tz}>{tz}</option>
                    ))}
                  </Select>
                  {errors.timezone && <p className="text-xs text-[hsl(var(--destructive))]">{errors.timezone.message}</p>}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="language">Language</Label>
                  <Select id="language" {...register("language")}>
                    {LANGUAGES.map((lang) => (
                      <option key={lang.value} value={lang.value}>{lang.label}</option>
                    ))}
                  </Select>
                  {errors.language && <p className="text-xs text-[hsl(var(--destructive))]">{errors.language.message}</p>}
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                {isDirty && (
                  <Button type="button" variant="outline" onClick={() => setShowUnsaved(true)}>
                    Discard
                  </Button>
                )}
                <Button type="submit" disabled={!isDirty || updateMutation.isPending}>
                  {updateMutation.isPending && <Loader2 className="mr-2 size-4 animate-spin" />}
                  Save Changes
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>

        <UnsavedChangesDialog
          open={showUnsaved}
          onOpenChange={setShowUnsaved}
          onDiscard={handleDiscard}
          onSave={() => { handleSubmit(onSubmit)(); setShowUnsaved(false) }}
        />
      </SettingsSection>
    </ErrorBoundary>
  )
}
