import { useState, useCallback } from "react"
import { zodResolver } from "@hookform/resolvers/zod"
import { useForm } from "react-hook-form"
import { Loader2, Plus, Copy, Check, Trash2, Key } from "lucide-react"
import { useApiKeys, useGenerateApiKey, useRevokeApiKey } from "../hooks/use-settings"
import { SettingsSection } from "../components/settings-section"
import { SettingsPlaceholder } from "../components/settings-placeholder"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { ConfirmDialog } from "@/shared/components/confirm-dialog"
import { Button } from "@/shared/ui/button"
import { Input } from "@/shared/ui/input"
import { Label } from "@/shared/ui/label"
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card"
import { Badge } from "@/shared/ui/badge"
import { apiKeySchema, type ApiKeyFormData } from "../validation"
import { formatDate, formatRelative } from "@/shared/lib/utils"
import { getApiError } from "@/shared/api/error-handler"

export function ApiKeysSettingsPage(): React.ReactElement {
  const { data: keys, isLoading, error, refetch } = useApiKeys()
  const generateMutation = useGenerateApiKey()
  const revokeMutation = useRevokeApiKey()
  const [showGenerate, setShowGenerate] = useState(false)
  const [showRevokeConfirm, setShowRevokeConfirm] = useState<string | null>(null)
  const [generatedKey, setGeneratedKey] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const { register, handleSubmit, reset, formState: { errors } } = useForm<ApiKeyFormData>({
    resolver: zodResolver(apiKeySchema),
  })

  const onGenerate = useCallback(
    (data: ApiKeyFormData) => {
      generateMutation.mutate(data.name, {
        onSuccess: (result) => {
          if (result?.raw_key) {
            setGeneratedKey(result.raw_key)
          }
          reset()
          setShowGenerate(false)
        },
      })
    },
    [generateMutation, reset],
  )

  const handleCopy = useCallback(() => {
    if (generatedKey) {
      navigator.clipboard.writeText(generatedKey)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }, [generatedKey])

  const handleRevoke = useCallback(() => {
    if (showRevokeConfirm) {
      revokeMutation.mutate(showRevokeConfirm, {
        onSuccess: () => setShowRevokeConfirm(null),
      })
    }
  }, [showRevokeConfirm, revokeMutation])

  return (
    <ErrorBoundary>
      <SettingsSection
        title="API Keys"
        description="Manage API keys for programmatic access."
      >
        <Card>
          <CardContent className="p-6">
            {isLoading || error ? (
              <SettingsPlaceholder
                title="API Key Management"
                description="API key management will be available when the backend supports it."
                isLoading={isLoading}
                error={error ? getApiError(error).detail : null}
                onRetry={refetch}
              />
            ) : (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <p className="text-sm text-[hsl(var(--muted-fg))]">
                    {keys?.length ?? 0} key(s) configured
                  </p>
                  <Button size="sm" onClick={() => setShowGenerate(true)}>
                    <Plus className="mr-2 size-4" />
                    Generate Key
                  </Button>
                </div>

                {generatedKey && (
                  <div className="rounded-lg border border-[hsl(var(--success))]/20 bg-[hsl(var(--success))]/5 p-4">
                    <div className="flex items-center justify-between">
                      <div className="space-y-1">
                        <p className="text-sm font-medium text-[hsl(var(--fg))]">New API Key</p>
                        <p className="font-mono text-xs text-[hsl(var(--muted-fg))] break-all">{generatedKey}</p>
                      </div>
                      <Button variant="outline" size="sm" onClick={handleCopy}>
                        {copied ? <Check className="mr-1 size-4" /> : <Copy className="mr-1 size-4" />}
                        {copied ? "Copied" : "Copy"}
                      </Button>
                    </div>
                    <p className="mt-2 text-xs text-[hsl(var(--destructive))]">
                      Copy this key now. It will not be shown again.
                    </p>
                  </div>
                )}

                {keys && keys.length > 0 ? (
                  <div className="space-y-2">
                    {keys.map((key) => (
                      <div
                        key={key.key_id}
                        className="flex items-center justify-between rounded-lg border border-[hsl(var(--border))] p-3"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <p className="text-sm font-medium text-[hsl(var(--fg))]">{key.name}</p>
                            <Badge variant="secondary">{key.key_prefix}...</Badge>
                          </div>
                          <p className="text-xs text-[hsl(var(--muted-fg))]">
                            Created {formatRelative(key.created_at)}
                            {key.last_used_at && <> · Last used {formatRelative(key.last_used_at)}</>}
                          </p>
                        </div>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setShowRevokeConfirm(key.key_id)}
                        >
                          <Trash2 className="size-4 text-[hsl(var(--destructive))]" />
                        </Button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex flex-col items-center gap-2 py-8 text-center">
                    <Key className="size-8 text-[hsl(var(--muted-fg))]" />
                    <p className="text-sm text-[hsl(var(--muted-fg))]">No API keys configured.</p>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        <ConfirmDialog
          open={showGenerate}
          onOpenChange={setShowGenerate}
          title="Generate API Key"
          description="Create a new API key for programmatic access."
          confirmLabel="Generate"
          onConfirm={handleSubmit(onGenerate)}
          loading={generateMutation.isPending}
        >
          <div className="mt-4 space-y-2">
            <Label htmlFor="key-name">Key Name</Label>
            <Input id="key-name" {...register("name")} placeholder="my-api-key" />
            {errors.name && <p className="text-xs text-[hsl(var(--destructive))]">{errors.name.message}</p>}
          </div>
        </ConfirmDialog>

        <ConfirmDialog
          open={!!showRevokeConfirm}
          onOpenChange={(open) => { if (!open) setShowRevokeConfirm(null) }}
          title="Revoke API Key"
          description="This action cannot be undone. The key will be immediately disabled."
          confirmLabel="Revoke"
          onConfirm={handleRevoke}
          variant="destructive"
          loading={revokeMutation.isPending}
        />
      </SettingsSection>
    </ErrorBoundary>
  )
}
