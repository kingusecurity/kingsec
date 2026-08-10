import { useEffect, useState } from 'react'
import { CheckCircle, HelpCircle, RefreshCw, ServerCog } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Badge } from '@/components/ui/Badge'
import { Skeleton } from '@/components/ui/Skeleton'
import { toast } from '@/components/ui/Toast'
import { useAIProviderConfig, useSaveAIProviderConfig, useTestAIProviderConfig } from '@/hooks/use-ai-provider'

const PROVIDER_OPTIONS = [
  { value: 'anthropic', label: 'Anthropic (Claude)' },
  { value: 'openai', label: 'OpenAI' },
  { value: 'openrouter', label: 'OpenRouter' },
  { value: 'glm', label: 'GLM (Zhipu AI)' },
  { value: 'gemini', label: 'Google Gemini' },
  { value: 'ollama', label: 'Ollama (local)' },
  { value: 'lm_studio', label: 'LM Studio (local)' },
]

export function AiProviderSection() {
  const { data, isLoading, error, refetch } = useAIProviderConfig()
  const saveMutation = useSaveAIProviderConfig()
  const testMutation = useTestAIProviderConfig()

  const [provider, setProvider] = useState('anthropic')
  const [apiKeyInput, setApiKeyInput] = useState('')
  const [isChangingKey, setIsChangingKey] = useState(false)
  const [model, setModel] = useState('')
  const [baseUrl, setBaseUrl] = useState('')

  // Seed the form from the loaded config exactly once per load - after
  // that, the form is the user's own in-progress edits, not something we
  // want to silently overwrite mid-edit on a background refetch.
  useEffect(() => {
    if (!data) return
    setProvider(data.provider)
    setModel(data.model ?? '')
    setBaseUrl(data.base_url ?? '')
  }, [data?.provider, data?.model, data?.base_url]) // eslint-disable-line react-hooks/exhaustive-deps

  const handleSave = async () => {
    try {
      await saveMutation.mutateAsync({
        provider,
        api_key: isChangingKey && apiKeyInput ? apiKeyInput : undefined,
        model: model || undefined,
        base_url: baseUrl || undefined,
      })
      toast.success('AI provider settings saved', 'Changes take effect immediately — no restart needed.')
      setApiKeyInput('')
      setIsChangingKey(false)
    } catch (err) {
      toast.error('Failed to save', err instanceof Error ? err.message : 'Unknown error')
    }
  }

  const handleTest = async () => {
    if (!apiKeyInput) {
      toast.warning('Enter a key to test', 'Test Connection checks the key you type here, not the one already saved.')
      return
    }
    try {
      const result = await testMutation.mutateAsync({
        provider,
        api_key: apiKeyInput,
        model: model || undefined,
        base_url: baseUrl || undefined,
      })
      if (result.success) {
        toast.success('Connection successful', result.message)
      } else {
        toast.warning('Connection failed', result.message)
      }
    } catch (err) {
      toast.error('Test failed', err instanceof Error ? err.message : 'Unknown error')
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <h2 className="text-lg font-semibold text-text-primary">AI Provider</h2>
        <Skeleton className="h-64 w-full rounded-lg" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-4">
        <h2 className="text-lg font-semibold text-text-primary">AI Provider</h2>
        <div className="rounded-lg bg-red-900/20 p-4 text-sm text-red-300">Failed to load AI provider settings</div>
      </div>
    )
  }

  const source = data?.source ?? 'none'
  const sourceBadge =
    source === 'database' ? (
      <Badge variant="success" size="sm" className="flex items-center gap-1">
        <CheckCircle className="h-3 w-3" />
        Configured via Settings
      </Badge>
    ) : source === 'environment' ? (
      <Badge variant="info" size="sm" className="flex items-center gap-1">
        <ServerCog className="h-3 w-3" />
        Configured via environment variable
      </Badge>
    ) : (
      <Badge variant="neutral" size="sm" className="flex items-center gap-1">
        <HelpCircle className="h-3 w-3" />
        Not Configured
      </Badge>
    )

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold text-text-primary">AI Provider</h2>
        <p className="text-sm text-text-muted">
          Configure the AI provider used for finding explanations, business-impact analysis, and remediation
          suggestions in reports. Bring your own API key — nothing is sent anywhere until you configure one.
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Provider Configuration</CardTitle>
              <CardDescription>Saved here overrides any KINGSEC_AI__* environment variables.</CardDescription>
            </div>
            {sourceBadge}
          </div>
        </CardHeader>
        <div className="p-5 space-y-4">
          <Select
            label="Provider"
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
            options={PROVIDER_OPTIONS}
          />

          <div>
            <label className="block text-sm font-medium text-text-secondary mb-1.5">API Key</label>
            {!isChangingKey ? (
              <div className="flex items-center gap-2">
                <Input
                  value={data?.api_key_masked ?? ''}
                  placeholder="No key configured"
                  disabled
                  className="font-mono"
                />
                <Button variant="outline" size="sm" onClick={() => setIsChangingKey(true)}>
                  Change
                </Button>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <Input
                  type="password"
                  value={apiKeyInput}
                  onChange={(e) => setApiKeyInput(e.target.value)}
                  placeholder="Paste new API key"
                  autoFocus
                  className="font-mono"
                />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setIsChangingKey(false)
                    setApiKeyInput('')
                  }}
                >
                  Cancel
                </Button>
              </div>
            )}
            <p className="mt-1.5 text-xs text-text-muted">
              The key is encrypted at rest and never shown again after saving — only the last 4 characters are
              displayed.
            </p>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <Input
              label="Model"
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder={data?.effective_model || 'Provider default'}
              helperText={`Optional — leave blank to use ${data?.effective_model ?? 'the provider default'}.`}
            />
            <Input
              label="Base URL"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://api.example.com"
              helperText="Optional — for self-hosted or custom endpoints (Ollama, LM Studio, proxies)."
            />
          </div>

          <div className="flex items-center gap-2 pt-2">
            <Button
              variant="outline"
              onClick={handleTest}
              disabled={testMutation.isPending || !apiKeyInput}
              iconLeft={testMutation.isPending ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : undefined}
            >
              {testMutation.isPending ? 'Testing...' : 'Test Connection'}
            </Button>
            <Button onClick={handleSave} loading={saveMutation.isPending}>
              Save
            </Button>
            <Button variant="ghost" size="sm" onClick={() => refetch()}>
              Refresh
            </Button>
          </div>
        </div>
      </Card>
    </div>
  )
}
