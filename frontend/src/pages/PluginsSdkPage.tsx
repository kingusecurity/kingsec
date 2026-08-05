import { useState } from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Card } from '@/components/ui/Card'
import { Spinner } from '@/components/ui/Spinner'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { useSdkPlugins, useScanPlugins, useLoadPlugin, useUnloadPlugin } from '@/hooks/use-plugin-sdk'

const typeColors: Record<string, string> = {
  scanner: 'bg-blue-100 text-blue-800',
  ai: 'bg-purple-100 text-purple-800',
  report: 'bg-green-100 text-green-800',
  integration: 'bg-cyan-100 text-cyan-800',
  export: 'bg-teal-100 text-teal-800',
  notification: 'bg-pink-100 text-pink-800',
  dashboard_widget: 'bg-indigo-100 text-indigo-800',
  compliance: 'bg-amber-100 text-amber-800',
  threat_feed: 'bg-red-100 text-red-800',
  automation_action: 'bg-orange-100 text-orange-800',
}

export function PluginsSdkPage() {
  const [typeFilter, setTypeFilter] = useState('')
  const { data, isLoading } = useSdkPlugins(typeFilter || undefined)
  const scanPlugins = useScanPlugins()
  const loadPlugin = useLoadPlugin()
  const unloadPlugin = useUnloadPlugin()

  const plugins = data?.plugins ?? []

  return (
    <PageContainer>
      <PageHeader
        title="Plugin SDK & Extensions"
        description="Extend KingSec with custom plugins"
        actions={
          <div className="flex gap-2">
            <Button onClick={() => scanPlugins.mutate()} variant="outline" disabled={scanPlugins.isPending}>
              {scanPlugins.isPending ? 'Scanning...' : 'Scan Directory'}
            </Button>
          </div>
        }
      />

      {/* The Marketplace tab was removed: it had no install/configure/detail
          action on any card - browsing only, no way to act on what you see.
          See docs/audits/dead-button-audit-2026-08.md. */}

      {/* Type filter */}
      <div className="mb-4 flex flex-wrap gap-2">
        <button
          onClick={() => setTypeFilter('')}
          className={`rounded px-2 py-1 text-xs ${!typeFilter ? 'bg-primary-600 text-white' : 'bg-gray-100 text-gray-600'}`}
        >All</button>
        {Object.entries(typeColors).map(([key, cls]) => (
          <button
            key={key}
            onClick={() => setTypeFilter(typeFilter === key ? '' : key)}
            className={`rounded px-2 py-1 text-xs ${typeFilter === key ? cls : 'bg-gray-100 text-gray-600'}`}
          >{key.replace('_', ' ')}</button>
        ))}
      </div>

      {isLoading ? (
        <div className="flex justify-center py-16"><Spinner /></div>
      ) : plugins.length === 0 ? (
        <Card><div className="p-8 text-center text-text-muted">No plugins found. Scan the plugins directory to find installable plugins.</div></Card>
      ) : (
        <div className="space-y-3">
          {plugins.map((p) => (
            <Card key={p.id}>
              <div className="flex items-center justify-between p-4">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold text-text-primary">{p.name}</h3>
                    <Badge className={typeColors[p.type] ?? ''}>{p.type.replace('_', ' ')}</Badge>
                    <Badge className={p.loaded ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-600'}>
                      {p.loaded ? 'Loaded' : 'Unloaded'}
                    </Badge>
                  </div>
                  <p className="mt-1 text-sm text-text-muted">v{p.version} &middot; {p.id}</p>
                  {p.permissions.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {p.permissions.map((perm) => (
                        <span key={perm} className="rounded bg-gray-100 px-1.5 py-0.5 text-[10px] text-text-muted">{perm}</span>
                      ))}
                    </div>
                  )}
                  {p.error && <p className="mt-1 text-xs text-red-500">{p.error}</p>}
                </div>
                <div className="flex items-center gap-2">
                  {p.loaded ? (
                    <Button onClick={() => unloadPlugin.mutate(p.id)} variant="outline" size="sm">Unload</Button>
                  ) : (
                    <Button onClick={() => loadPlugin.mutate(p.id)} size="sm">Load</Button>
                  )}
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </PageContainer>
  )
}
