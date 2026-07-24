import { cn } from '@/lib/utils'

interface TimelineStep {
  label: string
  status: 'completed' | 'current' | 'upcoming' | 'failed' | 'cancelled'
  timestamp?: string
}

interface AssessmentTimelineProps {
  steps: TimelineStep[]
}

const dotColors: Record<string, string> = {
  completed: 'bg-emerald-500',
  current: 'bg-blue-500 ring-2 ring-blue-500/30',
  upcoming: 'bg-gray-600',
  failed: 'bg-red-500',
  cancelled: 'bg-gray-500',
}

const lineColors: Record<string, string> = {
  completed: 'bg-emerald-500/50',
  current: 'bg-gray-700',
  upcoming: 'bg-gray-700',
  failed: 'bg-red-500/50',
  cancelled: 'bg-gray-700',
}

export function AssessmentTimeline({ steps }: AssessmentTimelineProps) {
  return (
    <div className="space-y-0">
      {steps.map((step, i) => {
        const isLast = i === steps.length - 1
        return (
          <div key={step.label} className="flex gap-3">
            <div className="flex flex-col items-center">
              <div className={cn('h-3 w-3 rounded-full shrink-0 mt-1', dotColors[step.status])} />
              {!isLast && <div className={cn('w-0.5 h-8', lineColors[step.status])} />}
            </div>
            <div className="pb-6">
              <p className={cn(
                'text-sm font-medium',
                step.status === 'current' ? 'text-text-primary' :
                step.status === 'completed' ? 'text-text-primary' :
                step.status === 'failed' ? 'text-red-400' :
                step.status === 'cancelled' ? 'text-gray-500' :
                'text-text-muted',
              )}>
                {step.label}
              </p>
              {step.timestamp && (
                <p className="text-xs text-text-muted mt-0.5">{step.timestamp}</p>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}
