import { useState, useEffect } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import {
  ArrowLeft, ArrowRight, Check, AlertTriangle, Clock,
  Shield, ShieldOff, Cpu, Info,
} from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Textarea } from '@/components/ui/Textarea'
import { Card, CardHeader, CardTitle, CardDescription, CardFooter } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Skeleton } from '@/components/ui/Skeleton'
import { cn } from '@/lib/utils'
import { useProfiles, usePlan } from '@/hooks/use-profiles'
import type { AssessmentProfile, ExecutionPlan } from '@/api/profiles'

const steps = ['Target', 'Profile', 'Authorization', 'Review'] as const

const createSchema = z.object({
  target_value: z.string().min(1, 'Target is required').max(2048),
  target_type: z.enum(['ip_address', 'hostname', 'url', 'network']),
  profile_id: z.string().min(1, 'Please select a profile'),
  authorized_by: z.string().min(1, 'Authorized by is required').max(256),
  scope: z.string().min(1, 'Scope is required').max(2048),
})

export type CreateAssessmentFormData = z.infer<typeof createSchema>

interface CreateAssessmentFormProps {
  onSubmit: (data: CreateAssessmentFormData) => void
  isPending?: boolean
}

const targetTypeLabels: Record<string, string> = {
  ip_address: 'IP Address',
  hostname: 'Hostname',
  url: 'URL',
  network: 'Network',
}

function ProfileCard({
  profile,
  selected,
  onClick,
}: {
  profile: AssessmentProfile
  selected: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'w-full text-left rounded-xl border p-4 transition-all',
        selected
          ? 'border-accent bg-accent/5 ring-1 ring-accent'
          : 'border-border-light bg-surface-secondary hover:border-gray-500',
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div>
          <h4 className="text-sm font-semibold text-text-primary">{profile.name}</h4>
          <p className="mt-1 text-xs text-text-secondary line-clamp-2">{profile.description}</p>
        </div>
        {selected && (
          <div className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent">
            <Check className="h-3 w-3 text-white" />
          </div>
        )}
      </div>
      <div className="mt-3 flex flex-wrap gap-1.5">
        <Badge variant="info" size="sm">
          <Clock className="mr-1 h-3 w-3" />
          {profile.estimated_duration_minutes}m
        </Badge>
        <Badge variant="neutral" size="sm">
          <Cpu className="mr-1 h-3 w-3" />
          {profile.scanners.length} scanners
        </Badge>
        {profile.tags.slice(0, 3).map((tag) => (
          <Badge key={tag} variant="success" size="sm">{tag}</Badge>
        ))}
      </div>
    </button>
  )
}

function PlanSummary({ plan }: { plan: ExecutionPlan }) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium text-text-primary">Execution Plan</span>
        {plan.can_proceed
          ? <Badge variant="success" size="sm">Ready</Badge>
          : <Badge variant="critical" size="sm">Blocked</Badge>
        }
      </div>

      <div className="flex items-center gap-4 text-xs text-text-muted">
        <span className="flex items-center gap-1">
          <Check className="h-3.5 w-3.5 text-emerald-400" />
          {plan.selected_scanners.length} selected
        </span>
        {plan.skipped_scanners.length > 0 && (
          <span className="flex items-center gap-1">
            <AlertTriangle className="h-3.5 w-3.5 text-yellow-400" />
            {plan.skipped_scanners.length} skipped
          </span>
        )}
        {plan.unavailable_scanners.length > 0 && (
          <span className="flex items-center gap-1">
            <ShieldOff className="h-3.5 w-3.5 text-red-400" />
            {plan.unavailable_scanners.length} unavailable
          </span>
        )}
        <span className="flex items-center gap-1">
          <Clock className="h-3.5 w-3.5" />
          ~{plan.estimated_duration_minutes} min
        </span>
      </div>

      {plan.selected_scanners.length > 0 && (
        <div>
          <p className="text-xs font-medium text-text-secondary mb-1.5">Selected Scanners</p>
          <div className="flex flex-wrap gap-1.5">
            {plan.selected_scanners.map((s) => (
              <Badge key={s.scanner_id} variant="success" size="sm">{s.name}</Badge>
            ))}
          </div>
        </div>
      )}

      {plan.skipped_scanners.length > 0 && (
        <div>
          <p className="text-xs font-medium text-text-secondary mb-1.5">Skipped (optional scanners unavailable)</p>
          <div className="space-y-1">
            {plan.skipped_scanners.map((s) => (
              <div key={s.scanner_id} className="flex items-center gap-2 text-xs text-yellow-300">
                <AlertTriangle className="h-3 w-3 shrink-0" />
                <span>{s.name}: {s.reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {plan.unavailable_scanners.length > 0 && (
        <div className="rounded-lg bg-red-900/20 p-2.5">
          <p className="text-xs font-medium text-red-300 mb-1">Required scanners unavailable</p>
          {plan.unavailable_scanners.map((s) => (
            <div key={s.scanner_id} className="flex items-start gap-2 text-xs text-red-300 mt-1">
              <ShieldOff className="h-3 w-3 shrink-0 mt-0.5" />
              <span>{s.name}: {s.reason}</span>
            </div>
          ))}
        </div>
      )}

      {plan.warnings.map((w, i) => (
        <div key={i} className="flex items-start gap-2 text-xs text-yellow-300">
          <Info className="h-3 w-3 shrink-0 mt-0.5" />
          <span>{w}</span>
        </div>
      ))}
    </div>
  )
}

export function CreateAssessmentForm({ onSubmit, isPending }: CreateAssessmentFormProps) {
  const [step, setStep] = useState(0)
  const { data: profiles, isLoading: profilesLoading } = useProfiles()
  const planMutation = usePlan()
  const [currentPlan, setCurrentPlan] = useState<ExecutionPlan | null>(null)
  const [planRequested, setPlanRequested] = useState(false)

  const form = useForm<CreateAssessmentFormData>({
    resolver: zodResolver(createSchema),
    defaultValues: {
      target_type: 'ip_address',
      target_value: '',
      profile_id: '',
      authorized_by: '',
      scope: '',
    },
  })

  const { register, handleSubmit, trigger, watch, setValue, formState: { errors } } = form
  const values = watch()

  // Auto-generate plan when profile is selected and target is set
  useEffect(() => {
    if (values.profile_id && values.target_value && values.target_type && planRequested) {
      planMutation.mutate(
        { profileId: values.profile_id, body: { target: values.target_value, target_type: values.target_type } },
        { onSuccess: (data) => setCurrentPlan(data) },
      )
    }
  }, [values.profile_id, values.target_value, values.target_type, planRequested])

  const handleNext = async () => {
    let valid = false
    if (step === 0) valid = await trigger(['target_value', 'target_type'])
    else if (step === 1) {
      valid = await trigger(['profile_id'])
      if (valid && !planRequested) {
        setPlanRequested(true)
      }
    } else if (step === 2) valid = await trigger(['authorized_by', 'scope'])
    if (valid) setStep((s) => Math.min(s + 1, steps.length - 1))
  }

  const handleBack = () => {
    setStep((s) => Math.max(s - 1, 0))
  }

  const compatibleProfiles = (profiles ?? []).filter((p) =>
    p.supported_target_types.includes(values.target_type),
  )

  const onFormSubmit = handleSubmit(onSubmit)

  return (
    <form onSubmit={onFormSubmit} className="space-y-6">
      <div className="flex items-center gap-2 overflow-x-auto pb-1">
        {steps.map((label, i) => (
          <div key={label} className="flex items-center gap-2 shrink-0">
            <div className={`flex h-8 w-8 items-center justify-center rounded-full text-xs font-medium ${
              i < step ? 'bg-accent text-white' :
              i === step ? 'bg-accent/20 text-accent border border-accent' :
              'bg-surface-tertiary text-text-muted'
            }`}>
              {i < step ? <Check className="h-4 w-4" /> : i + 1}
            </div>
            <span className={`text-sm whitespace-nowrap ${i === step ? 'text-text-primary font-medium' : 'text-text-muted'}`}>
              {label}
            </span>
            {i < steps.length - 1 && <div className="w-8 h-px bg-border mx-1" />}
          </div>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{steps[step]}</CardTitle>
          <CardDescription>
            {step === 0 && 'Enter the target and type for the security assessment'}
            {step === 1 && 'Select an assessment profile that matches your goal'}
            {step === 2 && 'Provide authorization and scope information'}
            {step === 3 && 'Review the assessment details before submitting'}
          </CardDescription>
        </CardHeader>

        <div className="px-5 py-4 space-y-4">
          {step === 0 && (
            <>
              <div>
                <label className="block text-sm font-medium text-text-primary mb-1.5">Target</label>
                <Input {...register('target_value')} placeholder="10.0.0.5" />
                {errors.target_value && <p className="mt-1 text-xs text-red-400">{errors.target_value.message}</p>}
              </div>
              <div>
                <label className="block text-sm font-medium text-text-primary mb-1.5">Target Type</label>
                <Select
                  {...register('target_type')}
                  options={[
                    { value: 'ip_address', label: 'IP Address' },
                    { value: 'hostname', label: 'Hostname' },
                    { value: 'url', label: 'URL' },
                    { value: 'network', label: 'Network' },
                  ]}
                />
              </div>
            </>
          )}

          {step === 1 && (
            <>
              {profilesLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <Skeleton key={i} className="h-28 w-full rounded-xl" />
                  ))}
                </div>
              ) : compatibleProfiles.length === 0 ? (
                <p className="text-sm text-text-muted py-4 text-center">
                  No profiles available for target type "{targetTypeLabels[values.target_type]}"
                </p>
              ) : (
                <div className="space-y-2 max-h-[400px] overflow-y-auto pr-1">
                  {compatibleProfiles.map((profile) => (
                    <ProfileCard
                      key={profile.id}
                      profile={profile}
                      selected={values.profile_id === profile.id}
                      onClick={() => {
                        setValue('profile_id', profile.id, { shouldValidate: true })
                        setPlanRequested(false)
                        setCurrentPlan(null)
                      }}
                    />
                  ))}
                </div>
              )}

              {values.profile_id && currentPlan && (
                <div className="border-t border-border pt-4 mt-2">
                  <PlanSummary plan={currentPlan} />
                </div>
              )}

              {values.profile_id && planMutation.isPending && (
                <div className="flex items-center gap-2 text-sm text-text-muted py-2">
                  <Skeleton className="h-4 w-4 rounded-full" />
                  Generating plan...
                </div>
              )}
            </>
          )}

          {step === 2 && (
            <>
              <div>
                <label className="block text-sm font-medium text-text-primary mb-1.5">Authorized By</label>
                <Input {...register('authorized_by')} placeholder="admin@company.com" />
                {errors.authorized_by && <p className="mt-1 text-xs text-red-400">{errors.authorized_by.message}</p>}
              </div>
              <div>
                <label className="block text-sm font-medium text-text-primary mb-1.5">Scope</label>
                <Textarea {...register('scope')} placeholder="10.0.0.0/24" rows={3} />
                {errors.scope && <p className="mt-1 text-xs text-red-400">{errors.scope.message}</p>}
              </div>
            </>
          )}

          {step === 3 && (
            <div className="space-y-4">
              <div className="space-y-3 rounded-lg bg-surface-tertiary/50 p-4">
                <Row label="Target" value={values.target_value} />
                <Row label="Type" value={targetTypeLabels[values.target_type]} />
                {currentPlan && (
                  <Row
                    label="Profile"
                    value={`${currentPlan.profile_name} (~${currentPlan.estimated_duration_minutes} min)`}
                  />
                )}
                <Row label="Authorized By" value={values.authorized_by} />
                <Row label="Scope" value={values.scope} />
              </div>

              {currentPlan && (
                <div className="rounded-lg bg-surface-tertiary/50 p-4">
                  <PlanSummary plan={currentPlan} />
                </div>
              )}
            </div>
          )}
        </div>

        <CardFooter>
          {step > 0 && (
            <Button type="button" variant="ghost" onClick={handleBack} iconLeft={<ArrowLeft className="h-4 w-4" />}>
              Back
            </Button>
          )}
          <div className="flex-1" />
          {step < steps.length - 1 ? (
            <Button type="button" onClick={handleNext} iconRight={<ArrowRight className="h-4 w-4" />}>
              {step === 1 ? 'Review Plan' : 'Next'}
            </Button>
          ) : (
            <Button type="submit" loading={isPending} iconRight={<Check className="h-4 w-4" />}>
              Create Assessment
            </Button>
          )}
        </CardFooter>
      </Card>
    </form>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between">
      <span className="text-sm text-text-secondary">{label}</span>
      <span className="text-sm text-text-primary font-medium">{value}</span>
    </div>
  )
}
