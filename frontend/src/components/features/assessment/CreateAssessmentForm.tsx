import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { ArrowLeft, ArrowRight, Check } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Textarea } from '@/components/ui/Textarea'
import { Card, CardHeader, CardTitle, CardDescription, CardFooter } from '@/components/ui/Card'

const steps = ['Target', 'Authorization', 'Review'] as const

const createSchema = z.object({
  target_value: z.string().min(1, 'Target is required').max(2048),
  target_type: z.enum(['ip_address', 'hostname', 'url', 'network']),
  authorized_by: z.string().min(1, 'Authorized by is required').max(256),
  scope: z.string().min(1, 'Scope is required').max(2048),
})

export type CreateAssessmentFormData = z.infer<typeof createSchema>

interface CreateAssessmentFormProps {
  onSubmit: (data: CreateAssessmentFormData) => void
  isPending?: boolean
}

export function CreateAssessmentForm({ onSubmit, isPending }: CreateAssessmentFormProps) {
  const [step, setStep] = useState(0)
  const form = useForm<CreateAssessmentFormData>({
    resolver: zodResolver(createSchema),
    defaultValues: { target_type: 'ip_address', target_value: '', authorized_by: '', scope: '' },
  })
  const { register, handleSubmit, trigger, watch, formState: { errors } } = form
  const values = watch()

  const handleNext = async () => {
    let valid = false
    if (step === 0) valid = await trigger(['target_value', 'target_type'])
    else if (step === 1) valid = await trigger(['authorized_by', 'scope'])
    if (valid) setStep((s) => Math.min(s + 1, steps.length - 1))
  }

  const handleBack = () => setStep((s) => Math.max(s - 1, 0))

  const onFormSubmit = handleSubmit(onSubmit)

  return (
    <form onSubmit={onFormSubmit} className="space-y-6">
      <div className="flex items-center gap-2">
        {steps.map((label, i) => (
          <div key={label} className="flex items-center gap-2">
            <div className={`flex h-8 w-8 items-center justify-center rounded-full text-xs font-medium ${
              i < step ? 'bg-accent text-white' :
              i === step ? 'bg-accent/20 text-accent border border-accent' :
              'bg-surface-tertiary text-text-muted'
            }`}>
              {i < step ? <Check className="h-4 w-4" /> : i + 1}
            </div>
            <span className={`text-sm ${i === step ? 'text-text-primary font-medium' : 'text-text-muted'}`}>
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
            {step === 1 && 'Provide authorization and scope information'}
            {step === 2 && 'Review the assessment details before submitting'}
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
          {step === 2 && (
            <div className="space-y-3 rounded-lg bg-surface-tertiary/50 p-4">
              <Row label="Target" value={values.target_value} />
              <Row label="Type" value={values.target_type.replace('_', ' ')} />
              <Row label="Authorized By" value={values.authorized_by} />
              <Row label="Scope" value={values.scope} />
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
              Next
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
