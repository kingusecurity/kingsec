import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { Plus, Loader2 } from "lucide-react"
import { useCreateAssessment } from "../hooks/use-assessments"
import { createAssessmentSchema, type CreateAssessmentFormData } from "../validation/assessments"
import { Button } from "@/shared/ui/button"
import { Input } from "@/shared/ui/input"
import { Label } from "@/shared/ui/label"
import { Select } from "@/shared/ui/select"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/shared/ui/dialog"

export function CreateAssessmentDialog(): React.ReactElement {
  const [open, setOpen] = useState(false)
  const createMutation = useCreateAssessment()

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<CreateAssessmentFormData>({
    resolver: zodResolver(createAssessmentSchema),
  })

  function onSubmit(data: CreateAssessmentFormData): void {
    createMutation.mutate(data, {
      onSuccess: () => {
        reset()
        setOpen(false)
      },
    })
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="mr-2 size-4" />
          New Assessment
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[480px]">
        <DialogHeader>
          <DialogTitle>Create Assessment</DialogTitle>
          <DialogDescription>Start a new attack surface assessment.</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="target_value">Target</Label>
            <Input id="target_value" placeholder="IP, hostname, or URL" {...register("target_value")} />
            {errors.target_value && <p className="text-xs text-[hsl(var(--destructive))]">{errors.target_value.message}</p>}
          </div>
          <div className="space-y-2">
            <Label htmlFor="target_type">Target Type</Label>
            <Select id="target_type" {...register("target_type")}>
              <option value="">Select type</option>
              <option value="ip_address">IP Address</option>
              <option value="hostname">Hostname</option>
              <option value="url">URL</option>
              <option value="network">Network</option>
            </Select>
            {errors.target_type && <p className="text-xs text-[hsl(var(--destructive))]">{errors.target_type.message}</p>}
          </div>
          <div className="space-y-2">
            <Label htmlFor="authorized_by">Authorized By</Label>
            <Input id="authorized_by" placeholder="Who authorized this" {...register("authorized_by")} />
            {errors.authorized_by && <p className="text-xs text-[hsl(var(--destructive))]">{errors.authorized_by.message}</p>}
          </div>
          <div className="space-y-2">
            <Label htmlFor="scope">Scope</Label>
            <Input id="scope" placeholder="Scope of authorization" {...register("scope")} />
            {errors.scope && <p className="text-xs text-[hsl(var(--destructive))]">{errors.scope.message}</p>}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)} disabled={createMutation.isPending}>
              Cancel
            </Button>
            <Button type="submit" disabled={createMutation.isPending}>
              {createMutation.isPending ? <Loader2 className="mr-2 size-4 animate-spin" /> : null}
              Create
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
