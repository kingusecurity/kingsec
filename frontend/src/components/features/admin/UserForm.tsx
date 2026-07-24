import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Button } from '@/components/ui/Button'

const createSchema = z.object({
  username: z.string().min(3, 'Username must be at least 3 characters').max(64),
  email: z.string().email('Invalid email address').min(5).max(254),
  password: z.string().min(8, 'Password must be at least 8 characters').max(128),
  role: z.string().min(1, 'Role is required'),
})

const editSchema = z.object({
  email: z.string().email('Invalid email address').min(5).max(254),
  role: z.string().min(1, 'Role is required'),
})

export interface CreateUserFormData {
  username: string
  email: string
  password: string
  role: string
}

export interface EditUserFormData {
  email: string
  role: string
}

type UserFormMode = 'create' | 'edit'

interface UserFormProps {
  mode: UserFormMode
  defaultValues?: { email: string; role: string }
  onSubmit: (data: CreateUserFormData | EditUserFormData) => void
  isPending: boolean
}

export function UserForm({ mode, defaultValues, onSubmit, isPending }: UserFormProps) {
  const isCreate = mode === 'create'

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<CreateUserFormData | EditUserFormData>({
    resolver: zodResolver(isCreate ? createSchema : editSchema),
    defaultValues: isCreate
      ? { username: '', email: '', password: '', role: '' }
      : { email: defaultValues?.email ?? '', role: defaultValues?.role ?? 'viewer' },
  })

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
      {isCreate && (
        <Input
          label="Username"
          placeholder="Enter username"
          error={('username' in errors ? errors.username?.message : undefined) as string | undefined}
          {...register('username')}
        />
      )}
      <Input
        label="Email"
        type="email"
        placeholder="Enter email address"
        error={errors.email?.message}
        {...register('email')}
      />
      {isCreate && (
        <Input
          label="Password"
          type="password"
          placeholder="Enter password"
          error={('password' in errors ? errors.password?.message : undefined) as string | undefined}
          {...register('password')}
        />
      )}
      <Select
        label="Role"
        error={errors.role?.message}
        options={[
          { value: '', label: 'Select a role...' },
          { value: 'admin', label: 'Admin' },
          { value: 'analyst', label: 'Analyst' },
          { value: 'viewer', label: 'Viewer' },
        ]}
        {...register('role')}
      />
      <div className="flex justify-end gap-3 pt-2">
        <Button type="submit" loading={isPending}>
          {isCreate ? 'Create User' : 'Save Changes'}
        </Button>
      </div>
    </form>
  )
}
