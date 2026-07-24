import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { UserForm } from '../UserForm'

describe('UserForm', () => {
  it('renders create mode fields', () => {
    render(<UserForm mode="create" onSubmit={vi.fn()} isPending={false} />)
    expect(screen.getByLabelText('Username')).toBeInTheDocument()
    expect(screen.getByLabelText('Email')).toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toBeInTheDocument()
    expect(screen.getByLabelText('Role')).toBeInTheDocument()
    expect(screen.getByText('Create User')).toBeInTheDocument()
  })

  it('renders edit mode fields', () => {
    render(<UserForm mode="edit" defaultValues={{ email: 'test@example.com', role: 'viewer' }} onSubmit={vi.fn()} isPending={false} />)
    expect(screen.queryByLabelText('Username')).not.toBeInTheDocument()
    expect(screen.getByLabelText('Email')).toBeInTheDocument()
    expect(screen.queryByLabelText('Password')).not.toBeInTheDocument()
    expect(screen.getByLabelText('Role')).toBeInTheDocument()
    expect(screen.getByText('Save Changes')).toBeInTheDocument()
  })

  it('calls onSubmit with form data', async () => {
    const onSubmit = vi.fn()
    render(<UserForm mode="create" onSubmit={onSubmit} isPending={false} />)

    await userEvent.type(screen.getByLabelText('Username'), 'newuser')
    await userEvent.type(screen.getByLabelText('Email'), 'new@example.com')
    await userEvent.type(screen.getByLabelText('Password'), 'password123')
    await userEvent.selectOptions(screen.getByLabelText('Role'), 'analyst')
    await userEvent.click(screen.getByText('Create User'))

    expect(onSubmit).toHaveBeenCalledWith(
      expect.objectContaining({
        username: 'newuser',
        email: 'new@example.com',
        role: 'analyst',
      }),
      expect.anything(),
    )
  })

  it('shows loading state on submit button', () => {
    render(<UserForm mode="create" onSubmit={vi.fn()} isPending={true} />)
    expect(screen.getByRole('button')).toBeDisabled()
  })
})
