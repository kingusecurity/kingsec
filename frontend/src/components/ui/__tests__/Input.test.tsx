import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Input } from '../Input'

describe('Input', () => {
  it('renders with label', () => {
    render(<Input label="Username" />)
    expect(screen.getByLabelText('Username')).toBeInTheDocument()
  })

  it('accepts input', async () => {
    const onChange = vi.fn()
    render(<Input label="Name" onChange={onChange} />)
    const input = screen.getByLabelText('Name')
    await userEvent.type(input, 'test')
    expect(onChange).toHaveBeenCalled()
    expect(input).toHaveValue('test')
  })

  it('displays error message', () => {
    render(<Input label="Email" error="Invalid email" />)
    expect(screen.getByRole('alert')).toHaveTextContent('Invalid email')
  })

  it('displays helper text', () => {
    render(<Input label="Email" helperText="Enter your email" />)
    expect(screen.getByText('Enter your email')).toBeInTheDocument()
  })

  it('shows loading spinner', () => {
    render(<Input label="Search" loading />)
    expect(screen.getByRole('status')).toBeInTheDocument()
  })

  it('is disabled', () => {
    render(<Input label="Disabled" disabled />)
    expect(screen.getByLabelText('Disabled')).toBeDisabled()
  })

  it('renders prefix and suffix', () => {
    render(
      <Input
        label="Price"
        prefix={<span>$</span>}
        suffix={<span>.00</span>}
      />,
    )
    expect(screen.getByText('$')).toBeInTheDocument()
    expect(screen.getByText('.00')).toBeInTheDocument()
  })

  it('sets aria-invalid when error is present', () => {
    render(<Input label="Test" error="Error" />)
    expect(screen.getByLabelText('Test')).toHaveAttribute('aria-invalid', 'true')
  })
})
