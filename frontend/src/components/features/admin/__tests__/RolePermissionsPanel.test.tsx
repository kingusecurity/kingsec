import { render, screen } from '@testing-library/react'
import { RolePermissionsPanel } from '../RolePermissionsPanel'
import type { RolePermission } from '@/api/admin'

const mockRoles: RolePermission[] = [
  {
    role: 'admin',
    description: 'Full system access',
    permissions: ['create_user', 'delete_user', 'manage_roles', 'view_reports', 'run_assessments', 'manage_settings'],
    accessible_modules: ['Dashboard', 'Assessments', 'Findings', 'Reports', 'Admin', 'Settings'],
  },
  {
    role: 'analyst',
    description: 'Can run assessments and view reports',
    permissions: ['run_assessments', 'view_reports'],
    accessible_modules: ['Dashboard', 'Assessments', 'Findings', 'Reports'],
  },
]

describe('RolePermissionsPanel', () => {
  const defaultProps = {
    roles: mockRoles,
    isLoading: false,
    error: null,
    onRetry: vi.fn(),
  }

  it('renders role names', () => {
    render(<RolePermissionsPanel {...defaultProps} />)
    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByText('analyst')).toBeInTheDocument()
  })

  it('renders role descriptions', () => {
    render(<RolePermissionsPanel {...defaultProps} />)
    expect(screen.getByText('Full system access')).toBeInTheDocument()
    expect(screen.getByText('Can run assessments and view reports')).toBeInTheDocument()
  })

  it('renders permissions', () => {
    render(<RolePermissionsPanel {...defaultProps} />)
    expect(screen.getByText('create_user')).toBeInTheDocument()
    expect(screen.getByText('delete_user')).toBeInTheDocument()
  })

  it('renders accessible modules', () => {
    render(<RolePermissionsPanel {...defaultProps} />)
    expect(screen.getAllByText('Admin').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('Reports').length).toBeGreaterThanOrEqual(1)
  })

  it('shows loading state', () => {
    const { container } = render(<RolePermissionsPanel {...defaultProps} roles={undefined} isLoading={true} />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })

  it('shows error state', () => {
    render(<RolePermissionsPanel {...defaultProps} roles={undefined} error={new Error('Failed')} />)
    expect(screen.getByText('Failed to load roles')).toBeInTheDocument()
  })

  it('shows empty message when no roles', () => {
    render(<RolePermissionsPanel {...defaultProps} roles={[]} />)
    expect(screen.getByText('No roles configured.')).toBeInTheDocument()
  })
})
