import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { CreateAssessmentForm } from '../CreateAssessmentForm'
import { useCheckGrantCoverage } from '@/hooks/use-grants'
import { usePlan, useProfiles } from '@/hooks/use-profiles'
import type { AssessmentProfile } from '@/api/profiles'

vi.mock('@/hooks/use-profiles', () => ({
  useProfiles: vi.fn(),
  usePlan: vi.fn(),
}))

vi.mock('@/hooks/use-grants', () => ({
  useCheckGrantCoverage: vi.fn(),
}))

const purposeBuiltProfiles: AssessmentProfile[] = [
  {
    id: 'code-review',
    name: 'Source Code Assessment',
    description: 'Static and dependency analysis of a server-local source path.',
    supported_target_types: ['source_path'],
    scanners: ['semgrep', 'trivy'],
    estimated_duration_minutes: 20,
    required_scanners: ['semgrep', 'trivy'],
    tags: ['code'],
  },
  {
    id: 'container-scan',
    name: 'Container Image Assessment',
    description: 'Trivy image scan.',
    supported_target_types: ['container_image'],
    scanners: ['trivy'],
    estimated_duration_minutes: 10,
    required_scanners: ['trivy'],
    tags: ['container'],
  },
  {
    id: 'domain-enumeration',
    name: 'Domain Enumeration',
    description: 'Amass domain enumeration.',
    supported_target_types: ['domain'],
    scanners: ['amass'],
    estimated_duration_minutes: 15,
    required_scanners: ['amass'],
    tags: ['domain'],
  },
]

describe('CreateAssessmentForm target contracts', () => {
  const readyPlan = {
    profile_id: 'domain-enumeration',
    profile_name: 'Domain Enumeration',
    target_value: 'example.com',
    target_type: 'domain',
    selected_scanners: [{ scanner_id: 'amass', name: 'Amass', selected: true, skip_state: null, reason: '' }],
    skipped_scanners: [],
    unavailable_scanners: [],
    warnings: [],
    estimated_duration_minutes: 15,
    can_proceed: true,
  }
  const covered = {
    enforced: true,
    target_type: 'domain',
    target_value: 'example.com',
    profile_id: 'domain-enumeration',
    required_tiers: [{ tier: 'domain_enumeration', covered: true, grant_id: 'agrt-test' }],
    fully_covered: true,
  }
  const planMutateAsync = vi.fn()
  const coverageMutateAsync = vi.fn()

  beforeEach(() => {
    planMutateAsync.mockReset().mockResolvedValue(readyPlan)
    coverageMutateAsync.mockReset().mockResolvedValue(covered)
    vi.mocked(useProfiles).mockReturnValue({
      data: purposeBuiltProfiles,
      isLoading: false,
    } as ReturnType<typeof useProfiles>)
    vi.mocked(usePlan).mockReturnValue({
      mutateAsync: planMutateAsync,
      isPending: false,
      isError: false,
      error: null,
      reset: vi.fn(),
    } as unknown as ReturnType<typeof usePlan>)
    vi.mocked(useCheckGrantCoverage).mockReturnValue({
      mutateAsync: coverageMutateAsync,
      isPending: false,
      isError: false,
      error: null,
      reset: vi.fn(),
    } as unknown as ReturnType<typeof useCheckGrantCoverage>)
  })

  it('offers the explicit domain, source path, and image target types with type-specific guidance', () => {
    render(<CreateAssessmentForm onSubmit={vi.fn()} />)

    const target = screen.getByLabelText('Target')
    const targetType = screen.getByLabelText('Target Type')

    expect(screen.getByRole('option', { name: 'DNS Domain (enumeration)' })).toHaveValue('domain')
    expect(screen.getByRole('option', { name: 'Source Path (KingSec server)' })).toHaveValue('source_path')
    expect(screen.getByRole('option', { name: 'Container Image Reference' })).toHaveValue('container_image')

    fireEvent.change(targetType, { target: { value: 'domain' } })
    expect(target).toHaveAttribute('placeholder', 'example.com')
    expect(screen.getByText(/third-party DNS and certificate-transparency sources/)).toBeInTheDocument()

    fireEvent.change(targetType, { target: { value: 'source_path' } })
    expect(target).toHaveAttribute('placeholder', '/srv/customer/source')
    expect(screen.getByText(/visible to the KingSec server/)).toBeInTheDocument()

    fireEvent.change(targetType, { target: { value: 'container_image' } })
    expect(target).toHaveAttribute('placeholder', 'registry.example.com/team/app:v1')
    expect(screen.getByText(/Trivy image scanning/)).toBeInTheDocument()
  })

  it('filters profiles by the exact target type and clears a selection when the type changes', async () => {
    render(<CreateAssessmentForm onSubmit={vi.fn()} />)

    fireEvent.change(screen.getByLabelText('Target Type'), { target: { value: 'source_path' } })
    fireEvent.change(screen.getByLabelText('Target'), { target: { value: '/srv/customer/source' } })
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))

    const sourceProfile = await screen.findByRole('button', { name: /Source Code Assessment/ })
    expect(screen.queryByRole('button', { name: /Container Image Assessment/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Domain Enumeration/ })).not.toBeInTheDocument()
    fireEvent.click(sourceProfile)

    fireEvent.click(screen.getByRole('button', { name: 'Back' }))
    fireEvent.change(screen.getByLabelText('Target Type'), { target: { value: 'container_image' } })
    fireEvent.change(screen.getByLabelText('Target'), { target: { value: 'alpine:3.20' } })
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))

    await screen.findByRole('button', { name: /Container Image Assessment/ })
    expect(screen.queryByRole('button', { name: /Source Code Assessment/ })).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Review Plan' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Container Image Assessment/ })).toBeInTheDocument()
    })
    expect(screen.queryByLabelText('Authorized By')).not.toBeInTheDocument()
    expect(planMutateAsync).not.toHaveBeenCalled()
  })

  it('sends the domain target type unchanged when requesting the selected plan and coverage', async () => {
    render(<CreateAssessmentForm onSubmit={vi.fn()} />)

    fireEvent.change(screen.getByLabelText('Target Type'), { target: { value: 'domain' } })
    fireEvent.change(screen.getByLabelText('Target'), { target: { value: 'example.com' } })
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    fireEvent.click(await screen.findByRole('button', { name: /Domain Enumeration/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Review Plan' }))

    await waitFor(() => {
      expect(planMutateAsync).toHaveBeenCalledWith({
        profileId: 'domain-enumeration',
        body: { target: 'example.com', target_type: 'domain' },
      })
    })
    expect(coverageMutateAsync).toHaveBeenCalledWith({
      target_type: 'domain',
      target_value: 'example.com',
      profile_id: 'domain-enumeration',
    })
  })
})
