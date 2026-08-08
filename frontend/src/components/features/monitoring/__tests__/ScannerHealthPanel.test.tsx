import { render, screen } from '@testing-library/react'
import { ScannerHealthPanel } from '../ScannerHealthPanel'

vi.mock('@/hooks/use-scanner-health', () => ({
  useScannerHealth: vi.fn(),
  useScannerDetail: vi.fn(),
  useScannerInstallInfo: vi.fn(),
}))
vi.mock('@/hooks/use-profiles', () => ({
  useProfiles: vi.fn(),
}))

import { useScannerHealth } from '@/hooks/use-scanner-health'
import { useProfiles } from '@/hooks/use-profiles'

// The real dev-environment scanner state from the scanner UX audit: 3/9
// installed and usable (nmap, semgrep, trivy), 6/9 missing.
const mockScannerHealth = {
  total: 9,
  installed: 3,
  usable: 3,
  partial: 0,
  missing: 6,
  health_score: 33.3,
  scanners: [
    { scanner_id: 'nmap', name: 'Nmap', installed: true, executable_path: 'C:\\Program Files (x86)\\Nmap\\nmap.EXE', version: '7.99', usable: true, availability_reason: null, warnings: [], required_assets: [], missing_assets: [], install_hints: [], permissions_ok: true, recommendations: [] },
    { scanner_id: 'nuclei', name: 'Nuclei', installed: false, executable_path: null, version: null, usable: false, availability_reason: "'nuclei' not found on PATH or common locations", warnings: [], required_assets: ['Nuclei templates'], missing_assets: [], install_hints: [], permissions_ok: true, recommendations: [] },
    { scanner_id: 'nikto', name: 'Nikto', installed: false, executable_path: null, version: null, usable: false, availability_reason: "'nikto' not found on PATH or common locations", warnings: [], required_assets: ['Perl runtime'], missing_assets: [], install_hints: [], permissions_ok: true, recommendations: [] },
    { scanner_id: 'ffuf', name: 'FFUF', installed: false, executable_path: null, version: null, usable: false, availability_reason: "'ffuf' not found on PATH or common locations", warnings: [], required_assets: [], missing_assets: [], install_hints: [], permissions_ok: true, recommendations: [] },
    { scanner_id: 'gobuster', name: 'Gobuster', installed: false, executable_path: null, version: null, usable: false, availability_reason: "'gobuster' not found on PATH or common locations", warnings: [], required_assets: [], missing_assets: [], install_hints: [], permissions_ok: true, recommendations: [] },
    { scanner_id: 'semgrep', name: 'Semgrep', installed: true, executable_path: 'C:\\Python314\\Scripts\\semgrep.EXE', version: '1.171.0', usable: true, availability_reason: null, warnings: [], required_assets: [], missing_assets: [], install_hints: [], permissions_ok: true, recommendations: [] },
    { scanner_id: 'trivy', name: 'Trivy', installed: true, executable_path: 'C:\\ProgramData\\chocolatey\\bin\\trivy.EXE', version: '0.72.0', usable: true, availability_reason: null, warnings: [], required_assets: [], missing_assets: ['Trivy vulnerability DB'], install_hints: [], permissions_ok: true, recommendations: [] },
    { scanner_id: 'amass', name: 'Amass', installed: false, executable_path: null, version: null, usable: false, availability_reason: "'amass' not found on PATH or common locations", warnings: [], required_assets: [], missing_assets: [], install_hints: [], permissions_ok: true, recommendations: [] },
    { scanner_id: 'zap', name: 'OWASP ZAP', installed: false, executable_path: null, version: null, usable: false, availability_reason: "'zap' not found on PATH or common locations", warnings: [], required_assets: ['Java runtime'], missing_assets: [], install_hints: [], permissions_ok: true, recommendations: [] },
  ],
}

// Real profile shapes from assessment_profiles.py's _DEFAULT_PROFILES,
// minus "Full Assessment" (which references all 9 scanners with none
// required) - kept out here so this fixture can exercise the "referenced
// by nobody" case with a synthetic scanner instead of relying on real
// data, since in the real profile set every scanner appears somewhere in
// Full Assessment.
const mockProfiles = [
  {
    id: 'quick-scan', name: 'Quick Host Scan', description: '', supported_target_types: ['ip_address', 'hostname'],
    scanners: ['nmap'], estimated_duration_minutes: 5, required_scanners: ['nmap'], tags: [],
  },
  {
    id: 'network-scan', name: 'Network Assessment', description: '', supported_target_types: ['network', 'ip_address', 'hostname'],
    scanners: ['nmap', 'nuclei'], estimated_duration_minutes: 30, required_scanners: ['nmap'], tags: [],
  },
  {
    id: 'web-scan', name: 'Web Application Scan', description: '', supported_target_types: ['url'],
    scanners: ['nmap', 'gobuster', 'ffuf', 'nuclei', 'zap'], estimated_duration_minutes: 60, required_scanners: ['nmap'], tags: [],
  },
  {
    id: 'code-review', name: 'Source Code Review', description: '', supported_target_types: ['hostname', 'ip_address'],
    scanners: ['semgrep'], estimated_duration_minutes: 15, required_scanners: ['semgrep'], tags: [],
  },
  {
    id: 'container-scan', name: 'Container Assessment', description: '', supported_target_types: ['hostname', 'ip_address'],
    scanners: ['trivy'], estimated_duration_minutes: 10, required_scanners: ['trivy'], tags: [],
  },
  {
    id: 'external-footprint', name: 'External Footprint Mapping', description: '', supported_target_types: ['hostname', 'ip_address'],
    scanners: ['amass', 'nmap'], estimated_duration_minutes: 20, required_scanners: ['nmap'], tags: [],
  },
  // Synthetic: proves a scanner used-but-never-required by any profile
  // renders "Optional for" only, with no "Required by" badge.
  {
    id: 'synthetic-optional-only', name: 'Synthetic Optional-Only Profile', description: '', supported_target_types: ['url'],
    scanners: ['nikto'], estimated_duration_minutes: 10, required_scanners: [], tags: [],
  },
]

function mockHooks() {
  vi.mocked(useScannerHealth).mockReturnValue({
    data: mockScannerHealth,
    isLoading: false,
    error: null,
    refetch: vi.fn(),
  } as any)
  vi.mocked(useProfiles).mockReturnValue({
    data: mockProfiles,
    isLoading: false,
    error: null,
  } as any)
}

describe('ScannerHealthPanel required/optional badges', () => {
  beforeEach(() => {
    mockHooks()
  })

  it('shows "Required by" listing every profile that requires a scanner used in multiple profiles', () => {
    // Nmap: required by Quick Host Scan, Network Assessment, Web
    // Application Scan, and External Footprint Mapping.
    render(<ScannerHealthPanel />)
    expect(
      screen.getByText('Required by: Quick Host Scan, Network Assessment, Web Application Scan, External Footprint Mapping'),
    ).toBeInTheDocument()
  })

  it('shows "Optional for" for a scanner referenced by exactly one profile, never required', () => {
    // Nikto only appears in the synthetic optional-only profile above.
    render(<ScannerHealthPanel />)
    expect(screen.getByText('Optional for: Synthetic Optional-Only Profile')).toBeInTheDocument()
  })

  it('shows no badge at all for a scanner referenced by no profile', () => {
    // FFUF is not in any profile in this fixture set.
    render(<ScannerHealthPanel />)
    expect(screen.queryByText(/Required by:.*FFUF/)).not.toBeInTheDocument()
    expect(screen.queryByText(/Optional for:.*FFUF/)).not.toBeInTheDocument()
    // FFUF's own row must still render (name present), just without a relevance badge.
    expect(screen.getByText('FFUF')).toBeInTheDocument()
  })

  it('shows both Required-by and Optional-for badges for a scanner that is required in some profiles and merely optional in others', () => {
    // Trivy: required by Container Assessment. Add a second profile
    // where Trivy is present but not required, to exercise the dual case
    // the real "Full Assessment" profile creates for Nmap/Trivy/Semgrep.
    vi.mocked(useProfiles).mockReturnValue({
      data: [
        ...mockProfiles,
        {
          id: 'full-assessment', name: 'Full Assessment', description: '', supported_target_types: ['ip_address'],
          scanners: ['trivy'], estimated_duration_minutes: 90, required_scanners: [], tags: [],
        },
      ],
      isLoading: false,
      error: null,
    } as any)

    render(<ScannerHealthPanel />)
    expect(screen.getByText('Required by: Container Assessment')).toBeInTheDocument()
    expect(screen.getByText('Optional for: Full Assessment')).toBeInTheDocument()
  })

  it('renders correctly when profile data has not loaded yet', () => {
    vi.mocked(useProfiles).mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
    } as any)

    render(<ScannerHealthPanel />)
    // Scanner rows still render without crashing; no relevance badges yet.
    expect(screen.getByText('Nmap')).toBeInTheDocument()
    expect(screen.queryByText(/Required by:/)).not.toBeInTheDocument()
  })
})
