import { render, screen } from '@testing-library/react'
import { FindingReferences } from '../FindingReferences'

describe('FindingReferences', () => {
  it('renders empty state when no references', () => {
    render(<FindingReferences />)
    expect(screen.getByText('No references available from the current API.')).toBeInTheDocument()
  })

  it('renders CVE identifiers', () => {
    render(<FindingReferences cve={['CVE-2024-1234', 'CVE-2024-5678']} />)
    expect(screen.getByText('CVE-2024-1234')).toBeInTheDocument()
    expect(screen.getByText('CVE-2024-5678')).toBeInTheDocument()
    expect(screen.getByText('CVE Identifiers')).toBeInTheDocument()
  })

  it('renders CWE classifications', () => {
    render(<FindingReferences cwe={['CWE-89', 'CWE-79']} />)
    expect(screen.getByText('CWE-89')).toBeInTheDocument()
    expect(screen.getByText('CWE-79')).toBeInTheDocument()
    expect(screen.getByText('CWE Classifications')).toBeInTheDocument()
  })

  it('renders CVSS score and vector', () => {
    render(<FindingReferences cvssScore={7.5} cvssVector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" />)
    expect(screen.getByText('7.5')).toBeInTheDocument()
    expect(screen.getByText(/CVSS:3.1/)).toBeInTheDocument()
  })
})
