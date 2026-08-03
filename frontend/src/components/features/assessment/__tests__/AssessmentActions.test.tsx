import { render, screen } from '@testing-library/react'
import { AssessmentActions } from '../AssessmentActions'

describe('AssessmentActions', () => {
  it('shows Start only for authorized (the only status start() accepts per the domain state machine)', () => {
    render(<AssessmentActions status="authorized" onStart={() => {}} />)
    expect(screen.getByText('Start')).toBeInTheDocument()
  })

  it('does not show Start for draft (start() requires AUTHORIZED, draft would 409)', () => {
    render(<AssessmentActions status="draft" onStart={() => {}} />)
    expect(screen.queryByText('Start')).not.toBeInTheDocument()
  })

  it('does not show Start for running, completed, failed, or cancelled', () => {
    for (const status of ['running', 'completed', 'failed', 'cancelled']) {
      const { unmount } = render(<AssessmentActions status={status} onStart={() => {}} />)
      expect(screen.queryByText('Start')).not.toBeInTheDocument()
      unmount()
    }
  })

  it('shows Cancel for draft, authorized, and running (all can transition to CANCELLED)', () => {
    for (const status of ['draft', 'authorized', 'running']) {
      const { unmount } = render(<AssessmentActions status={status} onCancel={() => {}} />)
      expect(screen.getByText('Cancel')).toBeInTheDocument()
      unmount()
    }
  })

  it('does not show Cancel once terminal (completed, failed, cancelled)', () => {
    for (const status of ['completed', 'failed', 'cancelled']) {
      const { unmount } = render(<AssessmentActions status={status} onCancel={() => {}} />)
      expect(screen.queryByText('Cancel')).not.toBeInTheDocument()
      unmount()
    }
  })

  it('shows Generate Report only for completed', () => {
    render(<AssessmentActions status="completed" onGenerateReport={() => {}} />)
    expect(screen.getByText('Generate Report')).toBeInTheDocument()
  })

  it('shows Delete for draft, failed, and cancelled', () => {
    for (const status of ['draft', 'failed', 'cancelled']) {
      const { unmount } = render(<AssessmentActions status={status} onDelete={() => {}} />)
      expect(screen.getByText('Delete')).toBeInTheDocument()
      unmount()
    }
  })
})
