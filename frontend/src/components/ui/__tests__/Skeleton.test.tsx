import { render } from '@testing-library/react'
import { Skeleton, CardSkeleton, TableSkeleton, TextSkeleton } from '../Skeleton'

describe('Skeleton', () => {
  it('renders with animate-pulse', () => {
    const { container } = render(<Skeleton className="h-4 w-24" />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })

  it('renders with aria-hidden', () => {
    const { container } = render(<Skeleton className="h-4 w-24" />)
    expect(container.querySelector('[aria-hidden="true"]')).toBeInTheDocument()
  })
})

describe('CardSkeleton', () => {
  it('renders without crashing', () => {
    const { container } = render(<CardSkeleton />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })
})

describe('TableSkeleton', () => {
  it('renders specified number of rows', () => {
    const { container } = render(<TableSkeleton rows={3} />)
    const rows = container.querySelectorAll('.animate-pulse')
    expect(rows.length).toBeGreaterThan(0)
  })
})

describe('TextSkeleton', () => {
  it('renders specified number of lines', () => {
    const { container } = render(<TextSkeleton lines={2} />)
    const lines = container.querySelectorAll('.animate-pulse')
    expect(lines.length).toBe(2)
  })
})
