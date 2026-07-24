import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AppearanceSection } from '../AppearanceSection'

describe('AppearanceSection', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('renders title', () => {
    render(<AppearanceSection />)
    expect(screen.getByText('Appearance')).toBeInTheDocument()
  })

  it('renders all theme options', () => {
    render(<AppearanceSection />)
    expect(screen.getByText('Dark')).toBeInTheDocument()
    expect(screen.getByText('Light')).toBeInTheDocument()
    expect(screen.getByText('System')).toBeInTheDocument()
  })

  it('defaults to system theme', () => {
    render(<AppearanceSection />)
    const systemRadio = screen.getByLabelText('System')
    expect(systemRadio).toBeChecked()
  })

  it('allows changing theme', async () => {
    render(<AppearanceSection />)
    const darkRadio = screen.getByLabelText('Dark')
    await userEvent.click(darkRadio)
    expect(darkRadio).toBeChecked()
  })
})
