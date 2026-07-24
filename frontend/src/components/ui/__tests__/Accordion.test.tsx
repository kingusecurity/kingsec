import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from '../Accordion'

describe('Accordion', () => {
  it('opens content when trigger is clicked', async () => {
    render(
      <Accordion>
        <AccordionItem value="item1">
          <AccordionTrigger>Trigger 1</AccordionTrigger>
          <AccordionContent>Content 1</AccordionContent>
        </AccordionItem>
      </Accordion>,
    )

    expect(screen.queryByText('Content 1')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /trigger 1/i }))
    expect(screen.getByText('Content 1')).toBeInTheDocument()
  })

  it('handles single mode correctly', async () => {
    render(
      <Accordion type="single">
        <AccordionItem value="item1">
          <AccordionTrigger>Trigger 1</AccordionTrigger>
          <AccordionContent>Content 1</AccordionContent>
        </AccordionItem>
        <AccordionItem value="item2">
          <AccordionTrigger>Trigger 2</AccordionTrigger>
          <AccordionContent>Content 2</AccordionContent>
        </AccordionItem>
      </Accordion>,
    )

    await userEvent.click(screen.getByRole('button', { name: /trigger 1/i }))
    expect(screen.getByText('Content 1')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /trigger 2/i }))
    expect(screen.getByText('Content 2')).toBeInTheDocument()
  })

  it('sets aria-expanded correctly', async () => {
    render(
      <Accordion>
        <AccordionItem value="item1">
          <AccordionTrigger>Trigger</AccordionTrigger>
          <AccordionContent>Content</AccordionContent>
        </AccordionItem>
      </Accordion>,
    )

    const trigger = screen.getByRole('button', { name: /trigger/i })
    expect(trigger).toHaveAttribute('aria-expanded', 'false')

    await userEvent.click(trigger)
    expect(trigger).toHaveAttribute('aria-expanded', 'true')
  })
})
