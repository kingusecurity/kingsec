import { render, screen } from '@testing-library/react'
import { useState } from 'react'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../Tabs'

describe('Tabs', () => {
  it('renders tabs and content', () => {
    function TestTabs() {
      const [value, setValue] = useState('a')
      return (
        <Tabs value={value} onValueChange={setValue}>
          <TabsList>
            <TabsTrigger value="a">Tab A</TabsTrigger>
            <TabsTrigger value="b">Tab B</TabsTrigger>
          </TabsList>
          <TabsContent value="a">Panel A</TabsContent>
          <TabsContent value="b">Panel B</TabsContent>
        </Tabs>
      )
    }
    render(<TestTabs />)
    expect(screen.getByText('Tab A')).toBeInTheDocument()
    expect(screen.getByText('Tab B')).toBeInTheDocument()
    expect(screen.getByText('Panel A')).toBeInTheDocument()
  })
})
