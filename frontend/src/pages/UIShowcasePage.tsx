import { useState } from 'react'
import { Button, Card, CardHeader, CardTitle, CardDescription, CardFooter } from '@/components/ui'
import { Badge } from '@/components/ui'
import { Spinner } from '@/components/ui'
import { Input } from '@/components/ui'
import { Textarea } from '@/components/ui'
import { Select } from '@/components/ui'
import { Checkbox } from '@/components/ui'
import { RadioGroup, RadioGroupItem } from '@/components/ui'
import { Toggle } from '@/components/ui'
import { Alert } from '@/components/ui'
import { Progress } from '@/components/ui'
import { Divider } from '@/components/ui'
import { Avatar } from '@/components/ui'
import { Tooltip } from '@/components/ui'
import { Modal } from '@/components/ui'
import { Drawer } from '@/components/ui'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui'
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from '@/components/ui'
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator } from '@/components/ui'
import { Breadcrumb, BreadcrumbItem, BreadcrumbSeparator } from '@/components/ui'
import { Pagination } from '@/components/ui'
import { EmptyState } from '@/components/ui'
import { ErrorState } from '@/components/ui'
import { LoadingState } from '@/components/ui'
import { ConfirmDialog } from '@/components/ui'
import { toast } from '@/components/ui'
import { CardSkeleton, TableSkeleton, TextSkeleton, DashboardSkeleton } from '@/components/ui'
import { Search, Settings, User, Mail, Trash2, ChevronRight } from 'lucide-react'

export function UIShowcasePage() {
  const [modalOpen, setModalOpen] = useState(false)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [tabValue, setTabValue] = useState('tab1')
  const [radioValue, setRadioValue] = useState('option1')
  const [progress, setProgress] = useState(0)
  const [page, setPage] = useState(1)

  return (
    <div className="mx-auto max-w-4xl space-y-16 py-10">
      <div>
        <h1 className="text-3xl font-bold text-text-primary">UI Component Showcase</h1>
        <p className="mt-1 text-text-secondary">Development-only reference page</p>
      </div>

      {/* Buttons */}
      <Section title="Button">
        <div className="flex flex-wrap gap-3">
          <Button variant="primary">Primary</Button>
          <Button variant="secondary">Secondary</Button>
          <Button variant="outline">Outline</Button>
          <Button variant="ghost">Ghost</Button>
          <Button variant="danger">Danger</Button>
          <Button variant="success">Success</Button>
        </div>
        <div className="flex flex-wrap gap-3">
          <Button size="xs">XSmall</Button>
          <Button size="sm">Small</Button>
          <Button size="md">Medium</Button>
          <Button size="lg">Large</Button>
        </div>
        <div className="flex flex-wrap gap-3">
          <Button loading>Loading</Button>
          <Button disabled>Disabled</Button>
          <Button iconLeft={<Search className="h-4 w-4" />}>Left Icon</Button>
          <Button iconRight={<ChevronRight className="h-4 w-4" />}>Right Icon</Button>
          <Button fullWidth>Full Width</Button>
        </div>
      </Section>

      {/* Card */}
      <Section title="Card">
        <div className="grid gap-4 sm:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Default Card</CardTitle>
              <CardDescription>This is a description</CardDescription>
            </CardHeader>
            <div className="px-5 py-3 text-sm text-text-secondary">Card body content</div>
            <CardFooter>
              <Button variant="ghost" size="sm">Cancel</Button>
              <Button size="sm">Save</Button>
            </CardFooter>
          </Card>
          <Card variant="elevated">
            <CardHeader>
              <CardTitle>Elevated Card</CardTitle>
              <CardDescription>With shadow</CardDescription>
            </CardHeader>
            <div className="px-5 py-3 text-sm text-text-secondary">Content</div>
          </Card>
          <Card variant="danger">
            <CardHeader>
              <CardTitle>Danger Card</CardTitle>
              <CardDescription>Warning state</CardDescription>
            </CardHeader>
          </Card>
          <Card variant="success">
            <CardHeader>
              <CardTitle>Success Card</CardTitle>
              <CardDescription>Success state</CardDescription>
            </CardHeader>
          </Card>
        </div>
      </Section>

      {/* Badge */}
      <Section title="Badge">
        <div className="flex flex-wrap gap-2">
          <Badge variant="critical">Critical</Badge>
          <Badge variant="high">High</Badge>
          <Badge variant="medium">Medium</Badge>
          <Badge variant="low">Low</Badge>
          <Badge variant="info">Info</Badge>
          <Badge variant="success">Success</Badge>
          <Badge variant="warning">Warning</Badge>
          <Badge variant="neutral">Neutral</Badge>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Badge size="sm">Small</Badge>
          <Badge size="md">Medium</Badge>
          <Badge size="lg">Large</Badge>
        </div>
      </Section>

      {/* Spinner */}
      <Section title="Spinner">
        <div className="flex items-center gap-4">
          <Spinner size="sm" />
          <Spinner size="md" />
          <Spinner size="lg" />
        </div>
      </Section>

      {/* Input */}
      <Section title="Input">
        <div className="grid gap-4 sm:grid-cols-2">
          <Input label="Default" placeholder="Enter text" />
          <Input label="With Helper" helperText="This is helper text" placeholder="Type here" />
          <Input label="With Error" error="This field is required" placeholder="Invalid" />
          <Input label="Loading" loading placeholder="Searching..." />
          <Input label="Disabled" disabled value="Cannot edit" />
          <Input label="With Prefix" prefix={<Mail className="h-4 w-4" />} placeholder="email@example.com" />
          <Input label="With Suffix" suffix={<Search className="h-4 w-4" />} placeholder="Search" />
        </div>
      </Section>

      {/* Textarea */}
      <Section title="Textarea">
        <div className="grid gap-4 sm:grid-cols-2">
          <Textarea label="Default" placeholder="Enter text" />
          <Textarea label="With Error" error="Required" />
          <Textarea label="Auto Resize" autoResize placeholder="Type to resize..." />
        </div>
      </Section>

      {/* Select */}
      <Section title="Select">
        <div className="grid gap-4 sm:grid-cols-2">
          <Select
            label="Simple Select"
            placeholder="Choose..."
            options={[
              { value: '1', label: 'Option 1' },
              { value: '2', label: 'Option 2' },
              { value: '3', label: 'Option 3' },
            ]}
          />
          <Select
            label="Grouped Select"
            groups={[
              {
                label: 'Group A',
                options: [
                  { value: 'a1', label: 'Option A1' },
                  { value: 'a2', label: 'Option A2' },
                ],
              },
              {
                label: 'Group B',
                options: [
                  { value: 'b1', label: 'Option B1' },
                  { value: 'b2', label: 'Option B2' },
                ],
              },
            ]}
          />
          <Select label="With Error" error="Required" />
          <Select label="Disabled" disabled />
        </div>
      </Section>

      {/* Checkbox & Radio & Toggle */}
      <Section title="Choice Inputs">
        <div className="flex flex-wrap gap-6">
          <div className="space-y-2">
            <p className="text-sm text-text-secondary">Checkbox</p>
            <Checkbox label="Check me" />
            <Checkbox label="Checked" defaultChecked />
            <Checkbox label="Disabled" disabled />
          </div>
          <div className="space-y-2">
            <p className="text-sm text-text-secondary">Radio Group</p>
            <RadioGroup value={radioValue} onValueChange={setRadioValue}>
              <RadioGroupItem value="option1" label="Option 1" />
              <RadioGroupItem value="option2" label="Option 2" />
              <RadioGroupItem value="option3" label="Option 3" disabled />
            </RadioGroup>
          </div>
          <div className="space-y-2">
            <p className="text-sm text-text-secondary">Toggle</p>
            <Toggle label="Enable notifications" />
            <Toggle label="Always on" defaultChecked />
            <Toggle label="Disabled" disabled />
          </div>
        </div>
      </Section>

      {/* Alert */}
      <Section title="Alert">
        <div className="space-y-3">
          <Alert variant="success" title="Success!">Operation completed successfully.</Alert>
          <Alert variant="warning" title="Warning">This action cannot be undone.</Alert>
          <Alert variant="error" title="Error">Something went wrong.</Alert>
          <Alert variant="info" title="Info">Here is some information.</Alert>
        </div>
      </Section>

      {/* Progress */}
      <Section title="Progress">
        <div className="space-y-4">
          <div>
            <p className="mb-2 text-sm text-text-secondary">Determinate: {progress}%</p>
            <Progress value={progress} />
            <div className="mt-2 flex gap-2">
              <Button size="sm" onClick={() => setProgress(Math.max(0, progress - 10))}>-10%</Button>
              <Button size="sm" onClick={() => setProgress(Math.min(100, progress + 10))}>+10%</Button>
            </div>
          </div>
          <div>
            <p className="mb-2 text-sm text-text-secondary">Indeterminate</p>
            <Progress indeterminate />
          </div>
        </div>
      </Section>

      {/* Skeleton */}
      <Section title="Skeleton">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <p className="mb-2 text-sm text-text-secondary">Card Skeleton</p>
            <CardSkeleton />
          </div>
          <div>
            <p className="mb-2 text-sm text-text-secondary">Text Skeleton</p>
            <TextSkeleton lines={4} />
          </div>
        </div>
        <div className="mt-4">
          <p className="mb-2 text-sm text-text-secondary">Table Skeleton (3 rows)</p>
          <TableSkeleton rows={3} />
        </div>
        <div className="mt-4">
          <p className="mb-2 text-sm text-text-secondary">Dashboard Skeleton</p>
          <DashboardSkeleton />
        </div>
      </Section>

      {/* Divider */}
      <Section title="Divider">
        <div className="space-y-4">
          <Divider />
          <Divider label="Or continue with" />
          <div className="flex h-20 items-center gap-4">
            <span className="text-sm text-text-secondary">Left</span>
            <Divider orientation="vertical" />
            <span className="text-sm text-text-secondary">Right</span>
          </div>
        </div>
      </Section>

      {/* Avatar */}
      <Section title="Avatar">
        <div className="flex flex-wrap items-center gap-4">
          <Avatar initials="JD" />
          <Avatar initials="AB" size="sm" />
          <Avatar initials="CD" size="lg" />
          <Avatar initials="EF" size="xl" />
          <Avatar fallback="?" />
          <Avatar src="/nonexistent.png" fallback="U" />
        </div>
      </Section>

      {/* Tooltip */}
      <Section title="Tooltip">
        <Tooltip content="This is a tooltip">
          <span className="text-sm text-text-secondary">Hover me</span>
        </Tooltip>
      </Section>

      {/* Modal */}
      <Section title="Modal">
        <Button onClick={() => setModalOpen(true)}>Open Modal</Button>
        <Modal
          open={modalOpen}
          onClose={() => setModalOpen(false)}
          title="Example Modal"
          footer={
            <>
              <Button variant="ghost" onClick={() => setModalOpen(false)}>Cancel</Button>
              <Button onClick={() => setModalOpen(false)}>Confirm</Button>
            </>
          }
        >
          <p className="text-sm text-text-secondary">This is the modal content. Press ESC or click outside to close.</p>
        </Modal>
      </Section>

      {/* Drawer */}
      <Section title="Drawer">
        <Button onClick={() => setDrawerOpen(true)}>Open Drawer</Button>
        <Drawer
          open={drawerOpen}
          onClose={() => setDrawerOpen(false)}
          title="Example Drawer"
          footer={
            <>
              <Button variant="ghost" onClick={() => setDrawerOpen(false)}>Cancel</Button>
              <Button onClick={() => setDrawerOpen(false)}>Save</Button>
            </>
          }
        >
          <p className="text-sm text-text-secondary">Drawer content from the right side.</p>
        </Drawer>
      </Section>

      {/* Confirm Dialog */}
      <Section title="Confirm Dialog">
        <Button variant="danger" onClick={() => setConfirmOpen(true)}>Delete Item</Button>
        <ConfirmDialog
          open={confirmOpen}
          onClose={() => setConfirmOpen(false)}
          onConfirm={() => { setConfirmOpen(false); toast.success('Deleted!', 'Item was deleted.') }}
          title="Confirm Delete"
          message="Are you sure you want to delete this item? This action cannot be undone."
          confirmLabel="Delete"
          variant="danger"
        />
      </Section>

      {/* Tabs */}
      <Section title="Tabs">
        <Tabs value={tabValue} onValueChange={setTabValue}>
          <TabsList>
            <TabsTrigger value="tab1">Tab 1</TabsTrigger>
            <TabsTrigger value="tab2">Tab 2</TabsTrigger>
            <TabsTrigger value="tab3" disabled>Disabled</TabsTrigger>
          </TabsList>
          <TabsContent value="tab1">Content for Tab 1</TabsContent>
          <TabsContent value="tab2">Content for Tab 2</TabsContent>
          <TabsContent value="tab3">You shouldn't see this</TabsContent>
        </Tabs>
      </Section>

      {/* Accordion */}
      <Section title="Accordion">
        <Accordion type="single">
          <AccordionItem value="accordion1">
            <AccordionTrigger>Section 1</AccordionTrigger>
            <AccordionContent>Content for section 1.</AccordionContent>
          </AccordionItem>
          <AccordionItem value="accordion2">
            <AccordionTrigger>Section 2</AccordionTrigger>
            <AccordionContent>Content for section 2.</AccordionContent>
          </AccordionItem>
        </Accordion>
      </Section>

      {/* Dropdown Menu */}
      <Section title="Dropdown Menu">
        <div className="relative inline-flex">
          <DropdownMenu>
            <DropdownMenuTrigger>
              <Button variant="outline" iconRight={<ChevronRight className="h-4 w-4" />}>Menu</Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem onClick={() => toast.info('Profile')}>
                <User className="h-4 w-4" /> Profile
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => toast.info('Settings')}>
                <Settings className="h-4 w-4" /> Settings
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => toast.warning('Deleted')} danger>
                <Trash2 className="h-4 w-4" /> Delete
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </Section>

      {/* Breadcrumb */}
      <Section title="Breadcrumb">
        <Breadcrumb>
          <BreadcrumbItem href="/">Home</BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem href="/assessments">Assessments</BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem isCurrent>Current Page</BreadcrumbItem>
        </Breadcrumb>
      </Section>

      {/* Pagination */}
      <Section title="Pagination">
        <Pagination currentPage={page} totalPages={10} onPageChange={setPage} />
      </Section>

      {/* Empty State */}
      <Section title="Empty State">
        <EmptyState
          title="No items found"
          description="Get started by creating your first item."
          action={{ label: 'Create Item', onClick: () => toast.success('Creating...') }}
        />
      </Section>

      {/* Error State */}
      <Section title="Error State">
        <ErrorState onRetry={() => toast.info('Retrying...')} />
      </Section>

      {/* Loading State */}
      <Section title="Loading State">
        <LoadingState message="Fetching data..." />
      </Section>

      {/* Toast */}
      <Section title="Toast">
        <div className="flex flex-wrap gap-3">
          <Button onClick={() => toast.success('Success!', 'Operation completed.')}>Success Toast</Button>
          <Button onClick={() => toast.warning('Warning!', 'Check your input.')}>Warning Toast</Button>
          <Button variant="danger" onClick={() => toast.error('Error!', 'Something broke.')}>Error Toast</Button>
          <Button variant="outline" onClick={() => toast.info('Info', 'Here is some info.')}>Info Toast</Button>
        </div>
      </Section>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-4">
      <Divider />
      <h2 className="text-xl font-semibold text-text-primary">{title}</h2>
      {children}
    </section>
  )
}
