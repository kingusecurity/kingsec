import { useState } from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/Tabs'
import { GeneralSection } from '@/components/features/settings/GeneralSection'
import { AppearanceSection } from '@/components/features/settings/AppearanceSection'
import { SecuritySection } from '@/components/features/settings/SecuritySection'
import { ApiSettingsSection } from '@/components/features/settings/ApiSettingsSection'
import { AboutSection } from '@/components/features/settings/AboutSection'
import { IntegrationsSection } from '@/components/features/settings/IntegrationsSection'
import { AiProviderSection } from '@/components/features/settings/AiProviderSection'
import { LicenseSection } from '@/components/features/settings/LicenseSection'
import { OrganizationSection } from '@/components/features/settings/OrganizationSection'

// Dashboard preferences and Notification preferences tabs were removed:
// both saved correctly to local storage, but nothing downstream ever read
// either set of values, so the controls had no effect. See
// docs/audits/dead-button-audit-2026-08.md.
const tabs = [
  { value: 'general', label: 'General' },
  { value: 'appearance', label: 'Appearance' },
  { value: 'license', label: 'License' },
  { value: 'organizations', label: 'Organizations' },
  { value: 'integrations', label: 'Integrations' },
  { value: 'ai-provider', label: 'AI Provider' },
  { value: 'security', label: 'Security' },
  { value: 'api', label: 'API' },
  { value: 'about', label: 'About' },
]

export function SettingsPage() {
  const [activeTab, setActiveTab] = useState('general')

  return (
    <PageContainer>
      <PageHeader title="Settings" description="Manage your application settings and preferences" />
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          {tabs.map((tab) => (
            <TabsTrigger key={tab.value} value={tab.value}>{tab.label}</TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="general"><GeneralSection /></TabsContent>
        <TabsContent value="appearance"><AppearanceSection /></TabsContent>
        <TabsContent value="license"><LicenseSection /></TabsContent>
        <TabsContent value="organizations"><OrganizationSection /></TabsContent>
        <TabsContent value="integrations"><IntegrationsSection /></TabsContent>
        <TabsContent value="ai-provider"><AiProviderSection /></TabsContent>
        <TabsContent value="security"><SecuritySection /></TabsContent>
        <TabsContent value="api"><ApiSettingsSection /></TabsContent>
        <TabsContent value="about"><AboutSection /></TabsContent>
      </Tabs>
    </PageContainer>
  )
}
