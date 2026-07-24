import { useState } from 'react'
import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/Tabs'
import { GeneralSection } from '@/components/features/settings/GeneralSection'
import { AppearanceSection } from '@/components/features/settings/AppearanceSection'
import { DashboardPreferencesSection } from '@/components/features/settings/DashboardPreferencesSection'
import { NotificationPreferencesSection } from '@/components/features/settings/NotificationPreferencesSection'
import { SecuritySection } from '@/components/features/settings/SecuritySection'
import { ApiSettingsSection } from '@/components/features/settings/ApiSettingsSection'
import { AboutSection } from '@/components/features/settings/AboutSection'

const tabs = [
  { value: 'general', label: 'General' },
  { value: 'appearance', label: 'Appearance' },
  { value: 'dashboard', label: 'Dashboard' },
  { value: 'notifications', label: 'Notifications' },
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
        <TabsContent value="dashboard"><DashboardPreferencesSection /></TabsContent>
        <TabsContent value="notifications"><NotificationPreferencesSection /></TabsContent>
        <TabsContent value="security"><SecuritySection /></TabsContent>
        <TabsContent value="api"><ApiSettingsSection /></TabsContent>
        <TabsContent value="about"><AboutSection /></TabsContent>
      </Tabs>
    </PageContainer>
  )
}
