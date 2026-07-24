import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card'
import { RadioGroup, RadioGroupItem } from '@/components/ui/RadioGroup'
import { useAppearance } from '@/hooks/use-appearance'

export function AppearanceSection() {
  const { theme, setTheme } = useAppearance()

  return (
    <Card>
      <CardHeader>
        <CardTitle>Appearance</CardTitle>
        <CardDescription>Customize the look and feel of the application</CardDescription>
      </CardHeader>
      <div className="p-5 space-y-4">
        <div>
          <p className="text-sm font-medium text-text-primary mb-3">Theme</p>
          <RadioGroup value={theme} onValueChange={(v) => setTheme(v as 'dark' | 'light' | 'system')}>
            <RadioGroupItem value="dark" label="Dark" />
            <RadioGroupItem value="light" label="Light" />
            <RadioGroupItem value="system" label="System" />
          </RadioGroup>
        </div>
      </div>
    </Card>
  )
}
