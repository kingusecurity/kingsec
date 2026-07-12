import { useThemeStore, THEMES, type ThemeName } from "@/shared/lib/theme-store"
import { Button } from "@/shared/ui/button"
import { cn } from "@/shared/lib/utils"

interface ThemeSwitcherProps {
  className?: string
  variant?: "dropdown" | "pills"
}

export function ThemeSwitcher({ className, variant = "pills" }: ThemeSwitcherProps): React.ReactElement {
  const { theme, setTheme } = useThemeStore()

  if (variant === "pills") {
    return (
      <div className={cn("flex flex-wrap gap-1", className)}>
        {THEMES.map((t) => (
          <Button
            key={t.name}
            variant={theme === t.name ? "default" : "ghost"}
            size="sm"
            className="h-7 px-2 text-xs"
            onClick={() => setTheme(t.name)}
          >
            {t.label}
          </Button>
        ))}
      </div>
    )
  }

  return (
    <select
      value={theme}
      onChange={(e) => setTheme(e.target.value as ThemeName)}
      className={cn(
        "h-8 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--bg))] px-2 text-xs text-[hsl(var(--fg))]",
        className,
      )}
    >
      {THEMES.map((t) => (
        <option key={t.name} value={t.name}>
          {t.label}
        </option>
      ))}
    </select>
  )
}
