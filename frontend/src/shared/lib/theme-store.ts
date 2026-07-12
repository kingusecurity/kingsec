import { create } from "zustand"
import { persist } from "zustand/middleware"

export type ThemeName = "light" | "dark" | "cyber" | "terminal" | "corporate"

interface ThemeState {
  theme: ThemeName
  setTheme: (theme: ThemeName) => void
}

function applyTheme(theme: ThemeName): void {
  const root = document.documentElement
  root.classList.remove("light", "dark", "cyber", "terminal", "corporate")
  root.classList.add(theme)
}

export const useThemeStore = create<ThemeState>()(
  persist(
    (set) => ({
      theme: "dark",
      setTheme: (theme: ThemeName) => {
        applyTheme(theme)
        set({ theme })
      },
    }),
    {
      name: "kingsec-theme",
      onRehydrateStorage: () => (state) => {
        if (state?.theme) {
          applyTheme(state.theme)
        }
      },
    },
  ),
)

export const THEMES: Array<{ name: ThemeName; label: string }> = [
  { name: "light", label: "Light" },
  { name: "dark", label: "Dark" },
  { name: "cyber", label: "Cyber" },
  { name: "terminal", label: "Terminal" },
  { name: "corporate", label: "Corporate" },
]
