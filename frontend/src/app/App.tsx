import { RouterProvider } from "react-router-dom"
import { router } from "./routes"
import { AuthProvider } from "@/features/auth/hooks/use-auth"
import { AppShell } from "./providers"

export function App(): React.ReactElement {
  return (
    <AppShell>
      <AuthProvider>
        <RouterProvider router={router} />
      </AuthProvider>
    </AppShell>
  )
}
