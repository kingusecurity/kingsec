import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/shared/lib/utils"

const buttonVariants = cva(
  "inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[hsl(var(--ring))] focus-visible:ring-offset-2 focus-visible:ring-offset-[hsl(var(--bg))] disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "bg-[hsl(var(--primary))] text-[hsl(var(--primary-fg))] hover:bg-[hsl(var(--primary))]/90",
        destructive: "bg-[hsl(var(--destructive))] text-[hsl(var(--destructive-fg))] hover:bg-[hsl(var(--destructive))]/90",
        outline: "border border-[hsl(var(--border))] bg-[hsl(var(--bg))] text-[hsl(var(--fg))] hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--accent-fg))]",
        secondary: "bg-[hsl(var(--muted))] text-[hsl(var(--muted-fg))] hover:bg-[hsl(var(--muted))]/80",
        ghost: "text-[hsl(var(--fg))] hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--accent-fg))]",
        link: "text-[hsl(var(--primary))] underline-offset-4 hover:underline",
      },
      size: {
        default: "h-10 px-4 py-2",
        sm: "h-9 rounded-md px-3",
        lg: "h-11 rounded-md px-8",
        icon: "h-10 w-10",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button
      className={cn(buttonVariants({ variant, size, className }))}
      ref={ref}
      {...props}
    />
  ),
)
Button.displayName = "Button"

export { Button, buttonVariants }
