import { Loader2Icon } from "lucide-react"

import { requireAccessibleLabel } from "@/components/ui/accessible-label"
import { cn } from "@/lib/utils"

type SpinnerBaseProps = Omit<
  React.ComponentProps<"svg">,
  "aria-hidden" | "aria-label" | "role"
>

type SpinnerProps = SpinnerBaseProps &
  (
    | { decorative: true; label?: never }
    | { decorative?: false; label: string }
  )

function Spinner({
  className,
  decorative = false,
  label,
  ...props
}: SpinnerProps) {
  const accessibleLabel = decorative
    ? undefined
    : requireAccessibleLabel(label, "SPINNER")

  return (
    <Loader2Icon
      role={decorative ? undefined : "status"}
      aria-hidden={decorative ? true : undefined}
      aria-label={accessibleLabel}
      className={cn("size-4 animate-spin", className)}
      {...props}
    />
  )
}

export { Spinner }
