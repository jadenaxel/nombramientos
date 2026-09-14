import * as React from "react"
import {
  ChevronLeftIcon,
  ChevronRightIcon,
  MoreHorizontalIcon,
} from "lucide-react"

import { cn } from "@/lib/utils"
import { requireAccessibleLabel } from "@/components/ui/accessible-label"
import { buttonVariants, type Button } from "@/components/ui/button"

type PaginationProps = Omit<React.ComponentProps<"nav">, "aria-label"> & {
  accessibleLabel: string
}

type PaginationDirectionProps = Omit<
  React.ComponentProps<typeof PaginationLink>,
  "aria-label" | "children"
> & {
  label: string
}

function Pagination({
  accessibleLabel,
  className,
  ...props
}: PaginationProps) {
  return (
    <nav
      role="navigation"
      aria-label={requireAccessibleLabel(accessibleLabel, "PAGINATION")}
      data-slot="pagination"
      className={cn("mx-auto flex w-full justify-center", className)}
      {...props}
    />
  )
}

function PaginationContent({
  className,
  ...props
}: React.ComponentProps<"ul">) {
  return (
    <ul
      data-slot="pagination-content"
      className={cn("flex flex-row items-center gap-1", className)}
      {...props}
    />
  )
}

function PaginationItem({ ...props }: React.ComponentProps<"li">) {
  return <li data-slot="pagination-item" {...props} />
}

type PaginationLinkProps = {
  isActive?: boolean
} & Pick<React.ComponentProps<typeof Button>, "size"> &
  React.ComponentProps<"a">

function PaginationLink({
  className,
  isActive,
  size = "icon",
  ...props
}: PaginationLinkProps) {
  return (
    <a
      aria-current={isActive ? "page" : undefined}
      data-slot="pagination-link"
      data-active={isActive}
      className={cn(
        buttonVariants({
          variant: isActive ? "outline" : "ghost",
          size,
        }),
        className
      )}
      {...props}
    />
  )
}

function PaginationPrevious({
  className,
  label,
  ...props
}: PaginationDirectionProps) {
  const accessibleLabel = requireAccessibleLabel(label, "PAGINATION_PREVIOUS")

  return (
    <PaginationLink
      aria-label={accessibleLabel}
      size="default"
      className={cn("gap-1 px-2.5 sm:pl-2.5", className)}
      {...props}
    >
      <ChevronLeftIcon aria-hidden="true" />
      <span className="hidden sm:block">{accessibleLabel}</span>
    </PaginationLink>
  )
}

function PaginationNext({
  className,
  label,
  ...props
}: PaginationDirectionProps) {
  const accessibleLabel = requireAccessibleLabel(label, "PAGINATION_NEXT")

  return (
    <PaginationLink
      aria-label={accessibleLabel}
      size="default"
      className={cn("gap-1 px-2.5 sm:pr-2.5", className)}
      {...props}
    >
      <span className="hidden sm:block">{accessibleLabel}</span>
      <ChevronRightIcon aria-hidden="true" />
    </PaginationLink>
  )
}

function PaginationEllipsis({
  className,
  ...props
}: React.ComponentProps<"span">) {
  return (
    <span
      aria-hidden
      data-slot="pagination-ellipsis"
      className={cn("flex size-9 items-center justify-center", className)}
      {...props}
    >
      <MoreHorizontalIcon aria-hidden="true" className="size-4" />
    </span>
  )
}

export {
  Pagination,
  PaginationContent,
  PaginationLink,
  PaginationItem,
  PaginationPrevious,
  PaginationNext,
  PaginationEllipsis,
}
