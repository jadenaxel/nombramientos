function requireAccessibleLabel(label: unknown, componentName: string): string {
  const normalizedLabel = typeof label === "string" ? label.trim() : ""

  if (!normalizedLabel) {
    throw new Error(`${componentName}_ACCESSIBLE_LABEL_REQUIRED`)
  }

  return normalizedLabel
}

export { requireAccessibleLabel }
