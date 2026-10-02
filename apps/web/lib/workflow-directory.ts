type MemberPage<T> = { items: T[]; total: number; nextCursor?: string | null };

export async function loadWorkflowMemberDirectory<T>(
  readPage: (cursor?: string) => Promise<MemberPage<T>>,
): Promise<{ items: T[]; total: number }> {
  const items: T[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | undefined;
  let total = 0;
  for (let pageNumber = 0; pageNumber < 100; pageNumber += 1) {
    const page = await readPage(cursor);
    items.push(...page.items);
    // The API total is scoped to the remaining cursor range on later pages.
    if (pageNumber === 0) total = page.total;
    if (!page.nextCursor) return { items, total: Math.max(total, items.length) };
    if (seenCursors.has(page.nextCursor)) throw new Error("MEMBER_DIRECTORY_PAGINATION_INVALID");
    seenCursors.add(page.nextCursor);
    cursor = page.nextCursor;
  }
  throw new Error("MEMBER_DIRECTORY_PAGINATION_LIMIT");
}

export function candidacyCanBeSelected(state: string): boolean {
  return ["UNDER_REVIEW", "PRELIMINARY_ACCEPTED", "CONFIRMED_FOR_BALLOT"].includes(state);
}

export function selectedReviewCandidacyIds(
  candidates: readonly { id: string; state: string }[],
  overrides: Readonly<Record<string, boolean>>,
): string[] {
  return candidates.filter((candidate) => candidacyCanBeSelected(candidate.state)
    && (overrides[candidate.id] ?? true)).map(({ id }) => id);
}
