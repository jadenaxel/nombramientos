import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const seedSource = readFileSync(new URL("../scripts/seed-demo.ts", import.meta.url), "utf8");
const anchorSource = readFileSync(new URL("../scripts/audit-anchor.ts", import.meta.url), "utf8");
const backupSource = readFileSync(new URL("../src/backup.ts", import.meta.url), "utf8");

describe("numeric audit and outbox sequence ordering", () => {
  it("never orders a sequence::text projection through its textual output alias", () => {
    expect(seedSource).toContain("FROM audit_events ORDER BY audit_events.sequence");
    expect(anchorSource).toContain("FROM audit_events ORDER BY audit_events.sequence");
    expect(backupSource).toContain("ORDER BY audit_events.sequence DESC LIMIT 1");
    expect(backupSource).toContain("ORDER BY outbox_events.sequence DESC LIMIT 1");

    expect(seedSource).not.toMatch(/FROM audit_events ORDER BY sequence/u);
    expect(anchorSource).not.toMatch(/FROM audit_events ORDER BY sequence/u);
    expect(backupSource).not.toMatch(/FROM (?:audit_events|outbox_events) ORDER BY sequence/u);
  });

  it("documents the two-digit ordering regression that the qualified bigint order prevents", () => {
    const sequences = Array.from({ length: 12 }, (_, index) => String(index + 1));
    expect([...sequences].sort()).toEqual(["1", "10", "11", "12", "2", "3", "4", "5", "6", "7", "8", "9"]);
    expect([...sequences].sort((left, right) => Number(left) - Number(right))).toEqual(sequences);
  });
});
