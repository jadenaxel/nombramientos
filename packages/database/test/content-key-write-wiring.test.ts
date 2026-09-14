import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { TENANT_RUNTIME_APPEND_ONLY_TABLES } from "../src/runtime-grant-contract.js";

const tenantStore = source("tenant-store.ts");
const workflowStore = source("core-workflow-store.ts");

describe("tenant content-key write guard wiring", () => {
  it("validates every supplied member/import/report envelope inside idempotent work", () => {
    expect(method(tenantStore, "createMember")).toMatch(/executeIdempotent[\s\S]*?assertWritableTenantContentKey[\s\S]*?envelopes: \[input\.displayEnvelope, input\.contactEnvelope, input\.eligibilityEnvelope\]/u);
    expect(method(tenantStore, "updateMember")).toMatch(/executeIdempotent[\s\S]*?assertWritableTenantContentKey[\s\S]*?envelopes: \[input\.displayEnvelope, input\.contactEnvelope, input\.eligibilityEnvelope\]/u);
    expect(method(tenantStore, "previewImport")).toMatch(/executeIdempotent[\s\S]*?assertWritableTenantContentKey[\s\S]*?input\.rows\.flatMap\(\(\{ displayEnvelope, contactEnvelope \}\)/u);
    expect(method(tenantStore, "commitImport")).toMatch(/executeIdempotent[\s\S]*?preview_envelopes[\s\S]*?assertWritableTenantContentKey[\s\S]*?actionableRows\.flatMap/u);
    expect(method(tenantStore, "completeReport")).toMatch(/executeIdempotent[\s\S]*?assertWritableTenantContentKey[\s\S]*?envelopes: \[input\.envelope\]/u);
    expect(method(tenantStore, "updateAssignment")).toMatch(/executeIdempotent[\s\S]*?assertWritableTenantContentKey[\s\S]*?envelopes: \[input\.envelope\]/u);
  });

  it("covers all incoming workflow content envelopes but not proposal/ballot ciphertext", () => {
    const expectations: Readonly<Record<string, RegExp>> = {
      addSession: /envelopes: \[input\.titleEnvelope, input\.locationEnvelope\]/u,
      updateSession: /envelopes: \[input\.titleEnvelope, input\.locationEnvelope\]/u,
      addSessionAgendaItem: /envelopes: \[input\.titleEnvelope, input\.notesEnvelope\]/u,
      recordSessionDecision: /envelopes: \[input\.evidenceEnvelope\]/u,
      configureCommittee: /input\.members\.map\(\(\{ displayEnvelope \}\) => displayEnvelope\)/u,
      resolveEligibilityPause: /envelopes: \[input\.evidenceEnvelope\]/u,
      reviewCandidacy: /envelopes: \[input\.rationaleEnvelope, input\.restrictedNoteEnvelope\]/u,
      createLinkedDesignation: /envelopes: \[input\.evidenceEnvelope\]/u,
      recordAssignmentConsent: /envelopes: \[input\.envelope\]/u,
      presentAssignment: /envelopes: \[input\.envelope\]/u,
      recordCongregationalDecision: /envelopes: \[input\.envelope\]/u,
      endAssignment: /envelopes: \[input\.evidenceEnvelope\]/u,
    };
    for (const [name, pattern] of Object.entries(expectations)) {
      const body = method(workflowStore, name);
      expect(body, name).toContain("executeIdempotent");
      expect(body, name).toMatch(pattern);
    }
    expect(method(tenantStore, "submit")).not.toContain("assertWritableTenantContentKey");
    expect(method(workflowStore, "createProposalManifest")).not.toContain("assertWritableTenantContentKey");
  });

  it("persists eligibility pauses before key validation and replays before invoking guarded work", () => {
    for (const name of ["recordAssignmentConsent", "presentAssignment", "recordCongregationalDecision"]) {
      const body = method(workflowStore, name);
      const pause = body.indexOf("ensureAssignmentMayAdvance");
      const guard = body.indexOf("assertWritableTenantContentKey");
      const write = body.indexOf("UPDATE assignments");
      expect(pause, `${name} eligibility check`).toBeGreaterThanOrEqual(0);
      expect(guard, `${name} content-key guard`).toBeGreaterThan(pause);
      expect(write, `${name} first ciphertext write`).toBeGreaterThan(guard);
    }
    for (const store of [tenantStore, workflowStore]) {
      const idempotency = method(store, "executeIdempotent");
      expect(idempotency.indexOf("return row.response_body")).toBeLessThan(idempotency.indexOf("await work()"));
    }
  });
});

describe("append-only proposal manifest privilege boundary", () => {
  it("serializes consolidation with round and process locks without locking the immutable manifest", () => {
    expect(TENANT_RUNTIME_APPEND_ONLY_TABLES).toContain("proposal_manifests");

    const body = method(workflowStore, "consolidateProposals");
    const roundLock = body.indexOf("await this.lockRound");
    const processLock = body.indexOf("await this.lockProcess");
    const manifestRead = body.indexOf("FROM proposal_manifests");
    expect(roundLock).toBeGreaterThanOrEqual(0);
    expect(processLock).toBeGreaterThan(roundLock);
    expect(manifestRead).toBeGreaterThan(processLock);
    expect(method(workflowStore, "lockRound")).toMatch(/FOR UPDATE OF round_state/u);
    expect(method(workflowStore, "lockProcess")).toMatch(/FOR UPDATE/u);

    const queryStart = body.lastIndexOf("`SELECT", manifestRead);
    const queryEnd = body.indexOf("`,", manifestRead);
    expect(queryStart).toBeGreaterThanOrEqual(0);
    expect(queryEnd).toBeGreaterThan(manifestRead);
    const manifestQuery = body.slice(queryStart, queryEnd + 1);
    expect(manifestQuery).not.toMatch(/\bFOR\s+(?:NO\s+KEY\s+UPDATE|UPDATE|SHARE|KEY\s+SHARE)\b/u);
  });
});

function source(filename: string): string {
  return readFileSync(new URL(`../src/${filename}`, import.meta.url), "utf8");
}

function method(contents: string, name: string): string {
  const start = [
    contents.indexOf(`public async ${name}`),
    contents.indexOf(`private async ${name}`),
  ].filter((value) => value >= 0).sort((left, right) => left - right)[0] ?? -1;
  if (start < 0) throw new Error(`Missing method ${name}`);
  const nextPublic = contents.indexOf("\n  public async ", start + 1);
  const nextPrivate = contents.indexOf("\n  private async ", start + 1);
  const candidates = [nextPublic, nextPrivate].filter((value) => value >= 0);
  const end = candidates.length > 0 ? Math.min(...candidates) : contents.length;
  return contents.slice(start, end);
}
