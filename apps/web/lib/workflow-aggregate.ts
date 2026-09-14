export type ProposalSubmissionPlaintext = {
  schema: "nombramientos-submission/v1";
  abstain: boolean;
  selections: string[];
};

export type ProposalAggregate = {
  schemaVersion: 1;
  sourceRoundId: string;
  sourceManifestHash: `sha256:${string}`;
  completedResponses: number;
  electorateDenominator: number;
  effectiveResponseDenominator: number;
  candidates: Array<{ memberId: string; distinctProponentCount: number }>;
};

export type ProposalCipherEnvelope = {
  readonly algorithm: "AES-256-GCM" | "XCHACHA20-POLY1305";
  readonly keyId: string;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly aad: string;
};

export type VerifiableProposalManifest = {
  readonly manifestHash: `sha256:${string}`;
  readonly schemaVersion: 1;
  readonly tenantId: string;
  readonly roundId: string;
  readonly roundVersion: number;
  readonly candidateSetHash: `sha256:${string}`;
  readonly rulesHash: `sha256:${string}`;
  readonly configurationHash: `sha256:${string}`;
  readonly electorateHash: `sha256:${string}`;
  readonly candidateIds: readonly string[];
  readonly entryCount: number;
  readonly entries: readonly {
    readonly position: number;
    readonly receiptId: string;
    readonly contentHash: `sha256:${string}`;
    readonly submissionRoundVersion: number;
    readonly envelope: ProposalCipherEnvelope;
  }[];
};

/**
 * Verifies the immutable closed-round manifest and every ciphertext before a
 * reviewer is allowed to decrypt proposals locally. The hash body mirrors the
 * server exactly and deliberately excludes transport-only envelope bytes.
 */
export async function verifyProposalManifest(manifest: VerifiableProposalManifest): Promise<void> {
  if (
    manifest.schemaVersion !== 1
    || !Number.isSafeInteger(manifest.roundVersion)
    || manifest.roundVersion <= 0
    || !Number.isSafeInteger(manifest.entryCount)
    || manifest.entryCount < 0
    || manifest.entries.length !== manifest.entryCount
  ) throw new Error("El manifiesto de propuestas no cumple el contrato inmutable.");

  if (
    new Set(manifest.candidateIds).size !== manifest.candidateIds.length
    || manifest.candidateIds.some((candidateId, index) => index > 0 && manifest.candidateIds[index - 1]! >= candidateId)
  ) throw new Error("El padrón de candidaturas del manifiesto no está ordenado o contiene duplicados.");

  const receiptIds = new Set<string>();
  for (const [index, entry] of manifest.entries.entries()) {
    if (
      entry.position !== index + 1
      || !Number.isSafeInteger(entry.submissionRoundVersion)
      || entry.submissionRoundVersion <= 0
      || receiptIds.has(entry.receiptId)
      || !/^sha256:[0-9a-f]{64}$/u.test(entry.contentHash)
    ) throw new Error("Las posiciones o recibos del manifiesto de propuestas son inválidos.");
    receiptIds.add(entry.receiptId);
    if (await proposalEnvelopeContentHash(entry.envelope) !== entry.contentHash) {
      throw new Error(`La huella cifrada de la propuesta en posición ${entry.position} no coincide.`);
    }
  }

  const expectedManifestHash = await workflowHash({
    schemaVersion: manifest.schemaVersion,
    tenantId: manifest.tenantId,
    roundId: manifest.roundId,
    roundVersion: manifest.roundVersion,
    candidateSetHash: manifest.candidateSetHash,
    rulesHash: manifest.rulesHash,
    configurationHash: manifest.configurationHash,
    electorateHash: manifest.electorateHash,
    candidateIds: [...manifest.candidateIds],
    entries: manifest.entries.map((entry) => ({
      position: entry.position,
      receiptId: entry.receiptId,
      contentHash: entry.contentHash,
      submissionRoundVersion: entry.submissionRoundVersion,
    })),
  });
  if (expectedManifestHash !== manifest.manifestHash) {
    throw new Error("La huella del manifiesto de propuestas no coincide con su contenido.");
  }
}

export async function proposalEnvelopeContentHash(envelope: ProposalCipherEnvelope): Promise<`sha256:${string}`> {
  const fixedJson = JSON.stringify({
    algorithm: envelope.algorithm,
    keyId: envelope.keyId,
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
    aad: envelope.aad,
  });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(fixedJson));
  return `sha256:${[...new Uint8Array(digest)].map((part) => part.toString(16).padStart(2, "0")).join("")}`;
}

export async function buildProposalAggregate(input: {
  manifest: {
    readonly manifestHash: `sha256:${string}`;
    readonly roundId: string;
    readonly entryCount: number;
    readonly candidateIds: readonly string[];
    readonly entries: readonly unknown[];
  };
  submissions: readonly ProposalSubmissionPlaintext[];
  maxProposalSelections: number;
}): Promise<{ aggregate: ProposalAggregate; aggregateHash: `sha256:${string}` }> {
  if (input.submissions.length !== input.manifest.entryCount || input.manifest.entries.length !== input.manifest.entryCount) {
    throw new Error("El conjunto descifrado no coincide con el manifiesto inmutable.");
  }
  if (!Number.isSafeInteger(input.maxProposalSelections) || input.maxProposalSelections <= 0) {
    throw new Error("El límite de propuestas congelado no es válido.");
  }
  const eligible = new Set(input.manifest.candidateIds);
  const counts = new Map<string, number>();
  let effectiveResponseDenominator = 0;
  for (const submission of input.submissions) {
    if (submission.schema !== "nombramientos-submission/v1" || typeof submission.abstain !== "boolean" || !Array.isArray(submission.selections)) {
      throw new Error("Una propuesta descifrada no cumple el contrato esperado.");
    }
    if (submission.selections.length > input.maxProposalSelections || new Set(submission.selections).size !== submission.selections.length) {
      throw new Error("Una propuesta excede el límite o repite una candidatura.");
    }
    if (submission.abstain !== (submission.selections.length === 0)) {
      throw new Error("La abstención y las selecciones de una propuesta son incoherentes.");
    }
    if (submission.selections.length > 0) effectiveResponseDenominator += 1;
    for (const memberId of submission.selections) {
      if (!eligible.has(memberId)) throw new Error("Una propuesta referencia una persona fuera del padrón congelado.");
      counts.set(memberId, (counts.get(memberId) ?? 0) + 1);
    }
  }
  const aggregate: ProposalAggregate = {
    schemaVersion: 1,
    sourceRoundId: input.manifest.roundId,
    sourceManifestHash: input.manifest.manifestHash,
    completedResponses: input.submissions.length,
    electorateDenominator: input.manifest.entryCount,
    effectiveResponseDenominator,
    candidates: [...counts.entries()]
      .map(([memberId, distinctProponentCount]) => ({ memberId, distinctProponentCount }))
      .sort((left, right) => left.memberId < right.memberId ? -1 : left.memberId > right.memberId ? 1 : 0),
  };
  return { aggregate, aggregateHash: await workflowHash(aggregate) };
}

export function canonicalWorkflowJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalWorkflowJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalWorkflowJson(record[key])}`).join(",")}}`;
}

export async function workflowHash(value: unknown): Promise<`sha256:${string}`> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalWorkflowJson(value)));
  return `sha256:${[...new Uint8Array(digest)].map((part) => part.toString(16).padStart(2, "0")).join("")}`;
}
