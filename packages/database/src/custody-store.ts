import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { appendTenantAuditEventV2 } from "./audit-event-chain.js";
import {
  acquireMemberEligibilityPolicySharedLock,
  MemberEligibilityGuardError,
  requireRoundCandidatesOperationallyEligible,
} from "./member-eligibility-guard.js";
import { CUSTODY_KEY_REVOKE_REASON_CODES, normalizeAllowedReasonCode } from "./reason-code.js";
import { validateTallyAggregate, type TallyAggregate } from "./custody-aggregate.js";
import {
  CUSTODY_HPKE_SUITE,
  CUSTODY_SIGNING_ALGORITHM,
  CustodyError,
  buildTallyAttestationContext,
  canonicalCustodyJson,
  custodySha256,
  hashCanonicalCustodyJson,
  validateCustodianKeyMaterial,
  validateEncryptedBallotEnvelope,
  verifyTallyAttestation,
  type CustodianKeyMaterial,
  type FrozenRecipient,
} from "./custody-crypto.js";

interface CustodianKeyRow {
  readonly id: string;
  readonly custodian_identity_id: string;
  readonly device_id: string;
  readonly recipient_id: string;
  readonly key_version: number;
  readonly status: "active" | "superseded" | "revoked";
  readonly hpke_kem: typeof CUSTODY_HPKE_SUITE.kem;
  readonly hpke_kdf: typeof CUSTODY_HPKE_SUITE.kdf;
  readonly hpke_aead: typeof CUSTODY_HPKE_SUITE.aead;
  readonly hpke_public_key: string;
  readonly hpke_fingerprint: string;
  readonly signing_algorithm: typeof CUSTODY_SIGNING_ALGORITHM;
  readonly signing_public_key_spki: string;
  readonly signing_fingerprint: string;
  readonly registered_at: Date;
  readonly revoked_at: Date | null;
}

interface RoundRow {
  readonly id: string;
  readonly cycle_id: string;
  readonly phase: string;
  readonly submission_kind: "proposal" | "vote";
  readonly candidate_set_hash: string;
  readonly rules_hash: string;
  readonly vacancies: number;
  readonly max_selections: number;
  readonly decision_rule: unknown;
  readonly version: number;
}

interface CustodySetRow {
  readonly round_id: string;
  readonly round_version: number;
  readonly decision_rule: unknown;
  readonly version: number;
  readonly frozen_at: Date;
}

interface SnapshotRow {
  readonly round_id: string;
  readonly custodian_identity_id: string;
  readonly device_id: string;
  readonly source_key_id: string;
  readonly recipient_id: string;
  readonly key_version: number;
  readonly hpke_kem: typeof CUSTODY_HPKE_SUITE.kem;
  readonly hpke_kdf: typeof CUSTODY_HPKE_SUITE.kdf;
  readonly hpke_aead: typeof CUSTODY_HPKE_SUITE.aead;
  readonly hpke_public_key: string;
  readonly hpke_fingerprint: string;
  readonly signing_algorithm: typeof CUSTODY_SIGNING_ALGORITHM;
  readonly signing_public_key_spki: string;
  readonly signing_fingerprint: string;
  readonly key_status: "active" | "superseded" | "revoked" | null;
}

interface ManifestRow {
  readonly id: string;
  readonly round_id: string;
  readonly custody_version: number;
  readonly round_version: number;
  readonly decision_rule: unknown;
  readonly manifest_hash: string;
  readonly entry_count: number;
  readonly state: "awaiting_attestations" | "publishable" | "disputed" | "published";
  readonly agreed_aggregate_hash: string | null;
  readonly agreed_aggregate: TallyAggregate | null;
  readonly version: number;
  readonly created_at: Date;
  readonly published_at: Date | null;
}

interface SubmissionManifestRow {
  readonly receipt_id: string | null;
  readonly receipt_content_hash: string | null;
  readonly content_hash: string;
  readonly envelope: unknown;
  readonly round_version: number;
}

interface ValidatedManifestEntry {
  readonly receiptId: string;
  readonly contentHash: string;
  readonly envelopeHash: string;
  readonly envelope: unknown;
}

export interface RegisterCustodianKeyInput extends CustodianKeyMaterial {
  readonly identityId: string;
  readonly idempotencyKey: string;
  readonly deviceId: string;
  readonly expectedVersion: number;
}

export interface RevokeCustodianKeyInput {
  readonly identityId: string;
  readonly idempotencyKey: string;
  readonly keyId: string;
  readonly expectedVersion: number;
  readonly reasonCode: string;
}

export interface SubmitHpkeBallotInput {
  readonly identityId: string;
  readonly idempotencyKey: string;
  readonly roundId: string;
  readonly expectedVersion: number;
  readonly envelope: unknown;
  readonly contentHash: string;
}

export interface FreezeRoundCustodyInput {
  readonly identityId: string;
  readonly idempotencyKey: string;
  readonly roundId: string;
  readonly expectedRoundVersion: number;
  readonly keyIds: readonly string[];
}

export interface CreateTallyManifestInput {
  readonly identityId: string;
  readonly idempotencyKey: string;
  readonly roundId: string;
  readonly expectedRoundVersion: number;
  readonly expectedCustodyVersion: number;
}

export interface AttestTallyManifestInput {
  readonly identityId: string;
  readonly idempotencyKey: string;
  readonly roundId: string;
  readonly expectedManifestVersion: number;
  readonly aggregate: unknown;
  readonly signature: string;
}

export interface PublishTallyAggregateInput {
  readonly identityId: string;
  readonly idempotencyKey: string;
  readonly roundId: string;
  readonly expectedRoundVersion: number;
  readonly expectedManifestVersion: number;
}

export class CustodyStore {
  public constructor(private readonly client: PoolClient) {}

  public async registerKey(input: RegisterCustodianKeyInput): Promise<Record<string, unknown>> {
    validateCustodianKeyMaterial({
      recipientId: input.recipientId,
      suite: input.suite,
      hpkePublicKey: input.hpkePublicKey,
      hpkeFingerprint: input.hpkeFingerprint,
      signingAlgorithm: input.signingAlgorithm,
      signingPublicKeySpki: input.signingPublicKeySpki,
      signingFingerprint: input.signingFingerprint,
    });
    return this.executeIdempotent(input.identityId, "custody.key.register", input.idempotencyKey, input, async () => {
      const previous = await this.client.query<CustodianKeyRow>(
        `${KEY_SELECT}
          WHERE custodian_identity_id=$1 AND device_id=$2
          ORDER BY key_version DESC LIMIT 1 FOR UPDATE`,
        [input.identityId, input.deviceId],
      );
      const latest = previous.rows[0];
      const latestVersion = latest?.key_version ?? 0;
      if (latestVersion !== input.expectedVersion) {
        throw conflict("VERSION_CONFLICT", "Custodian device key version is stale");
      }
      if (latest?.status === "active") {
        await this.client.query(
          "UPDATE custodian_device_keys SET status='superseded' WHERE id=$1 AND status='active'",
          [latest.id],
        );
      }

      const keyId = randomUUID();
      const keyVersion = latestVersion + 1;
      const inserted = await this.client.query<{ registered_at: Date }>(
        `INSERT INTO custodian_device_keys(
           id,custodian_identity_id,device_id,recipient_id,key_version,status,
           hpke_kem,hpke_kdf,hpke_aead,hpke_public_key,hpke_fingerprint,
           signing_algorithm,signing_public_key_spki,signing_fingerprint,registered_by_identity_id
         ) VALUES ($1,$2,$3,$4,$5,'active',$6,$7,$8,$9,$10,$11,$12,$13,$2)
         RETURNING registered_at`,
        [
          keyId,
          input.identityId,
          input.deviceId,
          input.recipientId,
          keyVersion,
          input.suite.kem,
          input.suite.kdf,
          input.suite.aead,
          input.hpkePublicKey,
          input.hpkeFingerprint,
          input.signingAlgorithm,
          input.signingPublicKeySpki,
          input.signingFingerprint,
        ],
      ).catch((error: unknown) => {
        if (postgresCode(error) === "23505") {
          throw conflict("KEY_MATERIAL_REUSED", "Custodian recipient or public-key fingerprint is already active or was reused");
        }
        throw error;
      });
      const registeredAt = inserted.rows[0]?.registered_at;
      if (!registeredAt) throw new Error("Custodian key insertion did not return a timestamp");
      await this.appendAudit("custody.key.registered", "custodian_key", keyId, "success", {
        deviceId: input.deviceId,
        keyVersion,
        recipientId: input.recipientId,
        hpkeFingerprint: input.hpkeFingerprint,
        signingFingerprint: input.signingFingerprint,
        replacedKeyId: latest?.id ?? null,
      });
      await this.emit("custody.key.changed", "custodian_key", keyId, {
        keyId,
        keyVersion,
        status: "active",
      });
      return {
        keyId,
        recipientId: input.recipientId,
        deviceId: input.deviceId,
        version: keyVersion,
        status: "active",
        hpkeFingerprint: input.hpkeFingerprint,
        signingFingerprint: input.signingFingerprint,
        registeredAt: registeredAt.toISOString(),
      };
    });
  }

  public async listKeys(): Promise<readonly Record<string, unknown>[]> {
    const result = await this.client.query<CustodianKeyRow>(
      `${KEY_SELECT} ORDER BY custodian_identity_id,device_id,key_version DESC`,
    );
    return result.rows.map(publicKeyRecord);
  }

  public async submitBallot(input: SubmitHpkeBallotInput): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "round.vote.submit", input.idempotencyKey, input, async () => {
      const round = await this.lockRound(input.roundId);
      if (round.version !== input.expectedVersion) throw conflict("VERSION_CONFLICT", "Round version is stale");
      if (round.submission_kind !== "vote" || round.phase !== "VOTACION_ABIERTA") {
        throw conflict("ROUND_CLOSED", "Round is not accepting encrypted ballots");
      }
      await this.requireOperationalCandidateEligibility(input.roundId);
      const snapshots = await this.requireUsableSnapshots(input.roundId);
      validateEncryptedBallotEnvelope(input.envelope, input.contentHash, {
        tenantId: await this.tenantId(),
        cycleId: round.cycle_id,
        roundId: round.id,
        submissionRoundVersion: round.version,
        candidateSetHash: round.candidate_set_hash,
        rulesHash: round.rules_hash,
        recipients: snapshots.map((snapshot) => ({
          recipientId: snapshot.recipient_id,
          hpkeFingerprint: snapshot.hpke_fingerprint,
        })),
      });
      const elector = await this.client.query(
        `SELECT 1 FROM round_elector_snapshots
          WHERE round_id=$1 AND identity_id=$2 AND can_submit AND NOT recused`,
        [input.roundId, input.identityId],
      );
      if (elector.rowCount !== 1) throw conflict("NOT_AN_ELECTOR", "Identity is not in the frozen electorate");
      const submission = await this.client.query<{ id: string; received_at: Date }>(
        `INSERT INTO encrypted_submissions(
           round_id,elector_identity_id,kind,envelope,content_hash,round_version
         ) VALUES ($1,$2,'vote',$3,$4,$5) RETURNING id,received_at`,
        [input.roundId, input.identityId, input.envelope, input.contentHash, round.version],
      ).catch((error: unknown) => {
        if (postgresCode(error) === "23505") {
          throw conflict("ALREADY_SUBMITTED", "A final ballot already exists for this elector");
        }
        throw error;
      });
      const stored = submission.rows[0];
      if (!stored) throw new Error("Encrypted ballot insertion did not return a row");
      const receipt = await this.client.query<{ id: string }>(
        `INSERT INTO participation_receipts(
           submission_id,round_id,elector_identity_id,kind,content_hash,received_at
         ) VALUES ($1,$2,$3,'vote',$4,$5) RETURNING id`,
        [stored.id, input.roundId, input.identityId, input.contentHash, stored.received_at],
      );
      const receiptId = receipt.rows[0]?.id;
      if (!receiptId) throw new Error("Encrypted ballot receipt insertion did not return a row");
      await this.emit("round.participation", "round", input.roundId, { roundId: input.roundId });
      await this.appendAudit("round.submission.received", "round", input.roundId, "success", {
        kind: "vote",
        receiptId,
        custodyVersion: (await this.requireCustodySet(input.roundId)).version,
      });
      return {
        receiptId,
        receivedAt: stored.received_at.toISOString(),
        roundId: input.roundId,
        roundVersion: round.version,
        contentHash: input.contentHash,
        status: "received",
      };
    });
  }

  public async revokeKey(input: RevokeCustodianKeyInput): Promise<Record<string, unknown>> {
    const reasonCode = normalizeAllowedReasonCode(input.reasonCode, CUSTODY_KEY_REVOKE_REASON_CODES);
    if (!reasonCode) throw conflict("INVALID_REASON_CODE", "Custody key revocation reason code is not allowed");
    return this.executeIdempotent(input.identityId, "custody.key.revoke", input.idempotencyKey, { ...input, reasonCode }, async () => {
      const result = await this.client.query<CustodianKeyRow>(
        `${KEY_SELECT} WHERE id=$1 AND custodian_identity_id=$2 FOR UPDATE`,
        [input.keyId, input.identityId],
      );
      const key = result.rows[0];
      if (!key) throw new CustodyError(404, "CUSTODY_KEY_NOT_FOUND", "Custodian key is unavailable");
      if (key.key_version !== input.expectedVersion) {
        throw conflict("VERSION_CONFLICT", "Custodian key version is stale");
      }
      if (key.status !== "active") throw conflict("KEY_NOT_ACTIVE", "Custodian key is not active");
      const updated = await this.client.query<{ revoked_at: Date }>(
        `UPDATE custodian_device_keys
            SET status='revoked',revoked_by_identity_id=$2,revoked_at=clock_timestamp(),revocation_reason=$3
          WHERE id=$1 AND status='active' RETURNING revoked_at`,
        [input.keyId, input.identityId, reasonCode],
      );
      const revokedAt = updated.rows[0]?.revoked_at;
      if (!revokedAt) throw conflict("KEY_NOT_ACTIVE", "Custodian key could not be revoked");
      const affected = await this.client.query<{ count: number }>(
        "SELECT count(*)::int AS count FROM round_custodian_key_snapshots WHERE source_key_id=$1",
        [input.keyId],
      );
      await this.appendAudit("custody.key.revoked", "custodian_key", input.keyId, "success", {
        deviceId: key.device_id,
        keyVersion: key.key_version,
        reasonCode,
        affectedFrozenRounds: affected.rows[0]?.count ?? 0,
      });
      await this.emit("custody.key.changed", "custodian_key", input.keyId, {
        keyId: input.keyId,
        keyVersion: key.key_version,
        status: "revoked",
      });
      return {
        keyId: input.keyId,
        version: key.key_version,
        status: "revoked",
        revokedAt: revokedAt.toISOString(),
        affectedFrozenRounds: affected.rows[0]?.count ?? 0,
      };
    });
  }

  public async freezeRound(input: FreezeRoundCustodyInput): Promise<Record<string, unknown>> {
    if (input.keyIds.length < 2 || new Set(input.keyIds).size !== input.keyIds.length) {
      throw new CustodyError(400, "CUSTODY_VALIDATION_ERROR", "At least two distinct keyIds are required");
    }
    return this.executeIdempotent(input.identityId, "custody.round.freeze", input.idempotencyKey, input, async () => {
      const round = await this.lockRound(input.roundId);
      if (round.version !== input.expectedRoundVersion) throw conflict("VERSION_CONFLICT", "Round version is stale");
      if (round.submission_kind !== "vote" || !["LISTA_CONFIRMADA", "VOTACION_ABIERTA"].includes(round.phase)) {
        throw conflict("PHASE_CONFLICT", "Custody can only freeze for a prepared or newly-open vote round");
      }
      const submissionCount = await this.client.query<{ count: number }>(
        "SELECT count(*)::int AS count FROM encrypted_submissions WHERE round_id=$1 AND kind='vote'",
        [input.roundId],
      );
      if ((submissionCount.rows[0]?.count ?? 0) !== 0) {
        throw conflict("CUSTODY_FREEZE_TOO_LATE", "Custody cannot freeze after the first ballot");
      }
      const existing = await this.client.query("SELECT 1 FROM round_custody_sets WHERE round_id=$1", [input.roundId]);
      if (existing.rowCount !== 0) throw conflict("CUSTODY_ALREADY_FROZEN", "Round custody is already frozen");

      const keys = await this.client.query<CustodianKeyRow>(
        `${KEY_SELECT} WHERE id=ANY($1::uuid[]) AND status='active' ORDER BY custodian_identity_id FOR SHARE`,
        [[...input.keyIds]],
      );
      if (keys.rowCount !== input.keyIds.length) {
        throw conflict("CUSTODY_KEY_UNAVAILABLE", "Every selected custody key must exist and be active in this tenant");
      }
      if (new Set(keys.rows.map((key) => key.custodian_identity_id)).size < 2) {
        throw conflict("CUSTODIANS_NOT_DISTINCT", "At least two distinct custodian identities are required");
      }
      for (const key of keys.rows) validateCustodianKeyMaterial(keyMaterialFromRow(key));

      await this.client.query(
        `INSERT INTO round_custody_sets(round_id,round_version,version,decision_rule,frozen_by_identity_id)
         VALUES ($1,$2,1,$3,$4)`,
        [input.roundId, round.version, round.decision_rule, input.identityId],
      );
      for (const key of keys.rows) {
        await this.client.query(
          `INSERT INTO round_custodian_key_snapshots(
             round_id,custodian_identity_id,device_id,source_key_id,recipient_id,key_version,
             hpke_kem,hpke_kdf,hpke_aead,hpke_public_key,hpke_fingerprint,
             signing_algorithm,signing_public_key_spki,signing_fingerprint
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
          [
            input.roundId,
            key.custodian_identity_id,
            key.device_id,
            key.id,
            key.recipient_id,
            key.key_version,
            key.hpke_kem,
            key.hpke_kdf,
            key.hpke_aead,
            key.hpke_public_key,
            key.hpke_fingerprint,
            key.signing_algorithm,
            key.signing_public_key_spki,
            key.signing_fingerprint,
          ],
        );
      }
      await this.appendAudit("custody.round.frozen", "round", input.roundId, "success", {
        roundVersion: round.version,
        custodyVersion: 1,
        custodianCount: keys.rows.length,
        keyIds: keys.rows.map((key) => key.id),
      });
      await this.emit("custody.round.frozen", "round", input.roundId, {
        roundId: input.roundId,
        version: 1,
        custodianCount: keys.rows.length,
      });
      return {
        roundId: input.roundId,
        roundVersion: round.version,
        version: 1,
        state: "frozen",
        custodians: keys.rows.map(publicKeyRecord),
      };
    });
  }

  public async getRoundCustody(roundId: string): Promise<Record<string, unknown> | null> {
    const set = await this.client.query<CustodySetRow>(
      "SELECT round_id,round_version,version,decision_rule,frozen_at FROM round_custody_sets WHERE round_id=$1",
      [roundId],
    );
    const custody = set.rows[0];
    if (!custody) return null;
    const snapshots = await this.loadSnapshots(roundId);
    return {
      roundId,
      roundVersion: custody.round_version,
      version: custody.version,
      decisionRule: custody.decision_rule,
      frozenAt: custody.frozen_at,
      custodians: snapshots.map(snapshotPublicRecord),
    };
  }

  public async getBallotRecipients(
    roundId: string,
    identityId: string,
    expectedTenantId: string,
  ): Promise<Record<string, unknown>> {
    const tenantId = await this.tenantId();
    if (tenantId !== expectedTenantId) {
      throw new CustodyError(403, "CUSTODY_TENANT_MISMATCH", "Custody recipients belong to another tenant");
    }
    const round = await this.requireRound(roundId);
    if (round.submission_kind !== "vote" || round.phase !== "VOTACION_ABIERTA") {
      throw conflict("PHASE_CONFLICT", "Ballot recipients are available only while this vote is open");
    }
    const elector = await this.client.query(
      `SELECT 1 FROM round_elector_snapshots
        WHERE round_id=$1 AND identity_id=$2 AND can_submit AND NOT recused`,
      [roundId, identityId],
    );
    if (elector.rowCount !== 1) {
      throw new CustodyError(403, "NOT_AN_ELECTOR", "Identity is not in the frozen electorate");
    }
    const custody = await this.requireCustodySet(roundId);
    const snapshots = await this.requireUsableSnapshots(roundId);
    return {
      roundId,
      roundVersion: round.version,
      custodyVersion: custody.version,
      suite: CUSTODY_HPKE_SUITE,
      recipients: snapshots
        .map((snapshot) => ({
          recipientId: snapshot.recipient_id,
          fingerprint: snapshot.hpke_fingerprint,
          hpkePublicKey: snapshot.hpke_public_key,
        }))
        .sort((left, right) => left.recipientId < right.recipientId ? -1 : left.recipientId > right.recipientId ? 1 : 0),
    };
  }

  public async createManifest(input: CreateTallyManifestInput): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "custody.manifest.create", input.idempotencyKey, input, async () => {
      let round = await this.lockRound(input.roundId);
      if (round.version !== input.expectedRoundVersion) throw conflict("VERSION_CONFLICT", "Round version is stale");
      if (round.submission_kind !== "vote" || !["VOTACION_CERRADA", "ESCRUTINIO"].includes(round.phase)) {
        throw conflict("PHASE_CONFLICT", "Tally manifest requires a closed vote or tally phase");
      }
      await this.requireOperationalCandidateEligibility(input.roundId);
      const custody = await this.requireCustodySet(input.roundId);
      if (custody.version !== input.expectedCustodyVersion) {
        throw conflict("VERSION_CONFLICT", "Custody snapshot version is stale");
      }
      const snapshots = await this.requireUsableSnapshots(input.roundId);
      const existing = await this.client.query("SELECT 1 FROM tally_manifests WHERE round_id=$1", [input.roundId]);
      if (existing.rowCount !== 0) throw conflict("MANIFEST_ALREADY_EXISTS", "Tally manifest is already fixed");

      const entries = await this.loadValidatedSubmissionEntries(round, snapshots);
      if (round.phase === "VOTACION_CERRADA") {
        const transitioned = await this.client.query<{ version: number }>(
          `UPDATE rounds SET phase='ESCRUTINIO',version=version+1
            WHERE id=$1 AND version=$2 AND phase='VOTACION_CERRADA' RETURNING version`,
          [input.roundId, round.version],
        );
        const version = transitioned.rows[0]?.version;
        if (!version) throw conflict("VERSION_CONFLICT", "Round changed while creating the tally manifest");
        await this.emit("round.phase", "round", input.roundId, {
          roundId: input.roundId,
          phase: "ESCRUTINIO",
          version,
        });
        round = { ...round, phase: "ESCRUTINIO", version };
      }

      const manifestId = randomUUID();
      const manifestBody = manifestHashBody({
        tenantId: await this.tenantId(),
        roundId: input.roundId,
        roundVersion: round.version,
        custodyVersion: custody.version,
        decisionRule: custody.decision_rule,
        entries,
      });
      const manifestHash = hashCanonicalCustodyJson(manifestBody);
      const created = await this.client.query<{ created_at: Date }>(
        `INSERT INTO tally_manifests(
           id,round_id,custody_version,round_version,decision_rule,manifest_hash,entry_count,created_by_identity_id
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at`,
        [manifestId, input.roundId, custody.version, round.version, custody.decision_rule, manifestHash, entries.length, input.identityId],
      );
      for (const [index, entry] of entries.entries()) {
        await this.client.query(
          `INSERT INTO tally_manifest_entries(manifest_id,position,receipt_id,content_hash,envelope_hash)
           VALUES ($1,$2,$3,$4,$5)`,
          [manifestId, index + 1, entry.receiptId, entry.contentHash, entry.envelopeHash],
        );
      }
      const createdAt = created.rows[0]?.created_at;
      if (!createdAt) throw new Error("Tally manifest insertion did not return a timestamp");
      await this.appendAudit("custody.manifest.created", "tally_manifest", manifestId, "success", {
        roundId: input.roundId,
        roundVersion: round.version,
        custodyVersion: custody.version,
        manifestHash,
        entryCount: entries.length,
      });
      await this.emit("custody.manifest.created", "round", input.roundId, {
        roundId: input.roundId,
        manifestId,
        manifestHash,
        entryCount: entries.length,
      });
      return {
        manifestId,
        roundId: input.roundId,
        roundVersion: round.version,
        custodyVersion: custody.version,
        manifestHash,
        entryCount: entries.length,
        version: 1,
        state: "awaiting_attestations",
        createdAt: createdAt.toISOString(),
      };
    });
  }

  public async downloadManifest(
    roundId: string,
    identityId: string,
  ): Promise<Record<string, unknown> | null> {
    const snapshots = await this.requireUsableSnapshots(roundId);
    const own = snapshots.find((snapshot) => snapshot.custodian_identity_id === identityId);
    if (!own) return null;
    if (own.key_status !== "active") throw conflict("CUSTODY_KEY_UNAVAILABLE", "Frozen custodian key is no longer active");
    const manifest = await this.requireManifest(roundId);
    const round = await this.requireRound(roundId);
    const entries = await this.loadValidatedSubmissionEntries(round, snapshots);
    this.assertManifestFixed(manifest, entries, await this.tenantId());
    return {
      manifest: manifestRecord(manifest),
      custodian: snapshotPublicRecord(own),
      entries: entries.map((entry) => ({
        receiptId: entry.receiptId,
        contentHash: entry.contentHash,
        envelopeHash: entry.envelopeHash,
        envelope: entry.envelope,
      })),
    };
  }

  public async getPublishedAggregate(roundId: string): Promise<Record<string, unknown>> {
    const manifest = await this.requireManifest(roundId);
    if (manifest.state !== "published" || !manifest.agreed_aggregate || !manifest.agreed_aggregate_hash) {
      throw new CustodyError(404, "AGGREGATE_NOT_PUBLISHED", "No authorized aggregate is published for this round");
    }
    return {
      roundId,
      manifestId: manifest.id,
      manifestHash: manifest.manifest_hash,
      aggregateHash: manifest.agreed_aggregate_hash,
      aggregate: manifest.agreed_aggregate,
      state: manifest.state,
      version: manifest.version,
      publishedAt: manifest.published_at?.toISOString() ?? null,
    };
  }

  public async attestManifest(input: AttestTallyManifestInput): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "custody.manifest.attest", input.idempotencyKey, input, async () => {
      const manifest = await this.lockManifest(input.roundId);
      if (manifest.version !== input.expectedManifestVersion) {
        throw conflict("VERSION_CONFLICT", "Tally manifest version is stale");
      }
      if (manifest.state === "published") throw conflict("MANIFEST_ALREADY_PUBLISHED", "Tally aggregate is already published");
      if (manifest.state === "disputed") throw conflict("MANIFEST_DISPUTED", "Tally manifest has conflicting attestations");
      const round = await this.requireRound(input.roundId);
      if (round.phase !== "ESCRUTINIO") throw conflict("PHASE_CONFLICT", "Attestations require the tally phase");
      const eligibility = await this.requireOperationalCandidateEligibility(input.roundId);
      const snapshots = await this.requireUsableSnapshots(input.roundId);
      const own = snapshots.find((snapshot) => snapshot.custodian_identity_id === input.identityId);
      if (!own) throw new CustodyError(403, "CUSTODIAN_NOT_FROZEN", "Identity is not a frozen custodian for this round");
      const entries = await this.loadValidatedSubmissionEntries(round, snapshots);
      this.assertManifestFixed(manifest, entries, await this.tenantId());
      const validatedAggregate = validateTallyAggregate(input.aggregate, {
        candidateIds: eligibility.candidateIds,
        receivedBallots: manifest.entry_count,
        maxSelections: round.max_selections,
        vacancies: round.vacancies,
        decisionRule: manifest.decision_rule,
      });
      const aggregateHash = validatedAggregate.aggregateHash;

      const context = buildTallyAttestationContext({
        tenantId: await this.tenantId(),
        roundId: input.roundId,
        manifestId: manifest.id,
        manifestHash: manifest.manifest_hash,
        aggregateHash,
      });
      const contextHash = verifyTallyAttestation({
        context,
        signingPublicKeySpki: own.signing_public_key_spki,
        signingFingerprint: own.signing_fingerprint,
        signature: input.signature,
      });
      await this.client.query(
        `INSERT INTO custodian_attestations(
           manifest_id,round_id,custodian_identity_id,source_key_id,manifest_hash,
           aggregate_hash,signing_fingerprint,signature,context_hash
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          manifest.id,
          input.roundId,
          input.identityId,
          own.source_key_id,
          manifest.manifest_hash,
          aggregateHash,
          own.signing_fingerprint,
          input.signature,
          contextHash,
        ],
      ).catch((error: unknown) => {
        if (postgresCode(error) === "23505") {
          throw conflict("CUSTODIAN_ALREADY_ATTESTED", "Custodian already attested this manifest");
        }
        throw error;
      });

      const agreement = await this.client.query<{ aggregate_hash: string; count: number }>(
        `SELECT aggregate_hash,count(DISTINCT custodian_identity_id)::int AS count
           FROM custodian_attestations WHERE manifest_id=$1
          GROUP BY aggregate_hash ORDER BY aggregate_hash`,
        [manifest.id],
      );
      const state = agreement.rows.length > 1
        ? "disputed"
        : (agreement.rows[0]?.count ?? 0) >= 2
          ? "publishable"
          : "awaiting_attestations";
      const agreedAggregateHash = state === "publishable" ? agreement.rows[0]?.aggregate_hash ?? null : null;
      const agreedAggregate = state === "publishable" ? validatedAggregate.aggregate : null;
      const updated = await this.client.query<{ version: number }>(
        `UPDATE tally_manifests
            SET state=$2,agreed_aggregate_hash=$3,agreed_aggregate=$4,version=version+1
          WHERE id=$1 RETURNING version`,
        [manifest.id, state, agreedAggregateHash, agreedAggregate],
      );
      const version = updated.rows[0]?.version;
      if (!version) throw new Error("Tally manifest attestation update did not return a version");
      await this.appendAudit("custody.manifest.attested", "tally_manifest", manifest.id, "success", {
        roundId: input.roundId,
        manifestHash: manifest.manifest_hash,
        aggregateHash,
        signingFingerprint: own.signing_fingerprint,
        state,
        version,
      });
      await this.emit("custody.manifest.attested", "round", input.roundId, {
        roundId: input.roundId,
        manifestId: manifest.id,
        state,
        version,
      });
      return {
        manifestId: manifest.id,
        manifestHash: manifest.manifest_hash,
        aggregateHash,
        context,
        contextHash,
        state,
        version,
      };
    });
  }

  public async publishAggregate(input: PublishTallyAggregateInput): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "custody.aggregate.publish", input.idempotencyKey, input, async () => {
      const manifest = await this.lockManifest(input.roundId);
      if (manifest.version !== input.expectedManifestVersion) {
        throw conflict("VERSION_CONFLICT", "Tally manifest version is stale");
      }
      if (manifest.state !== "publishable" || !manifest.agreed_aggregate_hash || !manifest.agreed_aggregate) {
        throw conflict("AGGREGATE_NOT_PUBLISHABLE", "Two matching custodian attestations are required");
      }
      const aggregateHash = manifest.agreed_aggregate_hash;
      const round = await this.lockRound(input.roundId);
      if (round.version !== input.expectedRoundVersion) throw conflict("VERSION_CONFLICT", "Round version is stale");
      if (round.phase !== "ESCRUTINIO") throw conflict("PHASE_CONFLICT", "Aggregate publication requires the tally phase");
      await this.requireOperationalCandidateEligibility(input.roundId);
      const snapshots = await this.requireUsableSnapshots(input.roundId);
      const entries = await this.loadValidatedSubmissionEntries(round, snapshots);
      this.assertManifestFixed(manifest, entries, await this.tenantId());
      const matching = await this.client.query<{ count: number; variants: number }>(
        `SELECT
           count(DISTINCT custodian_identity_id) FILTER (WHERE aggregate_hash=$2)::int AS count,
           count(DISTINCT aggregate_hash)::int AS variants
           FROM custodian_attestations WHERE manifest_id=$1`,
        [manifest.id, aggregateHash],
      );
      if ((matching.rows[0]?.count ?? 0) < 2 || matching.rows[0]?.variants !== 1) {
        throw conflict("AGGREGATE_NOT_PUBLISHABLE", "Custodian attestations do not form one two-person agreement");
      }

      const roundUpdate = await this.client.query<{ version: number }>(
        `UPDATE rounds SET phase='RESULTADO_INTERNO',version=version+1
          WHERE id=$1 AND version=$2 AND phase='ESCRUTINIO' RETURNING version`,
        [input.roundId, input.expectedRoundVersion],
      );
      const roundVersion = roundUpdate.rows[0]?.version;
      if (!roundVersion) throw conflict("VERSION_CONFLICT", "Round changed during aggregate publication");
      const publication = await this.client.query<{ version: number; published_at: Date }>(
        `UPDATE tally_manifests
            SET state='published',published_by_identity_id=$2,published_at=clock_timestamp(),version=version+1
          WHERE id=$1 AND version=$3 RETURNING version,published_at`,
        [manifest.id, input.identityId, input.expectedManifestVersion],
      );
      const published = publication.rows[0];
      if (!published) throw conflict("VERSION_CONFLICT", "Manifest changed during aggregate publication");
      await this.emit("round.phase", "round", input.roundId, {
        roundId: input.roundId,
        phase: "RESULTADO_INTERNO",
        version: roundVersion,
      });
      await this.emit("aggregate.published", "round", input.roundId, {
        roundId: input.roundId,
        manifestId: manifest.id,
        manifestHash: manifest.manifest_hash,
        aggregateHash,
        version: published.version,
      });
      await this.appendAudit("custody.aggregate.published", "tally_manifest", manifest.id, "success", {
        roundId: input.roundId,
        manifestHash: manifest.manifest_hash,
        aggregateHash,
        manifestVersion: published.version,
        roundVersion,
      });
      return {
        manifestId: manifest.id,
        manifestHash: manifest.manifest_hash,
        aggregateHash,
        aggregate: manifest.agreed_aggregate,
        state: "published",
        version: published.version,
        roundVersion,
        publishedAt: published.published_at.toISOString(),
      };
    });
  }

  private async tenantId(): Promise<string> {
    const result = await this.client.query<{ tenant_id: string }>(
      "SELECT tenant_id::text FROM tenant_settings WHERE singleton=true",
    );
    const tenantId = result.rows[0]?.tenant_id;
    if (!tenantId) throw new Error("Tenant settings are missing");
    return tenantId;
  }

  private async requireRound(roundId: string): Promise<RoundRow> {
    const result = await this.client.query<RoundRow>(
      `SELECT id,cycle_id,phase,submission_kind,candidate_set_hash,rules_hash,
              vacancies,max_selections,decision_rule,version
         FROM rounds WHERE id=$1`,
      [roundId],
    );
    const round = result.rows[0];
    if (!round) throw new CustodyError(404, "ROUND_UNAVAILABLE", "Round is unavailable");
    return round;
  }

  private async lockRound(roundId: string): Promise<RoundRow> {
    const result = await this.client.query<RoundRow>(
      `SELECT id,cycle_id,phase,submission_kind,candidate_set_hash,rules_hash,
              vacancies,max_selections,decision_rule,version
         FROM rounds WHERE id=$1 FOR UPDATE`,
      [roundId],
    );
    const round = result.rows[0];
    if (!round) throw new CustodyError(404, "ROUND_UNAVAILABLE", "Round is unavailable");
    return round;
  }

  private async requireCustodySet(roundId: string): Promise<CustodySetRow> {
    const result = await this.client.query<CustodySetRow>(
      "SELECT round_id,round_version,version,decision_rule,frozen_at FROM round_custody_sets WHERE round_id=$1",
      [roundId],
    );
    const custody = result.rows[0];
    if (!custody) throw conflict("CUSTODY_NOT_FROZEN", "Round has no frozen custody set");
    return custody;
  }

  private async loadSnapshots(roundId: string): Promise<readonly SnapshotRow[]> {
    const result = await this.client.query<SnapshotRow>(
      `SELECT snapshot.round_id,snapshot.custodian_identity_id,snapshot.device_id,
              snapshot.source_key_id,snapshot.recipient_id,snapshot.key_version,
              snapshot.hpke_kem,snapshot.hpke_kdf,snapshot.hpke_aead,
              snapshot.hpke_public_key,snapshot.hpke_fingerprint,
              snapshot.signing_algorithm,snapshot.signing_public_key_spki,
              snapshot.signing_fingerprint,key_state.status AS key_status
         FROM round_custodian_key_snapshots snapshot
         LEFT JOIN custodian_device_keys key_state ON key_state.id=snapshot.source_key_id
        WHERE snapshot.round_id=$1
        ORDER BY snapshot.custodian_identity_id`,
      [roundId],
    );
    return result.rows;
  }

  private async requireUsableSnapshots(roundId: string): Promise<readonly SnapshotRow[]> {
    const snapshots = await this.loadSnapshots(roundId);
    if (snapshots.length < 2 || new Set(snapshots.map((item) => item.custodian_identity_id)).size < 2) {
      throw conflict("CUSTODY_KEY_UNAVAILABLE", "At least two distinct frozen custodians are required");
    }
    if (snapshots.some((snapshot) => snapshot.key_status !== "active")) {
      throw conflict("CUSTODY_KEY_UNAVAILABLE", "A frozen custodian key is absent, superseded, or revoked");
    }
    for (const snapshot of snapshots) validateCustodianKeyMaterial(keyMaterialFromSnapshot(snapshot));
    return snapshots;
  }

  private async requireOperationalCandidateEligibility(roundId: string) {
    try {
      return await requireRoundCandidatesOperationallyEligible(this.client, roundId);
    } catch (error) {
      if (error instanceof MemberEligibilityGuardError) throw conflict(error.code, error.message);
      throw error;
    }
  }

  private async requireManifest(roundId: string): Promise<ManifestRow> {
    const result = await this.client.query<ManifestRow>(`${MANIFEST_SELECT} WHERE round_id=$1`, [roundId]);
    const manifest = result.rows[0];
    if (!manifest) throw new CustodyError(404, "MANIFEST_NOT_FOUND", "Tally manifest is unavailable");
    return manifest;
  }

  private async lockManifest(roundId: string): Promise<ManifestRow> {
    const result = await this.client.query<ManifestRow>(
      `${MANIFEST_SELECT} WHERE round_id=$1 FOR UPDATE`,
      [roundId],
    );
    const manifest = result.rows[0];
    if (!manifest) throw new CustodyError(404, "MANIFEST_NOT_FOUND", "Tally manifest is unavailable");
    return manifest;
  }

  private async loadValidatedSubmissionEntries(
    round: RoundRow,
    snapshots: readonly SnapshotRow[],
  ): Promise<readonly ValidatedManifestEntry[]> {
    const required = await this.client.query<{ count: number }>(
      `SELECT count(*)::int AS count FROM round_elector_snapshots
        WHERE round_id=$1 AND can_submit AND NOT recused`,
      [round.id],
    );
    const submissions = await this.client.query<SubmissionManifestRow>(
      `SELECT receipt.id AS receipt_id,receipt.content_hash AS receipt_content_hash,
              submission.content_hash,submission.envelope,submission.round_version
         FROM encrypted_submissions submission
         LEFT JOIN participation_receipts receipt ON receipt.submission_id=submission.id
        WHERE submission.round_id=$1 AND submission.kind='vote'
        ORDER BY receipt.id NULLS LAST`,
      [round.id],
    );
    if (submissions.rows.length === 0 || submissions.rows.length !== (required.rows[0]?.count ?? 0)) {
      throw conflict("PARTICIPATION_INCOMPLETE", "Manifest requires one ballot and receipt per frozen eligible elector");
    }
    const tenantId = await this.tenantId();
    const recipients: readonly FrozenRecipient[] = snapshots.map((snapshot) => ({
      recipientId: snapshot.recipient_id,
      hpkeFingerprint: snapshot.hpke_fingerprint,
    }));
    return submissions.rows.map((submission) => {
      if (!submission.receipt_id || submission.receipt_content_hash !== submission.content_hash) {
        throw conflict("RECEIPT_SET_INVALID", "Every encrypted ballot must have a matching receipt");
      }
      const hashes = validateEncryptedBallotEnvelope(submission.envelope, submission.content_hash, {
        tenantId,
        cycleId: round.cycle_id,
        roundId: round.id,
        submissionRoundVersion: submission.round_version,
        candidateSetHash: round.candidate_set_hash,
        rulesHash: round.rules_hash,
        recipients,
      });
      return {
        receiptId: submission.receipt_id,
        contentHash: hashes.contentHash,
        envelopeHash: hashes.envelopeHash,
        envelope: submission.envelope,
      };
    });
  }

  private assertManifestFixed(
    manifest: ManifestRow,
    entries: readonly ValidatedManifestEntry[],
    tenantId: string,
  ): void {
    const expectedHash = hashCanonicalCustodyJson(manifestHashBody({
      tenantId,
      roundId: manifest.round_id,
      roundVersion: manifest.round_version,
      custodyVersion: manifest.custody_version,
      decisionRule: manifest.decision_rule,
      entries,
    }));
    if (entries.length !== manifest.entry_count || expectedHash !== manifest.manifest_hash) {
      throw conflict("MANIFEST_SET_CHANGED", "Encrypted ballot or receipt set differs from the fixed manifest");
    }
  }

  private async executeIdempotent<T>(
    identityId: string,
    operation: string,
    idempotencyKey: string,
    request: unknown,
    work: () => Promise<T>,
  ): Promise<T> {
    const requestHash = hashCanonicalCustodyJson(request);
    const inserted = await this.client.query(
      `INSERT INTO idempotency_records(identity_id,operation,idempotency_key,request_hash)
       VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
      [identityId, operation, idempotencyKey, requestHash],
    );
    if (inserted.rowCount === 0) {
      const existing = await this.client.query<{ request_hash: string; response_body: T | null }>(
        `SELECT request_hash,response_body FROM idempotency_records
          WHERE identity_id=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`,
        [identityId, operation, idempotencyKey],
      );
      const row = existing.rows[0];
      if (!row || row.request_hash !== requestHash) {
        throw conflict("IDEMPOTENCY_CONFLICT", "Idempotency key was reused with different custody input");
      }
      if (row.response_body === null) {
        throw conflict("IDEMPOTENCY_IN_PROGRESS", "Original custody operation is still in progress");
      }
      return row.response_body;
    }
    const response = await work();
    await this.client.query(
      `UPDATE idempotency_records SET response_status=200,response_body=$4
        WHERE identity_id=$1 AND operation=$2 AND idempotency_key=$3`,
      [identityId, operation, idempotencyKey, response],
    );
    return response;
  }

  private async emit(
    eventType: string,
    aggregateType: string,
    aggregateId: string,
    payload: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    await this.client.query(
      `INSERT INTO outbox_events(audience,event_type,aggregate_type,aggregate_id,payload)
       VALUES ('tenant.authorized',$1,$2,$3,$4)`,
      [eventType, aggregateType, aggregateId, payload],
    );
  }

  private async appendAudit(
    action: string,
    entityType: string,
    entityId: string,
    result: "success" | "denied" | "failure",
    metadata: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    await appendTenantAuditEventV2(this.client, { action, entityType, entityId, result, metadata });
  }
}

const KEY_SELECT = `SELECT id,custodian_identity_id,device_id,recipient_id,key_version,status,
  hpke_kem,hpke_kdf,hpke_aead,hpke_public_key,hpke_fingerprint,
  signing_algorithm,signing_public_key_spki,signing_fingerprint,registered_at,revoked_at
  FROM custodian_device_keys`;

const MANIFEST_SELECT = `SELECT id,round_id,custody_version,round_version,manifest_hash,
  decision_rule,entry_count,state,agreed_aggregate_hash,agreed_aggregate,version,created_at,published_at FROM tally_manifests`;

function keyMaterialFromRow(row: CustodianKeyRow): CustodianKeyMaterial {
  return {
    recipientId: row.recipient_id,
    suite: CUSTODY_HPKE_SUITE,
    hpkePublicKey: row.hpke_public_key,
    hpkeFingerprint: row.hpke_fingerprint,
    signingAlgorithm: row.signing_algorithm,
    signingPublicKeySpki: row.signing_public_key_spki,
    signingFingerprint: row.signing_fingerprint,
  };
}

function keyMaterialFromSnapshot(row: SnapshotRow): CustodianKeyMaterial {
  return {
    recipientId: row.recipient_id,
    suite: CUSTODY_HPKE_SUITE,
    hpkePublicKey: row.hpke_public_key,
    hpkeFingerprint: row.hpke_fingerprint,
    signingAlgorithm: row.signing_algorithm,
    signingPublicKeySpki: row.signing_public_key_spki,
    signingFingerprint: row.signing_fingerprint,
  };
}

function publicKeyRecord(row: CustodianKeyRow): Record<string, unknown> {
  return {
    keyId: row.id,
    custodianIdentityId: row.custodian_identity_id,
    deviceId: row.device_id,
    recipientId: row.recipient_id,
    version: row.key_version,
    status: row.status,
    suite: CUSTODY_HPKE_SUITE,
    hpkePublicKey: row.hpke_public_key,
    hpkeFingerprint: row.hpke_fingerprint,
    signingAlgorithm: row.signing_algorithm,
    signingPublicKeySpki: row.signing_public_key_spki,
    signingFingerprint: row.signing_fingerprint,
    registeredAt: row.registered_at,
    revokedAt: row.revoked_at,
  };
}

function snapshotPublicRecord(row: SnapshotRow): Record<string, unknown> {
  return {
    keyId: row.source_key_id,
    custodianIdentityId: row.custodian_identity_id,
    deviceId: row.device_id,
    recipientId: row.recipient_id,
    version: row.key_version,
    status: row.key_status,
    suite: CUSTODY_HPKE_SUITE,
    hpkePublicKey: row.hpke_public_key,
    hpkeFingerprint: row.hpke_fingerprint,
    signingAlgorithm: row.signing_algorithm,
    signingPublicKeySpki: row.signing_public_key_spki,
    signingFingerprint: row.signing_fingerprint,
  };
}

function manifestRecord(row: ManifestRow): Record<string, unknown> {
  return {
    manifestId: row.id,
    roundId: row.round_id,
    custodyVersion: row.custody_version,
    decisionRule: row.decision_rule,
    roundVersion: row.round_version,
    manifestHash: row.manifest_hash,
    entryCount: row.entry_count,
    state: row.state,
    agreedAggregateHash: row.agreed_aggregate_hash,
    version: row.version,
    createdAt: row.created_at,
    publishedAt: row.published_at,
  };
}

function manifestHashBody(input: {
  readonly tenantId: string;
  readonly roundId: string;
  readonly roundVersion: number;
  readonly custodyVersion: number;
  readonly decisionRule: unknown;
  readonly entries: readonly ValidatedManifestEntry[];
}): Record<string, unknown> {
  return {
    tenantId: input.tenantId,
    roundId: input.roundId,
    purpose: "nombramientos.tally.manifest",
    schemaVersion: 1,
    roundVersion: input.roundVersion,
    custodyVersion: input.custodyVersion,
    decisionRule: input.decisionRule,
    entries: input.entries.map((entry) => ({
      receiptId: entry.receiptId,
      contentHash: entry.contentHash,
      envelopeHash: entry.envelopeHash,
    })),
  };
}

function conflict(code: string, message: string): CustodyError {
  return new CustodyError(409, code, message);
}

function postgresCode(error: unknown): string | null {
  return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string"
    ? error.code
    : null;
}
