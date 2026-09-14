import type { Envelope } from "./api.ts";
import { decryptJson } from "./crypto-client.ts";

export type EnvelopeKeyResolver = {
  readonly keyFor: (keyId: string, tenantId: string) => CryptoKey | undefined;
};

export class HistoricalEnvelopeKeyUnavailableError extends Error {
  public readonly keyId: string;

  public constructor(keyId: string) {
    super("HISTORICAL_ENVELOPE_KEY_UNAVAILABLE");
    this.name = "HistoricalEnvelopeKeyUnavailableError";
    this.keyId = keyId;
  }
}

/** Selects the exact generation named by an envelope; never falls back to the current key. */
export function keyForEnvelope(
  resolver: EnvelopeKeyResolver,
  tenantId: string,
  envelope: Pick<Envelope, "keyId">,
): CryptoKey {
  const key = resolver.keyFor(envelope.keyId, tenantId);
  if (!key) throw new HistoricalEnvelopeKeyUnavailableError(envelope.keyId);
  return key;
}

export async function openJsonEnvelope<T>(input: {
  readonly resolver: EnvelopeKeyResolver;
  readonly tenantId: string;
  readonly envelope: Envelope;
  readonly aad: Readonly<Record<string, unknown>>;
}): Promise<T> {
  return decryptJson<T>(
    keyForEnvelope(input.resolver, input.tenantId, input.envelope),
    input.envelope,
    { keyId: input.envelope.keyId, aad: input.aad, exactAad: true },
  );
}
