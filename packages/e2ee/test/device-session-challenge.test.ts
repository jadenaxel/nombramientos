import { randomUUID } from "node:crypto";
import { describe,expect,it,vi } from "vitest";
import { generateTenantDeviceKeyPair,openDeviceSessionChallenge,sealDeviceSessionChallenge,type DeviceSessionEnrollmentContext } from "../src/index.js";
function context(): DeviceSessionEnrollmentContext {
  return {purpose:"nombramientos.device-session-enrollment",version:1,challengeId:randomUUID(),tenantId:randomUUID(),identityId:randomUUID(),sessionId:randomUUID(),sourceSessionId:randomUUID(),deviceId:randomUUID(),signingFingerprint:"sha256:"+"a".repeat(64),expiresAt:new Date(Date.now()+120000).toISOString()};
}
describe("domain-separated HPKE device session challenge",() => {
  it("opens only with the already registered wrapping key and full expected context",async() => {
    const expected=context();
    const recipient=await generateTenantDeviceKeyPair(expected);
    const secret=crypto.getRandomValues(new Uint8Array(32));
    const challenge=await sealDeviceSessionChallenge({recipient,context:expected,secret});
    const opened=await openDeviceSessionChallenge({recipient,challenge,expected});
    expect(opened).toEqual(secret);
    opened.fill(0);secret.fill(0);
  });
  it.each(["tenantId","identityId","sessionId","sourceSessionId","deviceId","challengeId","signingFingerprint","expiresAt"])("rejects context substitution %s",async(field) => {
    const expected=context();
    const recipient=await generateTenantDeviceKeyPair(expected);
    const secret=crypto.getRandomValues(new Uint8Array(32));
    const challenge=await sealDeviceSessionChallenge({recipient,context:expected,secret});
    const changed={...expected,[field]:field === "signingFingerprint" ? "sha256:"+"b".repeat(64) : field === "expiresAt" ? new Date(Date.now()+60000).toISOString() : randomUUID()};
    await expect(openDeviceSessionChallenge({recipient,challenge,expected:changed})).rejects.toThrow();
    // Even supplying a forged expected context equal to a forged envelope
    // cannot change the authenticated HPKE AAD from the server's challenge.
    await expect(openDeviceSessionChallenge({recipient,challenge:{...challenge,context:changed},expected:changed})).rejects.toThrow();
    secret.fill(0);
  });
  it("rejects another wrapping key, expired challenges and damaged ciphertext",async() => {
    const expected=context();
    const recipient=await generateTenantDeviceKeyPair(expected);
    const other=await generateTenantDeviceKeyPair(expected);
    const secret=crypto.getRandomValues(new Uint8Array(32));
    const challenge=await sealDeviceSessionChallenge({recipient,context:expected,secret});
    await expect(openDeviceSessionChallenge({recipient:other,challenge,expected})).rejects.toThrow();
    const expired={...expected,expiresAt:new Date(Date.now()-1).toISOString()};
    await expect(openDeviceSessionChallenge({recipient,challenge:{...challenge,context:expired},expected:expired})).rejects.toThrow();
    await expect(openDeviceSessionChallenge({recipient,challenge:{...challenge,ciphertext:challenge.ciphertext.slice(1)},expected})).rejects.toThrow();
    secret.fill(0);
  });
  it.each([-86_400_000,86_400_000])("uses authoritative server time despite browser clock skew %s",async(offset) => {
    const serverNow=Date.now();
    const expected=context();
    const recipient=await generateTenantDeviceKeyPair(expected);
    const secret=crypto.getRandomValues(new Uint8Array(32));
    const challenge=await sealDeviceSessionChallenge({recipient,context:expected,secret});
    const clock=vi.spyOn(Date,"now").mockReturnValue(serverNow+offset);
    try {
      const opened=await openDeviceSessionChallenge({recipient,challenge,expected,nowMs:serverNow});
      expect(opened).toEqual(secret);
      opened.fill(0);
      await expect(openDeviceSessionChallenge({recipient,challenge,expected,nowMs:Date.parse(expected.expiresAt)+1})).rejects.toThrow();
      await expect(openDeviceSessionChallenge({recipient,challenge,expected,nowMs:Number.NaN})).rejects.toThrow();
    } finally { clock.mockRestore();secret.fill(0); }
  });
});
