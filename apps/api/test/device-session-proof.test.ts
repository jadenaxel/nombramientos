import { randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe,expect,it } from "vitest";
import { deviceProofRequired, signingKeyFingerprint, verifyCompactDeviceProof } from "../src/modules/device-session-proof.js";

async function fixture() {
  const keys = await generateKeyPair("ES256");
  const exported = await exportJWK(keys.publicKey);
  const publicJwk = {kty:exported.kty!,crv:exported.crv!,x:exported.x!,y:exported.y!};
  const payload = {purpose:"nombramientos.device-session-request",version:1,jti:randomUUID(),nonce:"one-use-server-nonce",htm:"PATCH",htu:"http://localhost:4100/v1/members",iat:Math.floor(Date.now()/1000),bodyHash:"sha256:"+"a".repeat(64)};
  return {keys,publicJwk,payload};
}
describe("device-bound compact JWS profile",() => {
  it("verifies ES256 with exactly the enrolled public signing key",async() => {
    const {keys,publicJwk,payload} = await fixture();
    const proof = await new SignJWT(payload).setProtectedHeader({alg:"ES256",typ:"dpop+jwt",jwk:publicJwk}).sign(keys.privateKey);
    await expect(verifyCompactDeviceProof(proof,publicJwk)).resolves.toEqual(payload);
    expect(signingKeyFingerprint(publicJwk)).toMatch(/^sha256:[a-f0-9]{64}$/u);
    expect(signingKeyFingerprint({...publicJwk,y:publicJwk.y,x:publicJwk.x})).toBe(signingKeyFingerprint(publicJwk));
  });
  it("does not trust an attacker-controlled JWK in the protected header",async() => {
    const enrolled = await fixture();
    const attacker = await fixture();
    const proof = await new SignJWT(attacker.payload).setProtectedHeader({alg:"ES256",typ:"dpop+jwt",jwk:attacker.publicJwk}).sign(attacker.keys.privateKey);
    await expect(verifyCompactDeviceProof(proof,enrolled.publicJwk)).rejects.toMatchObject({statusCode:401,code:"DEVICE_PROOF_INVALID"});
  });
  it.each([undefined,"JWT","application/jwt"])("rejects incorrect proof media type %s",async(typ) => {
    const {keys,publicJwk,payload} = await fixture();
    const proof = await new SignJWT(payload).setProtectedHeader({alg:"ES256",...(typ ? {typ} : {}),jwk:publicJwk}).sign(keys.privateKey);
    await expect(verifyCompactDeviceProof(proof,publicJwk)).rejects.toMatchObject({code:"DEVICE_PROOF_INVALID"});
  });
  it.each([{jku:"https://attacker.invalid/keys"},{x5u:"https://attacker.invalid/cert"},{kid:"unexpected"},{b64:true}])("rejects extraneous key/header negotiation %j",async(header) => {
    const {keys,publicJwk,payload} = await fixture();
    const proof = await new SignJWT(payload).setProtectedHeader({alg:"ES256",typ:"dpop+jwt",jwk:publicJwk,...header}).sign(keys.privateKey);
    await expect(verifyCompactDeviceProof(proof,publicJwk)).rejects.toMatchObject({code:"DEVICE_PROOF_INVALID"});
  });
  it.each([-121,6])("rejects stale/future issued-at %s",async(offset) => {
    const {keys,publicJwk,payload} = await fixture();
    const proof = await new SignJWT({...payload,iat:Math.floor(Date.now()/1000)+offset}).setProtectedHeader({alg:"ES256",typ:"dpop+jwt",jwk:publicJwk}).sign(keys.privateKey);
    await expect(verifyCompactDeviceProof(proof,publicJwk)).rejects.toMatchObject({code:"DEVICE_PROOF_INVALID"});
  });
  it("rejects private JWK material and oversized/malformed signatures",async() => {
    const {keys,publicJwk,payload} = await fixture();
    const valid = await new SignJWT(payload).setProtectedHeader({alg:"ES256",typ:"dpop+jwt",jwk:publicJwk}).sign(keys.privateKey);
    await expect(verifyCompactDeviceProof(valid,{...publicJwk,d:"not-accepted"})).rejects.toMatchObject({code:"DEVICE_PROOF_INVALID"});
    await expect(verifyCompactDeviceProof(valid.split(".").slice(0,2).join(".")+".AA",publicJwk)).rejects.toMatchObject({code:"DEVICE_PROOF_INVALID"});
    await expect(verifyCompactDeviceProof("A".repeat(8193),publicJwk)).rejects.toMatchObject({code:"DEVICE_PROOF_INVALID"});
  });
  it("rejects noncanonical base64url aliases of coordinates and signatures",async() => {
    const {keys,publicJwk,payload} = await fixture();
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const alias = (value:string) => value.slice(0,-1)+alphabet[alphabet.indexOf(value.at(-1)!) | 1]!;
    const aliasedCoordinate = alias(publicJwk.x);
    expect(Buffer.from(aliasedCoordinate,"base64url")).toEqual(Buffer.from(publicJwk.x,"base64url"));
    expect(() => signingKeyFingerprint({...publicJwk,x:aliasedCoordinate})).toThrow();
    const valid = await new SignJWT(payload).setProtectedHeader({alg:"ES256",typ:"dpop+jwt",jwk:publicJwk}).sign(keys.privateKey);
    const parts = valid.split(".");
    parts[2] = alias(parts[2]!);
    await expect(verifyCompactDeviceProof(parts.join("."),publicJwk)).rejects.toMatchObject({code:"DEVICE_PROOF_INVALID"});
  });
});
describe("explicit device proof bootstrap boundaries",() => {
  it("only exempts exact read/session/bootstrap routes and existing platform surface",() => {
    for(const [method,url] of [["GET","/v1/session"],["POST","/v1/auth/logout"],["GET","/v1/key-lifecycle"],["POST","/v1/key-lifecycle/devices"],["POST","/v1/key-lifecycle/challenges"],["GET","/v1/device-session"],["GET","/v1/platform/tenants"]]) expect(deviceProofRequired({method:method!,url:url!})).toBe(false);
    for(const [method,url] of [["PATCH","/v1/session"],["POST","/v1/key-lifecycle/grants"],["POST","/v1/key-lifecycle/grants/initialize"],["POST","/v1/key-lifecycle/rotations"],["POST","/v1/key-lifecycle/recoveries"],["GET","/v1/members"],["GET","/v1/access/roles"],["GET","/v1/events?tenantId=example"],["GET","/v1/platform-not-a-prefix"]]) expect(deviceProofRequired({method:method!,url:url!})).toBe(true);
  });
});
