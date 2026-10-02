import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { Transform } from "node:stream";
import { compactVerify, decodeJwt, importJWK } from "jose";
import { importCustodianPublicKey, sealDeviceSessionChallenge, type DeviceSessionEnrollmentContext } from "@nombramientos/e2ee";
import { DeviceSessionStoreError, hashKeyLifecycleRequest, type RequestPrincipal } from "@nombramientos/database";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { ApiError, unauthorized } from "../lib/errors.js";
import { parseBody, respond } from "../lib/http.js";

const PURPOSE = "nombramientos.device-session-request";
const coordinate = z.string().regex(/^[A-Za-z0-9_-]{43}$/u).refine((value) => Buffer.from(value,"base64url").toString("base64url") === value);
const PUBLIC_JWK = z.object({ kty: z.literal("EC"), crv: z.literal("P-256"), x: coordinate, y: coordinate }).strict();
const requestSchema = z.object({ method: z.enum(["GET","POST","PATCH","PUT","DELETE"]), path: z.string().min(1).max(8192), bodyHash: z.string().regex(/^sha256:[a-f0-9]{64}$/u), idempotencyKey: z.string().max(200).default("") }).strict();
const enrollmentSchema = z.object({ deviceId: z.string().uuid(), publicJwk: PUBLIC_JWK }).strict();
const completeSchema = z.object({ challengeId: z.string().uuid(), secret: z.string().regex(/^[A-Za-z0-9_-]{43}$/u), proof: z.string().max(8192) }).strict();
const EMPTY_HASH = digest(Buffer.alloc(0));
const bodyHashes = new WeakMap<FastifyRequest,string>();
const verifiedProofs = new WeakMap<FastifyRequest,Promise<void>>();
interface ProofPayload extends Record<string,unknown> {
  jti?: unknown; iat?: unknown; bodyHash?: unknown; htm?: unknown; path?: unknown; htu?: unknown;
  idempotencyKey?: unknown; sessionId?: unknown; tenantId?: unknown; identityId?: unknown;
  deviceId?: unknown; signingFingerprint?: unknown; purpose?: unknown; version?: unknown; sourceSessionId?: unknown;
}

export function signingKeyFingerprint(jwk: Record<string,unknown>): string {
  const parsed = PUBLIC_JWK.parse(jwk);
  // RFC 7638 thumbprint member ordering, represented as sha256:<hex>.
  return digest(Buffer.from(JSON.stringify({ crv: parsed.crv, kty: parsed.kty, x: parsed.x, y: parsed.y })));
}
function digest(bytes: Uint8Array): string { return `sha256:${createHash("sha256").update(bytes).digest("hex")}`; }
export function registerDeviceProofBodyHash(app: FastifyInstance): void {
  app.addHook("preParsing", async (request,_reply,payload) => {
    const hash = createHash("sha256");
    let length = 0;
    const tap = new Transform({
      transform(chunk: Buffer,_encoding,callback) {
        length += chunk.byteLength;
        hash.update(chunk);
        callback(null,chunk);
      },
      flush(callback) { bodyHashes.set(request,`sha256:${hash.digest("hex")}`); callback(); },
    });
    Object.defineProperty(tap,"receivedEncodedLength",{ get: () => length });
    payload.on("error",(error) => tap.destroy(error));
    return payload.pipe(tap);
  });
}

/** Explicit small bootstrap surface. Lifecycle grants/rotation/recovery remain protected. */
export function deviceProofRequired(request: Pick<FastifyRequest,"method"|"url">): boolean {
  const path = request.url.split("?",1)[0];
  if (path?.startsWith("/v1/platform/")) return false;
  if (path === "/v1/session" && request.method === "GET") return false;
  if (path === "/v1/auth/logout" && request.method === "POST") return false;
  if (path === "/v1/key-lifecycle" && request.method === "GET") return false;
  if (path === "/v1/key-lifecycle/devices" && request.method === "POST") return false;
  if (path === "/v1/key-lifecycle/challenges" && request.method === "POST") return false;
  return !["/v1/device-session","/v1/device-session/enrollment/challenge","/v1/device-session/enrollment/complete","/v1/device-session/proofs"].includes(path ?? "");
}
export function requireDeviceSessionProof(app: FastifyInstance, request: FastifyRequest): Promise<void> {
  const previous = verifiedProofs.get(request);
  if (previous) return previous;
  const check = verifyRequest(app,request);
  verifiedProofs.set(request,check);
  return check;
}
async function verifyRequest(app: FastifyInstance, request: FastifyRequest): Promise<void> {
  const principal = request.principal;
  if (!principal || principal.tenantKind !== "real") return;
  // Standalone account-factor enrollment/recovery already has a narrow route
  // allowlist in authenticate; it cannot access any tenant application data.
  if (principal.enrollmentOnly || principal.assuranceLevel === "recovery_limited") return;
  const binding = await app.database.withDeviceSessionPrincipal(principal,request.id,(store) => store.getBinding(principal.identityId,principal.sessionId));
  if (binding?.status === "revoked") {
    // Tenant revocation is authoritative even if supplementary control-plane
    // cleanup is temporarily unavailable. Never turn a known revoke into 500.
    await app.database.control.revokeSession(principal.sessionId,"e2ee_device_revoked").catch(() => undefined);
    throw new ApiError(401,"DEVICE_SESSION_REVOKED","This browser session has been revoked");
  }
  if (!deviceProofRequired(request)) return;
  if (!binding) throw new ApiError(428,"DEVICE_SESSION_ENROLLMENT_REQUIRED","Connect this browser before accessing protected data");
  const currentSourceSession = await sourceSession(app,principal);
  if (binding.sourceSessionId !== currentSourceSession) throw new ApiError(401,"DEVICE_SESSION_SOURCE_CHANGED","The central session context changed; reconnect through GestionChurch");
  const operationPath = request.url.split("?",1)[0];
  if ((binding.deviceStatus !== "active" || !binding.hasActiveGrant) && ![
    "/v1/key-lifecycle/grants/initialize","/v1/key-lifecycle/recoveries","/v1/key-lifecycle/loss-declarations",
  ].includes(operationPath ?? "")) {
    throw new ApiError(403,"DEVICE_SESSION_APPROVAL_REQUIRED","This browser is pending explicit authorization; no content access was granted");
  }
  const proof = request.headers["x-device-proof"];
  if (typeof proof !== "string") throw new ApiError(401,"DEVICE_PROOF_REQUIRED","Device proof is required");
  const payload = await verifyCompactDeviceProof(proof,binding.publicJwk);
  if (typeof payload.jti !== "string" || !z.string().uuid().safeParse(payload.jti).success) throw invalidProof();
  const challenge = await app.database.withDeviceSessionPrincipal(principal,request.id,(store) => store.readChallenge(String(payload.jti),principal.identityId,principal.sessionId,"request"));
  if (!challenge || hashKeyLifecycleRequest(payload) !== hashKeyLifecycleRequest(challenge.context)) throw invalidProof();
  const expectedBody = bodyHashes.get(request) ?? (request.body === undefined ? EMPTY_HASH : undefined);
  if (!expectedBody || payload.bodyHash !== expectedBody || payload.htm !== request.method
      || payload.path !== request.url || payload.htu !== targetUrl(app,request.url)
      || payload.idempotencyKey !== (request.headers["idempotency-key"] ?? "")
      || payload.sessionId !== principal.sessionId || payload.tenantId !== principal.activeTenantId
      || payload.identityId !== principal.identityId || payload.deviceId !== binding.deviceId
      || payload.sourceSessionId !== currentSourceSession
      || payload.signingFingerprint !== binding.signingFingerprint || payload.purpose !== PURPOSE || payload.version !== 1) throw invalidProof();
  await app.database.withDeviceSessionPrincipal(principal,request.id,(store) => store.consumeProof({ id:String(payload.jti),identityId:principal.identityId,sessionId:principal.sessionId,deviceId:binding.deviceId,signingFingerprint:binding.signingFingerprint })).catch(mapStoreError);
  request.principal = { ...principal, provenDeviceId: binding.deviceId };
}
export async function verifyCompactDeviceProof(proof: string, publicJwk: Record<string,unknown>): Promise<ProofPayload> {
  try {
    if (proof.length > 8192 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(proof)
        || proof.split(".").some((segment) => Buffer.from(segment,"base64url").toString("base64url") !== segment)
        || Buffer.from(proof.split(".")[2]!,"base64url").byteLength !== 64) throw invalidProof();
    const jwk = PUBLIC_JWK.parse(publicJwk);
    const verified = await compactVerify(proof,await importJWK(jwk,"ES256"),{ algorithms:["ES256"] });
    if (verified.protectedHeader.alg !== "ES256" || verified.protectedHeader.typ !== "dpop+jwt"
        || Object.keys(verified.protectedHeader).some((key) => !["alg","typ","jwk"].includes(key))
        || signingKeyFingerprint(PUBLIC_JWK.parse(verified.protectedHeader.jwk)) !== signingKeyFingerprint(jwk)) throw invalidProof();
    const payload = decodeJwt(proof) as ProofPayload;
    const now = Math.floor(Date.now()/1000);
    if (typeof payload.iat !== "number" || !Number.isSafeInteger(payload.iat) || payload.iat > now+5 || payload.iat < now-120) throw invalidProof();
    return payload;
  } catch { throw invalidProof(); }
}
function targetUrl(app: FastifyInstance,path: string): string {
  if (!path.startsWith("/v1/") || path.startsWith("//") || path.includes("#") || path.includes("\\")) throw invalidProof();
  return new URL(path,app.apiConfig.publicOrigin ?? `http://localhost:${app.apiConfig.port}`).href;
}
function invalidProof(): ApiError { return new ApiError(401,"DEVICE_PROOF_INVALID","The device proof is invalid or expired"); }
function mapStoreError(error: unknown): never {
  if (error instanceof DeviceSessionStoreError) throw new ApiError(error.code === "DEVICE_PROOF_BUDGET_EXCEEDED" ? 429 : 401,error.code,"The browser security context is unavailable; reconnect or retry safely");
  throw error;
}
function requirePrincipal(request: FastifyRequest): RequestPrincipal {
  if (!request.principal) throw unauthorized();
  if (request.principal.tenantKind !== "real") throw new ApiError(409,"REAL_TENANT_REQUIRED","Device proof binding is for real tenants");
  return request.principal;
}
async function sourceSession(app: FastifyInstance,principal: RequestPrincipal): Promise<string|null> {
  return app.database.control.getGestionChurchSessionBinding(principal.sessionId,principal.identityId,principal.activeTenantId);
}
export async function registerDeviceSessionRoutes(app: FastifyInstance): Promise<void> {
  app.get("/v1/device-session",{ preHandler:[app.authenticate] },async(request,reply) => {
    const principal = requirePrincipal(request);
    const binding = await app.database.withDeviceSessionPrincipal(principal,request.id,(store) => store.getBinding(principal.identityId,principal.sessionId));
    return respond(request,reply,{ binding,enrollmentRequired:!binding,session:{ sessionId:principal.sessionId,tenantId:principal.activeTenantId,identityId:principal.identityId,sourceSessionId:await sourceSession(app,principal) } });
  });
  app.post("/v1/device-session/enrollment/challenge",{ preHandler:[app.authenticate,app.verifyCsrf] },async(request,reply) => {
    const principal = requirePrincipal(request);
    const input = parseBody(enrollmentSchema,request);
    await importJWK(input.publicJwk,"ES256").catch(() => { throw invalidProof(); });
    const device = await app.database.withDeviceSessionPrincipal(principal,request.id,(store) => store.getDevice(principal.identityId,input.deviceId));
    if (!device) throw new ApiError(403,"DEVICE_SESSION_DEVICE_UNAVAILABLE","The selected browser is not registered for this identity");
    const recipient = await importCustodianPublicKey(device.wrappingPublicKey);
    const rawSigner = Buffer.concat([Buffer.from([4]),Buffer.from(input.publicJwk.x,"base64url"),Buffer.from(input.publicJwk.y,"base64url")]);
    if (digest(rawSigner) === recipient.fingerprint) throw new ApiError(400,"DEVICE_SIGNING_KEY_REUSE_DENIED","Signing and wrapping keys must be separate");
    const current = await app.database.withDeviceSessionPrincipal(principal,request.id,(store) => store.getBinding(principal.identityId,principal.sessionId));
    if (current && (current.status !== "active" || current.deviceId !== input.deviceId || current.signingFingerprint !== signingKeyFingerprint(input.publicJwk))) throw new ApiError(409,"DEVICE_SESSION_ALREADY_BOUND","Reconnect through the central login; this session cannot be rebound");
    const context: DeviceSessionEnrollmentContext = { purpose:"nombramientos.device-session-enrollment",version:1,challengeId:randomUUID(),tenantId:principal.activeTenantId,identityId:principal.identityId,sessionId:principal.sessionId,sourceSessionId:await sourceSession(app,principal),deviceId:input.deviceId,signingFingerprint:signingKeyFingerprint(input.publicJwk),expiresAt:new Date(Date.now()+120_000).toISOString() };
    const secret = new Uint8Array(randomBytes(32));
    try {
      const sealed = await sealDeviceSessionChallenge({ recipient,context,secret });
      await app.database.withDeviceSessionPrincipal(principal,request.id,(store) => store.issueChallenge({ id:context.challengeId,identityId:principal.identityId,sessionId:principal.sessionId,deviceId:input.deviceId,purpose:"enrollment",secretHash:digest(secret),publicJwk:input.publicJwk,context:{...context},expiresAt:context.expiresAt })).catch(mapStoreError);
      const issuedAt = Math.floor((Date.parse(context.expiresAt)-120_000)/1000);
      return respond(request,reply,{...sealed,challengeId:context.challengeId,expiresAt:context.expiresAt,issuedAt},201);
    } finally { secret.fill(0); }
  });
  app.post("/v1/device-session/enrollment/complete",{ preHandler:[app.authenticate,app.verifyCsrf] },async(request,reply) => {
    const principal = requirePrincipal(request);
    const input = parseBody(completeSchema,request);
    const challenge = await app.database.withDeviceSessionPrincipal(principal,request.id,(store) => store.readChallenge(input.challengeId,principal.identityId,principal.sessionId,"enrollment"));
    if (!challenge?.publicJwk || !challenge.secretHash) throw invalidProof();
    const proof = await verifyCompactDeviceProof(input.proof,challenge.publicJwk);
    const boundProof = { ...proof };
    delete boundProof.iat;
    if (hashKeyLifecycleRequest(boundProof) !== hashKeyLifecycleRequest({ purpose:"nombramientos.device-session-enrollment",challengeId:input.challengeId,context:challenge.context })) throw invalidProof();
    const secret = Buffer.from(input.secret,"base64url");
    const secretDigest = digest(secret);
    secret.fill(0);
    if (!timingSafeEqual(Buffer.from(secretDigest),Buffer.from(challenge.secretHash))) throw invalidProof();
    if (challenge.context["sourceSessionId"] !== await sourceSession(app,principal)) throw invalidProof();
    const binding = await app.database.withDeviceSessionPrincipal(principal,request.id,(store) => store.bindSession({ challengeId:input.challengeId,identityId:principal.identityId,sessionId:principal.sessionId,deviceId:String(challenge.context["deviceId"]),sourceSessionId:challenge.context["sourceSessionId"] as string|null,signingFingerprint:String(challenge.context["signingFingerprint"]),publicJwk:challenge.publicJwk!,secretHash:secretDigest })).catch(mapStoreError);
    return respond(request,reply,{ binding },201);
  });
  app.post("/v1/device-session/proofs",{ preHandler:[app.authenticate,app.verifyCsrf] },async(request,reply) => {
    const principal = requirePrincipal(request);
    const input = parseBody(requestSchema,request);
    const binding = await app.database.withDeviceSessionPrincipal(principal,request.id,(store) => store.getBinding(principal.identityId,principal.sessionId));
    if (!binding || binding.status !== "active") throw new ApiError(428,"DEVICE_SESSION_ENROLLMENT_REQUIRED","Connect this browser before accessing protected data");
    const claims = { purpose:PURPOSE,version:1,jti:randomUUID(),nonce:randomBytes(32).toString("base64url"),htm:input.method,htu:targetUrl(app,input.path),iat:Math.floor(Date.now()/1000),sessionId:principal.sessionId,sourceSessionId:await sourceSession(app,principal),tenantId:principal.activeTenantId,identityId:principal.identityId,deviceId:binding.deviceId,signingFingerprint:binding.signingFingerprint,path:input.path,bodyHash:input.bodyHash,idempotencyKey:input.idempotencyKey };
    await app.database.withDeviceSessionPrincipal(principal,request.id,(store) => store.issueChallenge({ id:claims.jti,identityId:principal.identityId,sessionId:principal.sessionId,deviceId:binding.deviceId,purpose:"request",context:claims,expiresAt:new Date(Date.now()+60_000).toISOString() })).catch(mapStoreError);
    return respond(request,reply,{claims,publicJwk:binding.publicJwk,issuedAt:claims.iat},201);
  });
}
