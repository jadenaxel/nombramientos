import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { catalogPackage2025 } from "@nombramientos/catalog";
import { captureTenantInvariant, canonicalJson, compareTenantInvariants, ControlPlaneStore, DatabaseRuntime, decryptBackupPayload, encryptBackupPayload, hashFile, MemorySecretProvider, runMigrations, sha256, TenantProvisioner, verifyBackupManifest } from "@nombramientos/database";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildServer } from "../src/server.js";
import { requireCurrentGestionChurchAccess } from "../src/modules/gestionchurch-integration-routes.js";
import { assertEphemeralNames, assertWorkspaceAdminUrl, deriveEphemeralNames } from "../scripts/real-browser-stack-guards.js";
// Explicit opt-in. No source code, env file, or running church database is mutated.
const enabled = process.env["NOMBRAMIENTOS_PREMIUM_ISOLATED"] === "true";
const suite = enabled ? describe.sequential : describe.skip;
const root = path.resolve(import.meta.dirname, "../../..");
suite("premium federation and real cryptography on owned ephemeral PostgreSQL", () => {
    const names = deriveEphemeralNames(randomUUID(), randomUUID());
    const marker = `nom-premium-isolated:${names.runId}`;
    const gcTenantId = randomUUID(), subjectId = randomUUID(), secondSubjectId = randomUUID();
    const sourceA = randomUUID(), sourceB = randomUUID(), sourceC = randomUUID(), sourceD = randomUUID();
    const activeSources = new Set([sourceA, sourceB, sourceC, sourceD]);
    const sourceSubjects = new Map([[sourceA, subjectId], [sourceB, subjectId], [sourceC, subjectId], [sourceD, secondSubjectId]]);
    const centralRoles = new Map([[subjectId, ["TENANT_ADMIN"]], [secondSubjectId, ["TENANT_ADMIN"]]]);
    const roleFingerprint = (roles) => createHash("sha256").update([...roles].sort().join("\n")).digest("hex");
    const codes = new Map();
    const secret = randomBytes(32).toString("base64url");
    const origin = "http://localhost:33991"; // Only an Origin header; no listener on this fixed port.
    let adminUrl;
    let cluster, control, tenant;
    let provisioner, provider, app, apiConfig, database;
    let createdControl = false, markerWritten = false;
    let clientA, clientB, clientC, clientD;
    let e2ee;
    let cryptoClient;
    let deviceA;
    let deviceB, deviceC, deviceD, grantD;
    const signingDevices = new Map();
    const denialReceipts = [];
    const deviceAId = randomUUID(), deviceBId = randomUUID(), deviceCId = randomUUID(), deviceDId = randomUUID();
    const memberId = randomUUID(), futureMemberId = randomUUID();
    const plaintext = { displayName: "Synthetic confidential member", membershipStatus: "active" };
    let generationOne;
    let backup;
    let grantB, historicalEnvelope;
    let persistedReport;
    let postgresBin;
    const passphrase = `synthetic-recovery-${randomBytes(20).toString("hex")}`;
    const poolConfig = (database) => {
        const url = new URL(adminUrl);
        return { host: url.hostname, port: Number(url.port), user: decodeURIComponent(url.username), password: decodeURIComponent(url.password), database, ssl: false, max: 4, connectionTimeoutMillis: 5_000 };
    };
    const dbUrl = (database) => { const url = new URL(adminUrl); url.pathname = `/${database}`; return url.toString(); };
    async function formatted(format, values) {
        const result = await cluster.query(format, values);
        assert.ok(result.rows[0]?.sql);
        await cluster.query(result.rows[0].sql);
    }
    async function rawRequest(method, url, client, payload, idempotencyKey = randomUUID(), additionalHeaders = {}) {
        const response = await app.inject({ method, url, headers: { origin, "user-agent": "premium-isolated-fixture", ...(client ? { cookie: client.cookie, "x-csrf-token": client.csrf } : {}), ...(method !== "GET" ? { "idempotency-key": idempotencyKey } : {}), ...additionalHeaders }, ...(payload === undefined ? {} : { payload: payload }) });
        const body = response.json();
        const code = body.error?.code;
        if (client && typeof code === "string" && /^DEVICE_(?:PROOF|SESSION|SIGNING_KEY)_[A-Z_]+$/.test(code) && response.statusCode !== 429) {
            // Persisted tenant audit, not a mocked logger. Verify every denied
            // proof request at its actual requestId, without printing secrets.
            const denied = await tenant.query("SELECT id,actor_identity_id,action,entity_type,entity_id,result,request_id,metadata,hash_version FROM audit_events WHERE request_id=$1 AND action='e2ee.http_session.denied'", [body.meta.requestId]);
            expect(denied.rowCount, `Tenant audit must contain exactly one event for ${code}`).toBe(1);
            const event = denied.rows[0];
            expect(event).toMatchObject({ actor_identity_id: client.identityId, action: "e2ee.http_session.denied", entity_type: "auth_session", entity_id: client.sessionId, result: "denied", request_id: body.meta.requestId, hash_version: 2 });
            expect(Object.keys(event.metadata).sort()).toEqual(["code", "method", "route"]);
            expect(event.metadata.code).toBe(code);
            expect(event.metadata.method).toBe(method);
            expect(event.metadata.route).toMatch(/^\/v1\/[A-Za-z0-9_:/.-]+$/);
            const serialized = JSON.stringify(event.metadata);
            for (const sensitive of [client.cookie, client.csrf, additionalHeaders["x-device-proof"], payload?.secret, payload?.proof, "fixture-private-email@invalid.example"]) {
                if (typeof sensitive === "string" && sensitive.length > 8) expect(serialized).not.toContain(sensitive);
            }
            denialReceipts.push({ id: event.id, requestId: event.request_id, code });
        }
        return { status: response.statusCode, body, cookies: response.cookies };
    }
    async function signedJwt(signer, claims, headerOverrides = {}) {
        const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "dpop+jwt", jwk: signer.publicJwk, ...headerOverrides })).toString("base64url");
        const body = Buffer.from(JSON.stringify(claims)).toString("base64url");
        const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signer.keyPair.privateKey, new TextEncoder().encode(`${header}.${body}`));
        assert.equal(signature.byteLength, 64, "The fixture must emit the JWS ES256 P1363 signature format");
        return `${header}.${body}.${Buffer.from(signature).toString("base64url")}`;
    }
    const proofExempt = (url) => url === "/v1/session" || url === "/v1/auth/logout" || url === "/v1/key-lifecycle" || url === "/v1/device-session"
        || url === "/v1/key-lifecycle/challenges" || url === "/v1/key-lifecycle/devices" || url.startsWith("/v1/device-session/");
    async function proofFor(method, url, client, payload, idempotencyKey = "", claimOverrides = {}, signer = client?.signer) {
        assert.ok(signer, "A device signer is required by this fixture operation");
        const issued = await rawRequest("POST", "/v1/device-session/proofs", client, {
            method, path: url, bodyHash: sha256(payload === undefined ? "" : JSON.stringify(payload)), idempotencyKey: method === "GET" ? "" : idempotencyKey,
        });
        assert.equal(issued.status, 201, `Device proof issuance: HTTP ${issued.status}, ${issued.body.error?.code ?? "unexpected"}`);
        const claims = { ...issued.body.data.claims, ...claimOverrides };
        return { claims, proof: await signedJwt(signer, claims) };
    }
    async function request(method, url, client, payload, idempotencyKey = randomUUID()) {
        const headers = {};
        if (client?.signer && !proofExempt(url)) {
            const issued = await rawRequest("POST", "/v1/device-session/proofs", client, {
                method, path: url, bodyHash: sha256(payload === undefined ? "" : JSON.stringify(payload)), idempotencyKey: method === "GET" ? "" : idempotencyKey,
            });
            // Still send the requested operation when a revoked source cannot
            // obtain a nonce, so an expected denial observes the actual route.
            if (issued.status === 201) headers["x-device-proof"] = await signedJwt(client.signer, issued.body.data.claims);
        }
        return rawRequest(method, url, client, payload, idempotencyKey, headers);
    }
    async function data(method, url, client, payload) {
        const response = await request(method, url, client, payload);
        // Deliberately do not print complete responses: they can contain cookies or encrypted material.
        assert.ok(response.status >= 200 && response.status < 300, `${method} ${url}: HTTP ${response.status}, ${response.body.error?.code ?? "unexpected"}`);
        return response.body.data;
    }
    async function restartOwnedApi() {
        // This is only the test-owned Fastify instance. Preserve
        // PostgreSQL sessions, proof nonces and ciphertext; never restart the
        // user's stack or relax a production security rate-limit setting.
        await app.close();
        app = await buildServer({ config: apiConfig, database, logger: false, closeDatabaseOnShutdown: false });
        await app.ready();
    }
    async function openOwnedEventStream(client) {
        // The sole real HTTP listener belongs to this random fixture, on an OS
        // assigned IPv4 loopback port. No browser or original service is used.
        if (!app.server.listening) await app.listen({ host: "127.0.0.1", port: 0 });
        const address = app.server.address();
        assert.ok(address && typeof address === "object" && address.port > 0);
        assert.ok(![3000, 3300, 4000, 4100, 55432].includes(address.port));
        const url = `/v1/events?tenantId=${names.tenantId}`;
        const { proof } = await proofFor("GET", url, client);
        const controller = new AbortController();
        const response = await fetch(`http://127.0.0.1:${address.port}${url}`, { headers: { origin, "user-agent": "premium-isolated-fixture", cookie: client.cookie, "x-csrf-token": client.csrf, "x-device-proof": proof }, signal: controller.signal });
        assert.equal(response.status, 200, "The valid device must open its signed stream");
        assert.ok(response.body);
        const reader = response.body.getReader();
        const first = await reader.read();
        assert.ok(!first.done && new TextDecoder().decode(first.value).includes("event: ready"));
        return { controller, reader };
    }
    async function expectStreamClosed(stream) {
        const timer = setTimeout(() => stream.controller.abort(), 5000);
        try {
            for (let chunks = 0; chunks < 16; chunks += 1) {
                const next = await stream.reader.read();
                if (next.done) return;
            }
            assert.fail("A revoked device's stream did not terminate");
        } finally { clearTimeout(timer); }
    }
    async function login(sourceSessionId, subject = subjectId) {
        const code = randomBytes(32).toString("base64url");
        codes.set(code, { sourceSessionId, subject });
        const response = await request("POST", "/v1/integrations/gestionchurch/session", undefined, { code });
        assert.equal(response.status, 200, `Federation exchange: HTTP ${response.status}, ${response.body.error?.code ?? "unexpected"}`);
        const session = response.body.data;
        const token = response.cookies.find((item) => item.name === "nom_session")?.value;
        assert.ok(token);
        const stored = await control.query("SELECT id::text FROM auth_sessions WHERE token_hash=$1", [createHash("sha256").update(token).digest("hex")]);
        assert.ok(stored.rows[0]?.id);
        return { identityId: session.user.id, sessionId: stored.rows[0].id, sourceSessionId, csrf: session.csrfToken, cookie: response.cookies.map((item) => `${item.name}=${item.value}`).join("; ") };
    }
    async function signerFor(deviceId) {
        if (!signingDevices.has(deviceId)) {
            const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
            const exported = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
            signingDevices.set(deviceId, { keyPair, publicJwk: { kty: exported.kty, crv: exported.crv, x: exported.x, y: exported.y } });
        }
        return signingDevices.get(deviceId);
    }
    async function enrollDevice(client, device, deviceId) {
        const signer = await signerFor(deviceId);
        const challenge = await data("POST", "/v1/device-session/enrollment/challenge", client, { deviceId, publicJwk: signer.publicJwk });
        assert.equal(challenge.context.tenantId, names.tenantId);
        assert.equal(challenge.context.identityId, client.identityId);
        assert.equal(challenge.context.sessionId, client.sessionId);
        assert.equal(challenge.context.sourceSessionId, client.sourceSessionId);
        assert.equal(challenge.context.deviceId, deviceId);
        const secretBytes = await e2ee.openDeviceSessionChallenge({ recipient: device, challenge, expected: challenge.context });
        try {
            const proof = await signedJwt(signer, { purpose: "nombramientos.device-session-enrollment", challengeId: challenge.challengeId, context: challenge.context, iat: Math.floor(Date.now() / 1000) });
            await data("POST", "/v1/device-session/enrollment/complete", client, { challengeId: challenge.challengeId, secret: Buffer.from(secretBytes).toString("base64url"), proof });
            client.signer = signer;
            client.deviceId = deviceId;
        } finally { secretBytes.fill(0); }
    }
    async function mutate(operation, route, intent, client = clientA) {
        const challenge = await data("POST", "/v1/key-lifecycle/challenges", client, { operation, request: intent });
        return data("POST", route, client, { ...intent, challengeId: challenge.challengeId });
    }
    async function contentKey(bytes) { return crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]); }
    async function grantFor(device, deviceId, key = generationOne, generation = 1, identityId = clientA.identityId) {
        const recipient = await e2ee.importCustodianPublicKey(await e2ee.exportTenantDevicePublicKey(device));
        return e2ee.createTenantKeyGrantEnvelope({ tenantId: names.tenantId, tenantKeyId: key.tenantKeyId, generation, identityId, deviceId, tenantKey: key.keyBytes, recipient });
    }
    async function openGrant(envelope, device, deviceId, tenantKeyId = generationOne.tenantKeyId, generation = 1) {
        return e2ee.openTenantKeyGrantEnvelope({ envelope: envelope, recipient: device, expected: { tenantId: names.tenantId, tenantKeyId, generation, identityId: clientA.identityId, deviceId } });
    }
    async function storedMember(client, id = memberId) {
        const roster = await data("GET", "/v1/members?limit=250", client);
        const member = roster.items.find((item) => item.id === id);
        assert.ok(member);
        return member.displayEnvelope;
    }
    beforeAll(async () => {
        assertEphemeralNames(names);
        const install = JSON.parse(readFileSync(path.join(root, "packages/database/.local/install.json"), "utf8"));
        adminUrl = install.DATABASE_ADMIN_URL;
        postgresBin = install.POSTGRES_BIN;
        assert.ok(typeof postgresBin === "string" && path.isAbsolute(postgresBin));
        assertWorkspaceAdminUrl(adminUrl);
        cluster = new Pool(poolConfig("postgres"));
        const existing = await cluster.query("SELECT 1 FROM pg_database WHERE datname=ANY($1::text[]) UNION ALL SELECT 1 FROM pg_roles WHERE rolname=ANY($2::text[])", [[names.controlDatabase, names.tenantDatabase], [names.ownerRole, names.runtimeRole]]);
        assert.equal(existing.rowCount, 0, "Generated resources must be absent before provisioning");
        await formatted("SELECT format('CREATE DATABASE %I TEMPLATE template0', $1::text) sql", [names.controlDatabase]);
        createdControl = true;
        control = new Pool(poolConfig(names.controlDatabase));
        await control.query("CREATE TABLE premium_fixture_marker(run_id uuid PRIMARY KEY, marker text NOT NULL)");
        await control.query("INSERT INTO premium_fixture_marker VALUES ($1,$2)", [names.runId, marker]);
        markerWritten = true;
        await runMigrations(control, { scope: "control", directory: path.join(root, "packages/database/migrations/control") });
        const secrets = new MemorySecretProvider();
        provisioner = new TenantProvisioner({ admin: poolConfig("postgres"), control, secrets, catalog: catalogPackage2025, migrationsRoot: path.join(root, "packages/database/migrations") });
        await provisioner.provision({ idempotencyKey: names.runId, tenantId: names.tenantId, slug: names.tenantSlug, displayName: "Premium synthetic nominations", kind: "real", timezone: "America/La_Paz", locale: "es" });
        tenant = new Pool(poolConfig(names.tenantDatabase));
        await tenant.query("CREATE TABLE premium_fixture_marker(run_id uuid PRIMARY KEY, marker text NOT NULL)");
        await tenant.query("INSERT INTO premium_fixture_marker VALUES ($1,$2)", [names.runId, marker]);
        e2ee = await import(pathToFileURL(path.join(root, "packages/e2ee/dist/index.js")).href);
        cryptoClient = await import(pathToFileURL(path.join(root, "apps/web/lib/crypto-client.ts")).href);
        provider = createServer(async (req, res) => {
            try {
                if (req.headers["x-integration-secret"] !== secret) {
                    res.writeHead(403).end();
                    return;
                }
                let text = "";
                for await (const chunk of req) {
                    text += chunk.toString();
                    if (text.length > 8192)
                        throw new Error("fixture payload too large");
                }
                const body = JSON.parse(text);
                res.setHeader("content-type", "application/json");
                if (req.url === "/redeem") {
                    const source = codes.get(body["code"]);
                    codes.delete(body["code"]);
                    if (!source || !activeSources.has(source.sourceSessionId) || sourceSubjects.get(source.sourceSessionId) !== source.subject) {
                        res.writeHead(401).end("{}");
                        return;
                    }
                    const roles = centralRoles.get(source.subject);
                    res.end(JSON.stringify({ subject: { id: source.subject, scope: "tenant", email: `${source.subject}@fixture.invalid`, name: "Synthetic centrally assigned user", roles, roleFingerprint: roleFingerprint(roles), sourceSessionId: source.sourceSessionId }, tenant: { id: gcTenantId, slug: names.tenantSlug, name: "Premium synthetic nominations", timezone: "America/La_Paz" } }));
                }
                else if (req.url === "/authorize") {
                    const roles = centralRoles.get(body["subjectId"]);
                    res.end(JSON.stringify({ authorized: Boolean(roles) && body["tenantId"] === gcTenantId && activeSources.has(body["sourceSessionId"]) && sourceSubjects.get(body["sourceSessionId"]) === body["subjectId"], ...(roles ? { roles, roleFingerprint: roleFingerprint(roles) } : {}) }));
                }
                else {
                    res.writeHead(404).end("{}");
                }
            }
            catch {
                res.writeHead(400).end("{}");
            }
        });
        await new Promise((resolve) => provider.listen(0, "127.0.0.1", resolve));
        const providerUrl = `http://127.0.0.1:${provider.address().port}`;
        apiConfig = { environment: "test", host: "127.0.0.1", port: 0, corsOrigins: new Set([origin]), secureCookies: false, sessionTtlSeconds: 1800, webauthn: { rpName: "Synthetic Nom", rpId: "localhost", expectedOrigins: [origin], challengeTtlSeconds: 300, stepUpTtlSeconds: 120 }, authEncryptionKey: randomBytes(32), controlDatabaseUrl: dbUrl(names.controlDatabase), secretMasterKey: randomBytes(32), secretFile: "unused-memory-only", tenantPoolMax: 3, tenantPoolIdleMs: 1000, gestionChurchIntegration: { enabled: true, sharedSecret: secret, redeemUrl: `${providerUrl}/redeem`, authorizeUrl: `${providerUrl}/authorize`, organizationUrl: `${providerUrl}/organization` } };
        database = new DatabaseRuntime({ control: poolConfig(names.controlDatabase), secretProvider: secrets, tenantPoolMax: 3, tenantPoolIdleMs: 1000 });
        app = await buildServer({ config: apiConfig, database, logger: false, closeDatabaseOnShutdown: false });
        await app.ready();
        console.info(JSON.stringify({ fixture: marker, phase: "owned-resources-created", controlDatabase: names.controlDatabase, tenantDatabase: names.tenantDatabase, ownerRole: names.ownerRole, runtimeRole: names.runtimeRole }));
    }, 90_000);
    afterAll(async () => {
        await app?.close();
        await database?.close();
        if (provider)
            await new Promise((resolve, reject) => provider.close((error) => error ? reject(error) : resolve()));
        await provisioner?.close();
        if (!cluster || !createdControl) {
            await cluster?.end();
            return;
        }
        assertEphemeralNames(names);
        // Ownership proof is mandatory. Refuse cleanup rather than guessing after a partial setup.
        assert.ok(markerWritten && control, "Owned control marker is required for cleanup");
        const proof = await control.query("SELECT marker FROM premium_fixture_marker WHERE run_id=$1", [names.runId]);
        assert.equal(proof.rows[0]?.marker, marker);
        if (tenant) {
            const proof = await tenant.query("SELECT marker FROM premium_fixture_marker WHERE run_id=$1", [names.runId]);
            assert.equal(proof.rows[0]?.marker, marker);
        }
        await tenant?.end();
        await control.end();
        const activity = await cluster.query("SELECT 1 FROM pg_stat_activity WHERE datname=ANY($1::text[])", [[names.controlDatabase, names.tenantDatabase]]);
        assert.equal(activity.rowCount, 0, "Cleanup never terminates another connection");
        const created = await cluster.query("SELECT datname FROM pg_database WHERE datname=ANY($1::text[])", [[names.tenantDatabase, names.controlDatabase]]);
        for (const target of [names.tenantDatabase, names.controlDatabase])
            if (created.rows.some((item) => item.datname === target))
                await formatted("SELECT format('DROP DATABASE %I', $1::text) sql", [target]);
        for (const target of [names.runtimeRole, names.ownerRole])
            await formatted("SELECT format('DROP ROLE IF EXISTS %I', $1::text) sql", [target]);
        const remaining = await cluster.query("SELECT 1 FROM pg_database WHERE datname=ANY($1::text[]) UNION ALL SELECT 1 FROM pg_roles WHERE rolname=ANY($2::text[])", [[names.controlDatabase, names.tenantDatabase], [names.ownerRole, names.runtimeRole]]);
        assert.equal(remaining.rowCount, 0, "Owned fixture cleanup must be complete");
        console.info(JSON.stringify({ fixture: marker, phase: "owned-resources-cleaned", databasesAndRolesRemaining: remaining.rowCount }));
        await cluster.end();
    }, 30_000);
    it("keeps two source sessions of the same user independently active after SSO", async () => {
        clientA = await login(sourceA);
        clientB = await login(sourceB);
        expect(clientA.identityId).toBe(clientB.identityId);
        expect(clientA.sessionId).not.toBe(clientB.sessionId);
        const sessionIds = [clientA.sessionId, clientB.sessionId];
        const expiriesBefore = await control.query("SELECT id::text,expires_at FROM auth_sessions WHERE id=ANY($1::uuid[]) ORDER BY id", [sessionIds]);
        const requestedAt = Date.now();
        const sessionA = await request("GET", "/v1/session", clientA);
        const sessionB = await request("GET", "/v1/session", clientB);
        expect(sessionA.status).toBe(200);
        expect(sessionB.status).toBe(200);
        for (const [client, session] of [[clientA, sessionA], [clientB, sessionB]]) {
            expect(session.body.data.sessionId).toBe(client.sessionId);
            const serverTime = Date.parse(session.body.data.serverTime);
            expect(Number.isFinite(serverTime)).toBe(true);
            expect(serverTime).toBeGreaterThanOrEqual(requestedAt);
            expect(serverTime).toBeLessThanOrEqual(Date.now());
        }
        expect((await control.query("SELECT id::text,expires_at FROM auth_sessions WHERE id=ANY($1::uuid[]) ORDER BY id", [sessionIds])).rows).toEqual(expiriesBefore.rows);
        const rows = await control.query("SELECT gestionchurch_source_session_id::text source FROM auth_sessions WHERE identity_id=$1 AND revoked_at IS NULL ORDER BY source", [clientA.identityId]);
        expect(rows.rows.map((item) => item.source).sort()).toEqual([sourceA, sourceB].sort());
    });
    it("grants device B access to exactly the same persisted confidential member; pending and wrong contexts cannot decrypt", async () => {
        deviceA = await e2ee.generateTenantDeviceKeyPair({ tenantId: names.tenantId, deviceId: deviceAId });
        deviceB = await e2ee.generateTenantDeviceKeyPair({ tenantId: names.tenantId, deviceId: deviceBId });
        for (const [device, id, client] of [[deviceA, deviceAId, clientA], [deviceB, deviceBId, clientB]]) {
            await mutate("device.register", "/v1/key-lifecycle/devices", { deviceId: id, label: id === deviceAId ? "Synthetic browser A" : "Synthetic browser B", wrappingPublicKey: await e2ee.exportTenantDevicePublicKey(device) }, client);
            await enrollDevice(client, device, id);
            expect((await request("GET", "/v1/session", client)).status).toBe(200);
            expect((await request("GET", "/v1/key-lifecycle", client)).status).toBe(200);
            const pending = await request("GET", "/v1/members?limit=250", client);
            expect(pending.status).toBe(403);
            expect(pending.body.error.code).toBe("DEVICE_SESSION_APPROVAL_REQUIRED");
        }
        generationOne = e2ee.generateTenantContentKey();
        backup = await e2ee.createEncryptedTenantKeyRecoveryBackup({ tenantId: names.tenantId, tenantKeyId: generationOne.tenantKeyId, generation: 1, tenantKey: generationOne.keyBytes, passphrase });
        const grantA = await mutate("grant.initialize", "/v1/key-lifecycle/grants/initialize", { deviceId: deviceAId, tenantKeyId: generationOne.tenantKeyId, envelope: await grantFor(deviceA, deviceAId), recoveryPublicKey: backup.recoveryPublicKey });
        await expect(openGrant(grantA.envelope, deviceB, deviceAId)).rejects.toThrow();
        const state = await data("GET", "/v1/key-lifecycle", clientB);
        expect(state.devices.find((item) => item.deviceId === deviceBId)?.status).toBe("pending");
        const pendingB = await request("GET", "/v1/members?limit=250", clientB);
        expect(pendingB.status).toBe(403);
        expect(pendingB.body.error.code).toBe("DEVICE_SESSION_APPROVAL_REQUIRED");
        grantB = await mutate("grant.approve", "/v1/key-lifecycle/grants", { targetIdentityId: clientB.identityId, targetDeviceId: deviceBId, tenantKeyId: generationOne.tenantKeyId, generation: 1, envelope: await grantFor(deviceB, deviceBId) });
        for (const client of [clientA, clientB]) {
            const sessions = (await data("GET", "/v1/auth/sessions", client)).items;
            expect(sessions.find((item) => item.id === clientA.sessionId)?.deviceLabel).toBe("Synthetic browser A");
            expect(sessions.find((item) => item.id === clientB.sessionId)?.deviceLabel).toBe("Synthetic browser B");
            expect(sessions.filter((item) => item.current).map((item) => item.id)).toEqual([client.sessionId]);
            expect(sessions.map((item) => item.id).sort()).toEqual([clientA.sessionId, clientB.sessionId].sort());
        }
        const keyA = await contentKey(generationOne.keyBytes);
        const sealed = await cryptoClient.encryptJson(keyA, generationOne.tenantKeyId, { tenantId: names.tenantId, memberId, purpose: "member-display", schemaVersion: 1 }, plaintext);
        await data("POST", "/v1/members", clientA, { id: memberId, eligible: true, displayEnvelope: sealed.envelope, displayContentHash: sealed.contentHash });
        historicalEnvelope = await storedMember(clientB);
        const openedB = await openGrant(grantB.envelope, deviceB, deviceBId);
        try {
            expect(await cryptoClient.decryptJson(await contentKey(openedB.keyBytes), historicalEnvelope, { keyId: generationOne.tenantKeyId, aad: { tenantId: names.tenantId, memberId, purpose: "member-display", schemaVersion: 1 }, exactAad: true })).toEqual(plaintext);
            await expect(cryptoClient.decryptJson(await contentKey(openedB.keyBytes), historicalEnvelope, { aad: { tenantId: randomUUID() } })).rejects.toThrow();
            await expect(openGrant({ ...grantB.envelope, ciphertext: "AAAA" }, deviceB, deviceBId)).rejects.toThrow();
        }
        finally {
            openedB.keyBytes.fill(0);
        }
        const persisted = await tenant.query("SELECT display_envelope::text value FROM members WHERE id=$1", [memberId]);
        expect(persisted.rows[0]?.value).not.toContain(plaintext.displayName);
        expect(JSON.stringify(grantB)).not.toContain(Buffer.from(generationOne.keyBytes).toString("base64url"));
    }, 20_000);
    it("rejects copied cookies, forged or replayed request proofs, and every signed request-context substitution", async () => {
        const target = "/v1/members?limit=250";
        const copiedCookie = { ...clientA, signer: undefined };
        const missing = await rawRequest("GET", target, copiedCookie);
        expect(missing.status).toBe(401);
        const first = await proofFor("GET", target, clientA);
        expect((await rawRequest("GET", target, clientA, undefined, undefined, { "x-device-proof": first.proof })).status).toBe(200);
        const replay = await rawRequest("GET", target, clientA, undefined, undefined, { "x-device-proof": first.proof });
        expect(replay.status).toBe(401);
        const impostor = await signerFor(randomUUID());
        const theft = await proofFor("GET", target, clientA, undefined, "", {}, impostor);
        expect((await rawRequest("GET", target, copiedCookie, undefined, undefined, { "x-device-proof": theft.proof })).status).toBe(401);
        for (const replacement of [
            { tenantId: randomUUID() }, { identityId: randomUUID() }, { sessionId: clientB.sessionId },
            { sourceSessionId: sourceB }, { deviceId: deviceBId }, { signingFingerprint: `sha256:${"0".repeat(64)}` },
            { htm: "POST" }, { htu: "https://different-origin.invalid/v1/members" },
            { path: "/v1/catalog" }, { bodyHash: sha256("different-body") }, { nonce: randomUUID() },
            { jti: randomUUID() }, { iat: Math.floor(Date.now() / 1000) - 3600 }, { iat: Math.floor(Date.now() / 1000) + 3600 },
        ]) {
            const changed = await proofFor("GET", target, clientA, undefined, "", replacement);
            const refused = await rawRequest("GET", target, clientA, undefined, undefined, { "x-device-proof": changed.proof });
            expect(refused.status, `Substituted claim ${Object.keys(replacement)[0]} must be refused`).toBe(401);
        }
        const queryBound = await proofFor("GET", target, clientA);
        expect((await rawRequest("GET", "/v1/members?limit=249", clientA, undefined, undefined, { "x-device-proof": queryBound.proof })).status).toBe(401);
        const body = { expectedVersion: 1, available: true }, idempotencyKey = randomUUID();
        const bodyBound = await proofFor("PATCH", `/v1/members/${memberId}`, clientA, body, idempotencyKey);
        expect((await rawRequest("PATCH", `/v1/members/${memberId}`, clientA, { ...body, available: false }, idempotencyKey, { "x-device-proof": bodyBound.proof })).status).toBe(401);
        const keyBound = await proofFor("PATCH", `/v1/members/${memberId}`, clientA, body, idempotencyKey);
        expect((await rawRequest("PATCH", `/v1/members/${memberId}`, clientA, body, randomUUID(), { "x-device-proof": keyBound.proof })).status).toBe(401);
        expect((await tenant.query("SELECT version,available FROM members WHERE id=$1", [memberId])).rows[0]).toEqual({ version: 1, available: true });
        // A browser routinely opens panels concurrently. Distinct server nonces
        // must not produce a shared-lock upgrade deadlock or a spurious 500.
        const parallel = await Promise.all(Array.from({ length: 6 }, () => proofFor("GET", target, clientA)));
        const responses = await Promise.all(parallel.map(({ proof }) => rawRequest("GET", target, clientA, undefined, undefined, { "x-device-proof": proof })));
        expect(responses.map(({ status }) => status)).toEqual(Array(6).fill(200));
    }, 30_000);
    it("bounds expired nonce cleanup without deleting live proofs, grants, signers, bindings or audit history", async () => {
        const target = "/v1/members?limit=250";
        const liveProof = await proofFor("GET", target, clientA);
        const expiredProof = await proofFor("GET", target, clientA);
        const protectedSnapshot = async () => (await tenant.query(`SELECT jsonb_build_object(
          'generations',(SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id) FROM e2ee_key_generations g),
          'grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id) FROM e2ee_key_grants g),
          'devices',(SELECT jsonb_agg(to_jsonb(d) ORDER BY d.device_id) FROM e2ee_key_devices d),
          'signers',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.device_id) FROM e2ee_http_devices s),
          'bindings',(SELECT jsonb_agg(to_jsonb(b) ORDER BY b.session_id) FROM e2ee_http_session_bindings b),
          'members',(SELECT jsonb_agg(to_jsonb(m) ORDER BY m.id) FROM members m)
        ) value`)).rows[0].value;
        const protectedBefore = await protectedSnapshot();
        const auditBefore = await tenant.query("SELECT * FROM audit_events ORDER BY id");
        await tenant.query("UPDATE e2ee_http_challenges SET expires_at=clock_timestamp()-interval '1 minute' WHERE id=$1", [expiredProof.claims.jti]);
        const expiredIds = Array.from({ length: 701 }, () => randomUUID());
        await tenant.query(`INSERT INTO e2ee_http_challenges(id,identity_id,session_id,device_id,purpose,context,expires_at,consumed_at)
          SELECT id,$2,$3,$4,'request','{"fixture":"expired-only"}'::jsonb,clock_timestamp()-interval '1 hour',
            CASE WHEN ordinal%2=0 THEN clock_timestamp()-interval '2 hours' ELSE NULL END
          FROM unnest($1::uuid[]) WITH ORDINALITY fixture(id,ordinal)`,
        [expiredIds, clientA.identityId, clientA.sessionId, deviceAId]);
        // One statement deletes at most500. The older synthetic rows precede
        // the intentionally expired real proof, so201 of701 remain until the
        // next ordinary runtime issuance fires another bounded cleanup.
        expect((await tenant.query("SELECT count(*)::int count FROM e2ee_http_challenges WHERE id=ANY($1::uuid[])", [expiredIds])).rows[0].count).toBe(201);
        const triggerProof = await proofFor("GET", target, clientA);
        expect((await tenant.query("SELECT count(*)::int count FROM e2ee_http_challenges WHERE id=ANY($1::uuid[])", [[...expiredIds, expiredProof.claims.jti]])).rows[0].count).toBe(0);
        expect((await tenant.query("SELECT id FROM e2ee_http_challenges WHERE id=ANY($1::uuid[]) AND consumed_at IS NULL", [[liveProof.claims.jti, triggerProof.claims.jti]])).rowCount).toBe(2);
        expect(await protectedSnapshot()).toEqual(protectedBefore);
        expect((await tenant.query("SELECT * FROM audit_events ORDER BY id")).rows).toEqual(auditBefore.rows);
        const privileges = await tenant.query(`SELECT
          has_table_privilege($1,'e2ee_http_challenges','DELETE') can_delete,
          has_function_privilege($1,'prune_expired_e2ee_http_challenges()','EXECUTE') can_execute,
          p.prosecdef,p.proowner::regrole::text owner,p.proconfig
          FROM pg_proc p WHERE p.oid='prune_expired_e2ee_http_challenges()'::regprocedure`, [names.runtimeRole]);
        expect(privileges.rows[0]).toEqual({ can_delete: false, can_execute: false, prosecdef: true, owner: names.ownerRole, proconfig: ["search_path=pg_catalog"] });
        expect((await rawRequest("GET", target, clientA, undefined, undefined, { "x-device-proof": expiredProof.proof })).status).toBe(401);
        expect((await rawRequest("GET", target, clientA, undefined, undefined, { "x-device-proof": liveProof.proof })).status).toBe(200);
        expect((await rawRequest("GET", target, clientA, undefined, undefined, { "x-device-proof": liveProof.proof })).status).toBe(401);
        expect((await rawRequest("GET", target, clientA, undefined, undefined, { "x-device-proof": triggerProof.proof })).status).toBe(200);
        expect((await tenant.query("SELECT * FROM audit_events WHERE id=ANY($1::uuid[]) ORDER BY id", [auditBefore.rows.map(({ id }) => id)])).rows).toEqual(auditBefore.rows);
    }, 30_000);
    it("requires existing wrapping-key possession and preserves an immutable signer during enrollment attempts", async () => {
        const original = await tenant.query("SELECT signing_fingerprint FROM e2ee_http_devices WHERE device_id=$1", [deviceAId]);
        const challenge = await data("POST", "/v1/device-session/enrollment/challenge", clientA, { deviceId: deviceAId, publicJwk: clientA.signer.publicJwk });
        await expect(e2ee.openDeviceSessionChallenge({ recipient: deviceB, challenge, expected: challenge.context })).rejects.toThrow();
        const secretBytes = await e2ee.openDeviceSessionChallenge({ recipient: deviceA, challenge, expected: challenge.context });
        const claims = { purpose: "nombramientos.device-session-enrollment", challengeId: challenge.challengeId, context: challenge.context, iat: Math.floor(Date.now() / 1000) };
        try {
            const validProof = await signedJwt(clientA.signer, claims);
            const wrongSecret = await rawRequest("POST", "/v1/device-session/enrollment/complete", clientA, { challengeId: challenge.challengeId, secret: randomBytes(32).toString("base64url"), proof: validProof });
            expect(wrongSecret.status).toBe(401);
            const otherSession = await rawRequest("POST", "/v1/device-session/enrollment/complete", clientB, { challengeId: challenge.challengeId, secret: Buffer.from(secretBytes).toString("base64url"), proof: validProof });
            expect(otherSession.status).toBe(401);
            const replacedContext = await rawRequest("POST", "/v1/device-session/enrollment/complete", clientA, { challengeId: challenge.challengeId, secret: Buffer.from(secretBytes).toString("base64url"), proof: await signedJwt(clientA.signer, { ...claims, context: { ...challenge.context, sourceSessionId: sourceB } }) });
            expect(replacedContext.status).toBe(401);
            const complete = { challengeId: challenge.challengeId, secret: Buffer.from(secretBytes).toString("base64url"), proof: validProof };
            expect((await rawRequest("POST", "/v1/device-session/enrollment/complete", clientA, complete)).status).toBe(201);
            expect((await rawRequest("POST", "/v1/device-session/enrollment/complete", clientA, complete)).status).toBe(401);
        } finally { secretBytes.fill(0); }
        const attacker = await signerFor(randomUUID());
        const replacement = await rawRequest("POST", "/v1/device-session/enrollment/challenge", clientA, { deviceId: deviceAId, publicJwk: attacker.publicJwk });
        if (replacement.status < 300) {
            // Even possession of the wrapping key must not silently overwrite a
            // previously authorized signer. A lost signer requires recovery.
            const opened = await e2ee.openDeviceSessionChallenge({ recipient: deviceA, challenge: replacement.body.data, expected: replacement.body.data.context });
            try {
                const replaced = await rawRequest("POST", "/v1/device-session/enrollment/complete", clientA, {
                    challengeId: replacement.body.data.challengeId, secret: Buffer.from(opened).toString("base64url"),
                    proof: await signedJwt(attacker, { purpose: "nombramientos.device-session-enrollment", challengeId: replacement.body.data.challengeId, context: replacement.body.data.context, iat: Math.floor(Date.now() / 1000) }),
                });
                expect(replaced.status).toBe(401);
            } finally { opened.fill(0); }
        } else { expect([401, 409]).toContain(replacement.status); }
        expect((await tenant.query("SELECT signing_fingerprint FROM e2ee_http_devices WHERE device_id=$1", [deviceAId])).rows).toEqual(original.rows);
        expect((await request("GET", "/v1/members?limit=250", clientA)).status).toBe(200);
    }, 30_000);
    it("never replaces a federated session source and closes a live stream when control source differs from its proven binding", async () => {
        const token = clientA.cookie.split("; ").find((item) => item.startsWith("nom_session="))?.slice("nom_session=".length);
        assert.ok(token);
        await expect(database.control.bindGestionChurchSession(createHash("sha256").update(token).digest("hex"), clientA.identityId, sourceB)).rejects.toThrow("Federated session binding failed");
        expect(await database.control.getGestionChurchSessionBinding(clientA.sessionId, clientA.identityId, names.tenantId)).toBe(sourceA);
        const target = "/v1/members?limit=250";
        const existingProof = await proofFor("GET", target, clientA);
        const stream = await openOwnedEventStream(clientA);
        try {
            // Fault injection affects only this explicitly owned fixture. A
            // normal API bind already refused this replacement above.
            await control.query("UPDATE auth_sessions SET gestionchurch_source_session_id=$2 WHERE id=$1", [clientA.sessionId, sourceB]);
            const denied = await rawRequest("GET", target, clientA, undefined, undefined, { "x-device-proof": existingProof.proof });
            expect(denied.status).toBe(401);
            expect(denied.body.error.code).toBe("DEVICE_SESSION_SOURCE_CHANGED");
            await expectStreamClosed(stream);
            expect((await tenant.query("SELECT source_session_id::text FROM e2ee_http_session_bindings WHERE session_id=$1", [clientA.sessionId])).rows[0].source_session_id).toBe(sourceA);
        } finally {
            stream.controller.abort();
            await stream.reader.cancel().catch(() => undefined);
            await control.query("UPDATE auth_sessions SET gestionchurch_source_session_id=$2 WHERE id=$1", [clientA.sessionId, sourceA]);
        }
        expect((await rawRequest("GET", target, clientA, undefined, undefined, { "x-device-proof": existingProof.proof })).status).toBe(200);
    }, 15_000);
    it("recovers the existing member on a fresh C device with an offline backup; rejects wrong password and nonce replay", async () => {
        await expect(e2ee.openEncryptedTenantKeyRecoveryBackup(backup.backup, "synthetic-wrong-password")).rejects.toThrow();
        clientC = await login(sourceC);
        deviceC = await e2ee.generateTenantDeviceKeyPair({ tenantId: names.tenantId, deviceId: deviceCId });
        await mutate("device.register", "/v1/key-lifecycle/devices", { deviceId: deviceCId, label: "Synthetic recovered device", wrappingPublicKey: await e2ee.exportTenantDevicePublicKey(deviceC) }, clientC);
        await enrollDevice(clientC, deviceC, deviceCId);
        const pendingC = await request("GET", "/v1/members?limit=250", clientC);
        expect(pendingC.status).toBe(403);
        expect(pendingC.body.error.code).toBe("DEVICE_SESSION_APPROVAL_REQUIRED");
        const recovered = await e2ee.openEncryptedTenantKeyRecoveryBackup(backup.backup, passphrase);
        try {
            const recipient = await e2ee.importCustodianPublicKey(await e2ee.exportTenantDevicePublicKey(deviceC));
            const envelope = await e2ee.createTenantKeyGrantEnvelope({ tenantId: names.tenantId, tenantKeyId: recovered.tenantKeyId, generation: 1, identityId: clientA.identityId, deviceId: deviceCId, tenantKey: recovered.tenantKey, recipient });
            const authorization = await e2ee.signTenantKeyRecovery(recovered.recoverySigningKey, e2ee.createTenantKeyRecoveryContext({ tenantId: names.tenantId, tenantKeyId: recovered.tenantKeyId, generation: 1, recoveryNonce: randomUUID(), targetIdentityId: clientA.identityId, targetDeviceId: deviceCId, targetDeviceFingerprint: deviceC.fingerprint, envelopeHash: envelope.envelopeHash }));
            const intent = { tenantKeyId: recovered.tenantKeyId, targetIdentityId: clientA.identityId, targetDeviceId: deviceCId, envelope, authorization };
            // Recovery is initiated by the fresh C browser that owns the
            // signed/wrapping keys; A's session is not silently rebound to C.
            const grant = await mutate("key.recover", "/v1/key-lifecycle/recoveries", intent, clientC);
            const fresh = await openGrant(grant.envelope, deviceC, deviceCId);
            try {
                expect(await cryptoClient.decryptJson(await contentKey(fresh.keyBytes), await storedMember(clientA))).toEqual(plaintext);
            }
            finally {
                fresh.keyBytes.fill(0);
            }
            const challenge = await data("POST", "/v1/key-lifecycle/challenges", clientC, { operation: "key.recover", request: intent });
            const replay = await request("POST", "/v1/key-lifecycle/recoveries", clientC, { ...intent, challengeId: challenge.challengeId });
            expect(replay.status).toBe(409);
        }
        finally {
            recovered.tenantKey.fill(0);
        }
    }, 20_000);
    it("rechecks a queued metadata-only write inside its transaction after the exact device is revoked", async () => {
        const source = randomUUID(), deviceId = randomUUID(), raceMemberId = randomUUID();
        activeSources.add(source);
        sourceSubjects.set(source, subjectId);
        const client = await login(source);
        const device = await e2ee.generateTenantDeviceKeyPair({ tenantId: names.tenantId, deviceId });
        await mutate("device.register", "/v1/key-lifecycle/devices", { deviceId, label: "Synthetic race device", wrappingPublicKey: await e2ee.exportTenantDevicePublicKey(device) }, client);
        await enrollDevice(client, device, deviceId);
        const grant = await mutate("grant.approve", "/v1/key-lifecycle/grants", { targetIdentityId: client.identityId, targetDeviceId: deviceId, tenantKeyId: generationOne.tenantKeyId, generation: 1, envelope: await grantFor(device, deviceId) });
        const display = await cryptoClient.encryptJson(await contentKey(generationOne.keyBytes), generationOne.tenantKeyId, { tenantId: names.tenantId, memberId: raceMemberId, purpose: "member-display", schemaVersion: 1 }, { displayName: "Synthetic revocation race" });
        await data("POST", "/v1/members", clientA, { id: raceMemberId, eligible: true, displayEnvelope: display.envelope, displayContentHash: display.contentHash });
        const payload = { expectedVersion: 1, available: false }, key = randomUUID();
        const { proof } = await proofFor("PATCH", `/v1/members/${raceMemberId}`, client, payload, key);
        const original = app.database.withPrincipal;
        let release, markReached;
        const admitted = new Promise((resolve) => { markReached = resolve; });
        const barrier = new Promise((resolve) => { release = resolve; });
        let gated = false, pending;
        // This test-owned server barrier pauses after route authentication but
        // before the data transaction. It models a queued admitted request,
        // not a production hook or an invented database-side revocation.
        app.database.withPrincipal = async function (principal, requestId, work) {
            if (principal.sessionId === client.sessionId && !gated) {
                gated = true;
                markReached();
                await barrier;
            }
            return original.call(this, principal, requestId, work);
        };
        try {
            pending = rawRequest("PATCH", `/v1/members/${raceMemberId}`, client, payload, key, { "x-device-proof": proof });
            let timer;
            try {
                await Promise.race([admitted, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("The queued write did not reach the transaction barrier")), 5000); })]);
            } finally { clearTimeout(timer); }
            await mutate("grant.revoke", "/v1/key-lifecycle/grants/revoke", { grantId: grant.grantId, expectedVersion: grant.version, reasonCode: "DEVICE_RETIRED", confirmLastActiveGrant: false });
            release();
            expect((await pending).status).toBe(401);
            expect((await tenant.query("SELECT version,available FROM members WHERE id=$1", [raceMemberId])).rows[0]).toEqual({ version: 1, available: true });
            expect((await request("GET", "/v1/members?limit=250", clientA)).status).toBe(200);
        } finally {
            release();
            app.database.withPrincipal = original;
            await pending?.catch(() => undefined);
            activeSources.delete(source);
        }
    }, 30_000);
    it("denies federated administrators operational voter/custodian entitlement instead of inventing roles", async () => {
        clientD = await login(sourceD, secondSubjectId);
        expect(clientD.identityId).not.toBe(clientA.identityId);
        deviceD = await e2ee.generateTenantDeviceKeyPair({ tenantId: names.tenantId, deviceId: deviceDId });
        await mutate("device.register", "/v1/key-lifecycle/devices", { deviceId: deviceDId, label: "Synthetic second elector", wrappingPublicKey: await e2ee.exportTenantDevicePublicKey(deviceD) }, clientD);
        await enrollDevice(clientD, deviceD, deviceDId);
        grantD = await mutate("grant.approve", "/v1/key-lifecycle/grants", { targetIdentityId: clientD.identityId, targetDeviceId: deviceDId, tenantKeyId: generationOne.tenantKeyId, generation: 1, envelope: await grantFor(deviceD, deviceDId, generationOne, 1, clientD.identityId) });
        const ownSessions = (await data("GET", "/v1/auth/sessions", clientD)).items;
        expect(ownSessions.map((item) => item.id)).toEqual([clientD.sessionId]);
        expect(ownSessions[0]?.deviceLabel).toBe("Synthetic second elector");
        expect(ownSessions[0]?.current).toBe(true);
        expect(JSON.stringify(ownSessions)).not.toContain("Synthetic browser A");
        expect(JSON.stringify(ownSessions)).not.toContain("Synthetic browser B");
        const managerSessions = (await data("GET", "/v1/auth/sessions", clientA)).items;
        expect(managerSessions.some((item) => item.id === clientD.sessionId)).toBe(false);
        expect(JSON.stringify(managerSessions)).not.toContain("Synthetic second elector");
        const roles = await data("GET", "/v1/access/roles", clientA);
        const custodian = roles.items.find((item) => item.code === "TALLY_CUSTODIAN");
        assert.ok(custodian);
        const registration = await request("POST", "/v1/custody/keys", clientA, {});
        expect(registration.status).toBe(403);
        const binding = await request("POST", "/v1/access/bindings", clientA, { targetIdentityId: clientD.identityId, roleId: custodian.id });
        expect(binding.status).toBe(403);
        expect(binding.body.error.code).toBe("GESTIONCHURCH_MANAGED_OPERATIONAL_ROLE");
    });
    it("runs an owned cycle through encrypted proposals, two-custodian ballots, acceptance, election, organization and a retrieved CSV artifact", async () => {
        // Operational bindings now come exclusively from explicit central role
        // assertions through the real SSO exchange/projection, not direct SQL.
        centralRoles.set(subjectId, ["TENANT_ADMIN", "NOMINATIONS_COMMISSION_MEMBER", "NOMINATIONS_BALLOT_CUSTODIAN"]);
        centralRoles.set(secondSubjectId, ["VIEWER", "NOMINATIONS_COMMISSION_MEMBER", "NOMINATIONS_BALLOT_CUSTODIAN"]);
        expect((await request("GET", "/v1/session", clientA)).status).toBe(401);
        expect((await request("GET", "/v1/session", clientD)).status).toBe(401);
        clientA = await login(sourceA);
        clientB = await login(sourceB);
        clientC = await login(sourceC);
        clientD = await login(sourceD, secondSubjectId);
        await enrollDevice(clientA, deviceA, deviceAId);
        await enrollDevice(clientB, deviceB, deviceBId);
        await enrollDevice(clientC, deviceC, deviceCId);
        await enrollDevice(clientD, deviceD, deviceDId);
        const projected = await data("GET", "/v1/access/bindings", clientA);
        expect(projected.items.filter((item) => item.identityId === clientA.identityId).map((item) => item.roleCode).sort())
            .toEqual(["CHURCH_ADMIN", "COMMITTEE_MEMBER", "TALLY_CUSTODIAN"]);
        expect(projected.items.filter((item) => item.identityId === clientD.identityId).map((item) => item.roleCode).sort())
            .toEqual(["COMMITTEE_MEMBER", "TALLY_CUSTODIAN"]);
        expect(projected.identities.find((item) => item.identityId === clientD.identityId)?.gestionChurchManaged).toBe(true);
        const custodianRole = (await data("GET", "/v1/access/roles", clientA)).items.find((item) => item.code === "TALLY_CUSTODIAN");
        const centralBinding = projected.items.find((item) => item.identityId === clientD.identityId && item.roleCode === "TALLY_CUSTODIAN");
        assert.ok(custodianRole && centralBinding);
        for (const [url, payload] of [
            ["/v1/access/bindings", { targetIdentityId: clientD.identityId, roleId: custodianRole.id }],
            ["/v1/access/bindings/revoke", { targetIdentityId: clientD.identityId, roleId: custodianRole.id, expectedVersion: centralBinding.version }],
        ]) {
            const blocked = await request("POST", url, clientA, payload);
            expect(blocked.status).toBe(403);
            expect(blocked.body.error.code).toBe("GESTIONCHURCH_MANAGED_OPERATIONAL_ROLE");
        }
        const key = await contentKey(generationOne.keyBytes);
        const seal = (aad, value) => cryptoClient.encryptJson(key, generationOne.tenantKeyId, { tenantId: names.tenantId, ...aad }, value);
        const secondMemberId = randomUUID();
        const secondMember = await seal({ memberId: secondMemberId, purpose: "member-display", schemaVersion: 1 }, { displayName: "Synthetic second committee member" });
        await data("POST", "/v1/members", clientA, { id: secondMemberId, eligible: true, displayEnvelope: secondMember.envelope, displayContentHash: secondMember.contentHash });
        const catalog = await data("GET", "/v1/catalog", clientA);
        const office = catalog.offices.find((item) => ["church_election", "church_election_after_nominating_report"].includes(item.appointmentMechanism));
        assert.ok(office);
        const cycle = await data("POST", "/v1/cycles", clientA, { name: "Synthetic complete premium cycle", locale: "es", timezone: "America/La_Paz", jurisdiction: "owned-fixture-only", termStart: "2025-01-01", termEnd: "2035-12-31", normativeVersion: catalog.normativeVersion, configuration: {} });
        const cycleId = cycle.id, sessionId = randomUUID();
        const workflow = () => data("GET", `/v1/cycles/${cycleId}/workflow`, clientA);
        const title = await seal({ cycleId, sessionId, purpose: "session-title", schemaVersion: 1, titleVersion: 1 }, { title: "Synthetic institutional session" });
        await data("POST", `/v1/cycles/${cycleId}/sessions`, clientA, { sessionId, expectedCycleVersion: cycle.version, sequence: 1, titleEnvelope: title.envelope, titleContentHash: title.contentHash, startsAt: "2030-10-01T18:00:00-04:00", endsAt: "2030-10-01T20:00:00-04:00" });
        const committee = await Promise.all([[clientA, memberId], [clientD, secondMemberId]].map(async ([client, id], index) => ({ identityId: client.identityId, memberId: id, roleCode: index ? "member" : "chair", votingRight: true, pastoralCapacity: false, displayEnvelope: (await seal({ cycleId, identityId: client.identityId, purpose: "committee-display", schemaVersion: 1 }, { displayName: `Synthetic committee ${index + 1}` })).envelope })));
        await data("PUT", `/v1/cycles/${cycleId}/committee`, clientA, { expectedCycleVersion: (await workflow()).cycle.version, members: committee });
        await data("PUT", `/v1/cycles/${cycleId}/electorate`, clientA, { expectedCycleVersion: (await workflow()).cycle.version, electors: [clientA, clientD].map((client) => ({ identityId: client.identityId, canPropose: true, canVote: true, recused: false })) });
        const configured = await data("POST", `/v1/cycles/${cycleId}/vacancy-processes`, clientA, { expectedCycleVersion: (await workflow()).cycle.version, officeId: office.id, vacancyCount: 1, maxProposalSelections: 1, maxBallotSelections: 1, decisionRule: { kind: "PLURALITY" }, abstentionRule: "EXCLUDED_FROM_CANDIDATE_TOTALS", tiebreakPolicy: "NEW_BALLOT_ROUND", quorumRule: { kind: "ALL_REQUIRED" }, aggregateAudience: "committee", agendaOrder: 1 });
        const processId = configured.processId;
        const processVersion = async () => (await workflow()).processes.find((item) => item.id === processId).version;
        await data("POST", `/v1/cycles/${cycleId}/activate`, clientA, { expectedVersion: (await workflow()).cycle.version });
        await data("POST", `/v1/sessions/${sessionId}/start`, clientA, { expectedVersion: 1 });
        const proposal = await data("POST", `/v1/office-processes/${processId}/proposal-rounds`, clientA, { expectedProcessVersion: await processVersion() });
        const openedProposal = await data("POST", `/v1/proposal-rounds/${proposal.roundId}/open`, clientA, { expectedRoundVersion: proposal.version, expectedProcessVersion: await processVersion() });
        const activeProposal = await data("GET", "/v1/rounds/active", clientA);
        const proposalAad = { tenantId: names.tenantId, cycleId, roundId: proposal.roundId, purpose: "proposal", schemaVersion: 1, roundVersion: openedProposal.version, candidateSetHash: activeProposal.round.candidateSetHash, rulesHash: activeProposal.round.rulesHash };
        for (const client of [clientA, clientD]) {
            const sealed = await seal(proposalAad, { schema: "nombramientos-submission/v1", selections: [memberId], abstain: false });
            const receipt = await data("POST", `/v1/rounds/${proposal.roundId}/submissions`, client, { kind: "proposal", expectedVersion: openedProposal.version, envelope: sealed.envelope, contentHash: sealed.contentHash });
            expect(receipt.status).toBe("received");
        }
        const closedProposal = await data("POST", `/v1/proposal-rounds/${proposal.roundId}/close`, clientA, { expectedRoundVersion: openedProposal.version, expectedProcessVersion: await processVersion(), reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED" });
        await data("POST", `/v1/proposal-rounds/${proposal.roundId}/manifest`, clientA, { expectedRoundVersion: closedProposal.version });
        const proposalManifest = await data("GET", `/v1/proposal-rounds/${proposal.roundId}/manifest`, clientA);
        const aggregateClient = await import(pathToFileURL(path.join(root, "apps/web/lib/workflow-aggregate.ts")).href);
        await aggregateClient.verifyProposalManifest(proposalManifest);
        const submissions = await Promise.all(proposalManifest.entries.map((entry) => cryptoClient.decryptJson(key, entry.envelope, { aad: proposalAad, exactAad: true })));
        const consolidated = await aggregateClient.buildProposalAggregate({ manifest: proposalManifest, submissions, maxProposalSelections: 1 });
        expect(consolidated.aggregate.candidates).toEqual([{ memberId, distinctProponentCount: 2 }]);
        const reviewed = await data("POST", `/v1/proposal-rounds/${proposal.roundId}/aggregate`, clientA, { expectedRoundVersion: closedProposal.version, expectedProcessVersion: await processVersion(), manifestId: proposalManifest.manifestId, manifestHash: proposalManifest.manifestHash, effectiveResponseDenominator: consolidated.aggregate.effectiveResponseDenominator, aggregateHash: consolidated.aggregateHash, candidates: consolidated.aggregate.candidates });
        const candidacyId = reviewed.candidacyIds[0];
        assert.ok(candidacyId);
        await data("POST", `/v1/office-processes/${processId}/candidacies/${candidacyId}/reviews`, clientA, { expectedVersion: 1, toState: "UNDER_REVIEW", reasonCode: "REVIEW_STARTED" });
        await data("POST", `/v1/office-processes/${processId}/candidate-lists`, clientA, { expectedProcessVersion: await processVersion(), orderedCandidacyIds: [candidacyId] });
        const ballot = await data("POST", `/v1/office-processes/${processId}/ballot-rounds`, clientA, { expectedProcessVersion: await processVersion() });
        const custodians = await Promise.all([clientA, clientD].map(async (client, index) => {
            const hpke = await e2ee.generateCustodianKeyPair(`synthetic:${names.runId}:${index}`);
            const signing = await e2ee.generateCustodianSigningKeyPair();
            const hpkePublic = await e2ee.exportCustodianPublicKey(hpke);
            const signingPublic = await e2ee.exportCustodianSigningPublicKey(signing);
            const registered = await data("POST", "/v1/custody/keys", client, { deviceId: randomUUID(), recipientId: hpkePublic.recipientId, expectedVersion: 0, suite: e2ee.HPKE_SUITE, hpkePublicKey: hpkePublic.publicKey, hpkeFingerprint: hpkePublic.fingerprint, signingAlgorithm: "Ed25519", signingPublicKeySpki: signingPublic.publicKeySpki, signingFingerprint: signingPublic.fingerprint });
            return { client, hpke, signing, keyId: registered.keyId };
        }));
        await data("POST", `/v1/rounds/${ballot.roundId}/custody/freeze`, clientA, { expectedRoundVersion: ballot.version, keyIds: custodians.map((item) => item.keyId) });
        const openedBallot = await data("POST", `/v1/ballot-rounds/${ballot.roundId}/open`, clientA, { expectedRoundVersion: ballot.version, expectedProcessVersion: await processVersion() });
        const recipientSet = await data("GET", `/v1/rounds/${ballot.roundId}/custody/recipients`, clientA);
        const recipients = await Promise.all(recipientSet.recipients.map((recipient) => e2ee.importCustodianPublicKey({ format: "nombramientos.hpke-public-key", version: 1, suite: e2ee.HPKE_SUITE, recipientId: recipient.recipientId, fingerprint: recipient.fingerprint, publicKey: recipient.hpkePublicKey })));
        const rules = { candidateIds: [candidacyId], minSelections: 1, maxSelections: 1, allowAbstention: true };
        const ballotAad = await e2ee.createBallotAad({ tenantId: names.tenantId, cycleId, roundId: ballot.roundId, purpose: e2ee.BALLOT_PURPOSE, schemaVersion: e2ee.BALLOT_SCHEMA_VERSION, roundVersion: openedBallot.version }, rules);
        for (const client of [clientA, clientD]) {
            const envelope = await e2ee.sealBallotEnvelope({ payload: { schemaVersion: 1, selections: [candidacyId], abstain: false }, aad: ballotAad, rules, recipients });
            const receipt = await data("POST", `/v1/rounds/${ballot.roundId}/submissions`, client, { kind: "vote", expectedVersion: openedBallot.version, envelope, contentHash: await e2ee.computeBallotContentHash(envelope) });
            expect(receipt.status).toBe("received");
        }
        const closedBallot = await data("POST", `/v1/ballot-rounds/${ballot.roundId}/close`, clientA, { expectedRoundVersion: openedBallot.version, expectedProcessVersion: await processVersion(), reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED" });
        const manifest = await data("POST", `/v1/rounds/${ballot.roundId}/custody/manifest`, clientA, { expectedRoundVersion: closedBallot.version, expectedCustodyVersion: 1 });
        const downloadedManifest = await data("GET", `/v1/rounds/${ballot.roundId}/custody/manifest`, clientA);
        const ballots = await Promise.all(downloadedManifest.entries.map((entry) => e2ee.openBallotEnvelope({ envelope: entry.envelope, recipient: custodians[0].hpke, expectedAad: ballotAad, rules })));
        const tally = e2ee.createTallyAggregate({ ...rules, vacancies: 1, rule: { kind: "PLURALITY" }, ballots });
        const aggregateHash = await e2ee.computeTallyAggregateHash(tally);
        const attestationContext = e2ee.createTallyAttestationContext({ tenantId: names.tenantId, roundId: ballot.roundId, manifestId: manifest.manifestId, manifestHash: manifest.manifestHash, aggregateHash });
        let manifestVersion = manifest.version;
        for (const custodian of custodians) {
            const signature = await e2ee.signTallyAttestation(custodian.signing, attestationContext);
            const attested = await data("POST", `/v1/rounds/${ballot.roundId}/custody/attestations`, custodian.client, { expectedManifestVersion: manifestVersion, aggregate: tally, signature: signature.signature });
            manifestVersion = attested.version;
        }
        const published = await data("POST", `/v1/rounds/${ballot.roundId}/custody/publication`, clientA, { expectedRoundVersion: manifest.roundVersion, expectedManifestVersion: manifestVersion });
        expect(published.aggregate.decision.selectedCandidateIds).toEqual([candidacyId]);
        const provisional = await data("POST", `/v1/office-processes/${processId}/provisional-assignments`, clientA, { roundId: ballot.roundId, expectedProcessVersion: await processVersion(), expectedAggregateHash: aggregateHash, sessionId });
        const assignmentId = provisional.assignments[0].assignmentId;
        const evidence = async (purpose, note) => (await seal({ assignmentId, purpose, schemaVersion: 1 }, { note })).envelope;
        const invalidDirectAcceptance = await request("POST", `/v1/assignments/${assignmentId}/consent`, clientA, { expectedVersion: 1, status: "ACCEPTED", envelope: await evidence("assignment-consent", "Synthetic acceptance"), sessionId });
        expect(invalidDirectAcceptance.status).toBe(409);
        await data("POST", `/v1/assignments/${assignmentId}/consent`, clientA, { expectedVersion: 1, status: "CONTACTED", envelope: await evidence("assignment-consent", "Synthetic contacted"), sessionId });
        await data("POST", `/v1/assignments/${assignmentId}/consent`, clientA, { expectedVersion: 2, status: "ACCEPTED", envelope: await evidence("assignment-consent", "Synthetic accepted"), sessionId });
        await data("POST", `/v1/assignments/${assignmentId}/presentation`, clientA, { expectedVersion: 3, envelope: await evidence("assignment-presentation", "Synthetic presented"), sessionId });
        await data("POST", `/v1/assignments/${assignmentId}/congregational-decision`, clientA, { expectedVersion: 4, outcome: "ELECTED", envelope: await evidence("congregational-decision", "Synthetic elected"), sessionId });
        const active = await data("POST", `/v1/assignments/${assignmentId}/activate`, clientA, { expectedVersion: 5, sessionId });
        expect(active).toMatchObject({ state: "VIGENTE", version: 6 });
        await data("POST", `/v1/sessions/${sessionId}/close`, clientA, { expectedVersion: (await data("GET", `/v1/sessions/${sessionId}`, clientA)).version });
        await data("POST", `/v1/cycles/${cycleId}/close`, clientA, { expectedVersion: (await workflow()).cycle.version });
        expect((await workflow()).cycle.status).toBe("closed");
        const history = await data("GET", `/v1/assignments/${assignmentId}/history`, clientB);
        expect(history.assignment).toMatchObject({ memberId, state: "VIGENTE" });
        expect(await cryptoClient.decryptJson(key, history.assignment.memberSnapshot.displayEnvelope)).toEqual(plaintext);
        const organization = await data("GET", `/v1/organization?cycleId=${cycleId}&stage=elected`, clientA);
        expect(organization.items.map((item) => ({ memberId: item.memberId, state: item.processState }))).toEqual(expect.arrayContaining([{ memberId, state: "VIGENTE" }]));
        const snapshot = await data("GET", `/v1/reports/workflow-snapshot?reportType=cycle_summary&audience=committee&cycleId=${cycleId}`, clientA);
        expect(snapshot.cycle.status).toBe("closed");
        const reportArtifact = await import(pathToFileURL(path.join(root, "apps/web/lib/report-artifact.ts")).href);
        const reportExport = await import(pathToFileURL(path.join(root, "apps/web/lib/report-export.ts")).href);
        const rows = [["Member", plaintext.displayName], ["Office", office.names.es], ["State", history.assignment.state], ["Cycle", snapshot.cycle.status]];
        const snapshotSha256 = await aggregateClient.workflowHash({ reportType: "cycle_summary", audience: "committee", rows });
        const pending = await data("POST", "/v1/reports/generate", clientA, { reportType: "cycle_summary", audience: "committee", locale: "es", format: "csv", filters: { cycleId, snapshotSha256, snapshotAt: new Date().toISOString() } });
        const plaintextReport = await reportExport.buildLocalArtifact(pending, rows, "Synthetic fixture", "Synthetic cycle summary", "Committee", "America/La_Paz");
        try {
            const descriptor = { tenantId: names.tenantId, reportId: pending.id, requestVersion: pending.version, reportType: pending.reportType, audience: pending.audience, locale: pending.locale, format: pending.format, filename: pending.filename, mediaType: pending.mediaType, snapshotSha256 };
            const encrypted = await reportArtifact.encryptReportArtifact({ key, keyId: generationOne.tenantKeyId, descriptor, plaintext: plaintextReport });
            persistedReport = { descriptor, plaintextSha256: sha256(plaintextReport) };
            const ready = await data("POST", `/v1/reports/${pending.id}/complete`, clientA, { expectedVersion: pending.version, envelope: encrypted.envelope, artifactSha256: encrypted.artifactSha256, ciphertextSha256: encrypted.ciphertextSha256, plaintextBytes: encrypted.plaintextBytes, rowCount: rows.length, generatedAt: new Date().toISOString() });
            expect(ready.state).toBe("ready");
            const retrieved = await data("GET", `/v1/reports/${pending.id}/artifact`, clientB);
            const recoveredReport = await reportArtifact.decryptReportArtifact({ key, keyId: generationOne.tenantKeyId, descriptor, artifact: retrieved });
            try { expect(Buffer.from(recoveredReport).equals(Buffer.from(plaintextReport))).toBe(true); expect(new TextDecoder().decode(recoveredReport)).toContain(plaintext.displayName); }
            finally { recoveredReport.fill(0); }
            expect(JSON.stringify(retrieved)).not.toContain(plaintext.displayName);
            await expect(reportArtifact.decryptReportArtifact({ key, keyId: generationOne.tenantKeyId, descriptor: { ...descriptor, tenantId: randomUUID() }, artifact: retrieved })).rejects.toThrow();
        }
        finally { plaintextReport.fill(0); }
        await mutate("grant.revoke", "/v1/key-lifecycle/grants/revoke", { grantId: grantD.grantId, expectedVersion: grantD.version, reasonCode: "DEVICE_RETIRED", confirmLastActiveGrant: false });
    }, 40_000);
    it("revokes B and rotates future content while a fresh C keyring still opens the original historical member", async () => {
        const persistedNonce = await proofFor("GET", "/v1/members?limit=250", clientA);
        expect((await rawRequest("GET", "/v1/members?limit=250", clientA, undefined, undefined, { "x-device-proof": persistedNonce.proof })).status).toBe(200);
        await restartOwnedApi();
        // The long security/cycle fixture starts a fresh API admission window,
        // while an already consumed proof remains rejected durably in SQL.
        expect((await rawRequest("GET", "/v1/members?limit=250", clientA, undefined, undefined, { "x-device-proof": persistedNonce.proof })).status).toBe(401);
        const stream = await openOwnedEventStream(clientB);
        try {
            await mutate("grant.revoke", "/v1/key-lifecycle/grants/revoke", { grantId: grantB.grantId, expectedVersion: grantB.version, reasonCode: "DEVICE_RETIRED", confirmLastActiveGrant: false });
            await expectStreamClosed(stream);
        } finally { stream.controller.abort(); await stream.reader.cancel().catch(() => undefined); }
        const second = e2ee.generateTenantContentKey();
        try {
            const recovery = await e2ee.createEncryptedTenantKeyRecoveryBackup({ tenantId: names.tenantId, tenantKeyId: second.tenantKeyId, generation: 2, tenantKey: second.keyBytes, passphrase });
            await mutate("key.rotate", "/v1/key-lifecycle/rotations", { expectedTenantKeyId: generationOne.tenantKeyId, expectedGeneration: 1, newTenantKeyId: second.tenantKeyId, reasonCode: "DEVICE_ROSTER_CHANGED", recoveryPublicKey: recovery.recoveryPublicKey, grants: await Promise.all([[deviceA, deviceAId], [deviceC, deviceCId]].map(async ([device, id]) => ({ targetIdentityId: clientA.identityId, targetDeviceId: id, envelope: await grantFor(device, id, second, 2) }))) });
            const sealed = await cryptoClient.encryptJson(await contentKey(second.keyBytes), second.tenantKeyId, { tenantId: names.tenantId, memberId: futureMemberId, purpose: "member-display", schemaVersion: 1 }, { displayName: "Synthetic future member", membershipStatus: "active" });
            await data("POST", "/v1/members", clientA, { id: futureMemberId, eligible: true, displayEnvelope: sealed.envelope, displayContentHash: sealed.contentHash });
            const future = await storedMember(clientA, futureMemberId);
            await expect(cryptoClient.decryptJson(await contentKey(generationOne.keyBytes), future)).rejects.toThrow();
            // Device B's cookie can no longer borrow A/C's active grants. Its
            // exact HTTP sessions are invalidated as part of revocation.
            expect((await request("GET", "/v1/session", clientB)).status).toBe(401);
            expect((await request("PATCH", `/v1/members/${futureMemberId}`, clientB, { expectedVersion: 1, displayEnvelope: sealed.envelope, displayContentHash: sealed.contentHash })).status).toBe(401);
            expect((await request("GET", "/v1/members?limit=250", clientB)).status).toBe(401);
            expect((await request("GET", "/v1/members?limit=250", clientA)).status).toBe(200);
            expect((await request("GET", "/v1/members?limit=250", clientC)).status).toBe(200);
            const state = await data("GET", "/v1/key-lifecycle", clientA);
            const revoked = await tenant.query("SELECT status FROM e2ee_key_grants WHERE id=$1", [grantB.grantId]);
            expect(revoked.rows[0]?.status).toBe("revoked");
            const historical = state.ownGrants.find((item) => item.deviceId === deviceCId && item.status === "retired");
            assert.ok(historical);
            const opened = await openGrant(historical.envelope, deviceC, deviceCId);
            try {
                expect(await cryptoClient.decryptJson(await contentKey(opened.keyBytes), await storedMember(clientA))).toEqual(plaintext);
            }
            finally {
                opened.keyBytes.fill(0);
            }
            // Honest boundary: revocation cannot erase an already extracted prior key.
            expect(await cryptoClient.decryptJson(await contentKey(generationOne.keyBytes), historicalEnvelope)).toEqual(plaintext);
        }
        finally {
            second.keyBytes.fill(0);
        }
    }, 20_000);
    it("restores actual encrypted database backups into empty owned databases and opens the same historical member and opaque CSV", async () => {
        const restoreNames = deriveEphemeralNames(randomUUID(), randomUUID());
        assertEphemeralNames(restoreNames);
        const localRoot = path.join(root, "packages/database/.local");
        const scratch = await mkdtemp(path.join(localRoot, "premium-backup-"));
        let restoredControl, restoredTenant;
        const created = [];
        const backupKey = randomBytes(32);
        try {
            if (process.platform === "win32") {
                const identity = execFileSync("whoami.exe", ["/user", "/fo", "csv", "/nh"], { encoding: "utf8", windowsHide: true });
                const sid = identity.match(/S-1-\d+(?:-\d+)+/u)?.[0]; assert.ok(sid);
                execFileSync("icacls.exe", [scratch, "/inheritance:r", "/grant:r", `*${sid}:(OI)(CI)F`], { stdio: "pipe", windowsHide: true });
            }
            const credentials = new URL(adminUrl);
            const toolSuffix = process.platform === "win32" ? ".exe" : "";
            const pgDumpVersion = execFileSync(path.join(postgresBin, `pg_dump${toolSuffix}`), ["--version"], { encoding: "utf8", windowsHide: true }).trim();
            const pgRestoreVersion = execFileSync(path.join(postgresBin, `pg_restore${toolSuffix}`), ["--version"], { encoding: "utf8", windowsHide: true }).trim();
            assert.match(pgDumpVersion, /^pg_dump \(PostgreSQL\) 18\./u);
            assert.match(pgRestoreVersion, /^pg_restore \(PostgreSQL\) 18\./u);
            async function pgTool(tool, args) {
                await new Promise((resolve, reject) => {
                    const child = spawn(path.join(postgresBin, `${tool}${process.platform === "win32" ? ".exe" : ""}`), ["--host", credentials.hostname, "--port", credentials.port, "--username", decodeURIComponent(credentials.username), ...args], { windowsHide: true, shell: false, env: { ...process.env, PGPASSWORD: decodeURIComponent(credentials.password), PGCONNECT_TIMEOUT: "5" }, stdio: ["ignore", "ignore", "pipe"] });
                    child.stderr.resume();
                    child.once("error", () => reject(new Error(`${tool} fixture tool unavailable`)));
                    child.once("close", (code) => code === 0 ? resolve() : reject(new Error(`${tool} fixture failed with exit ${code}`)));
                });
            }
            async function controlDigest(pool) {
                const tables = await pool.query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename");
                const summary = [];
                for (const { tablename } of tables.rows) {
                    assert.match(tablename, /^[a-z][a-z0-9_]{0,62}$/u);
                    const rows = await pool.query(`SELECT to_jsonb(source)::text value FROM public."${tablename}" source ORDER BY to_jsonb(source)::text`);
                    summary.push({ table: tablename, rows: rows.rowCount, digest: sha256(canonicalJson(rows.rows.map((row) => row.value))) });
                }
                return summary;
            }
            const beforeControl = await controlDigest(control);
            const controlDump = path.join(scratch, "control.dump"), tenantDump = path.join(scratch, "tenant.dump");
            await pgTool("pg_dump", ["--dbname", names.controlDatabase, "--format=custom", "--no-owner", "--no-privileges", "--lock-wait-timeout=5000", "--file", controlDump]);
            const client = await tenant.connect();
            let invariant, point;
            try {
                await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
                point = (await client.query("SELECT pg_export_snapshot() snapshot_id,clock_timestamp() captured_at,current_setting('server_version') server_version")).rows[0];
                invariant = await captureTenantInvariant(client);
                await pgTool("pg_dump", ["--dbname", names.tenantDatabase, "--format=custom", "--no-owner", "--no-privileges", "--lock-wait-timeout=5000", "--snapshot", point.snapshot_id, "--file", tenantDump]);
                await client.query("COMMIT");
            } catch (error) { await client.query("ROLLBACK"); throw error; }
            finally { client.release(); }
            const dump = await hashFile(tenantDump);
            const core = { backupId: randomUUID(), tenantId: names.tenantId, tenantKind: "real", sourceDatabase: names.tenantDatabase, credentialVersion: 1, runtimeSecretReference: `tenant-db/${names.tenantId}/runtime/v1`, recoveryPointAt: point.captured_at.toISOString(), backupCompletedAt: new Date().toISOString(), postgresServerVersion: point.server_version, pgDumpVersion, encryptionKeyId: randomUUID(), invariant, invariantSha256: sha256(canonicalJson(invariant)), dump: { format: "pg_dump-custom", ...dump } };
            const encryptedPath = path.join(scratch, "database.dump.aesgcm");
            const encryption = await encryptBackupPayload(tenantDump, encryptedPath, backupKey, core);
            const manifest = verifyBackupManifest({ format: "nombramientos-tenant-backup", version: 1, core, encryption: { algorithm: "AES-256-GCM", ...encryption }, payload: { file: "database.dump.aesgcm", ...await hashFile(encryptedPath) } });
            await expect(decryptBackupPayload(encryptedPath, path.join(scratch, "wrong.dump"), randomBytes(32), manifest)).rejects.toThrow();
            expect(() => verifyBackupManifest({ ...manifest, core: { ...core, credentialVersion: 2 } })).toThrow();
            const decryptedPath = path.join(scratch, "restored-tenant.dump");
            await decryptBackupPayload(encryptedPath, decryptedPath, backupKey, manifest);
            expect(await hashFile(decryptedPath)).toEqual(dump);
            const controlBytes = await readFile(controlDump);
            const controlEnvelope = await cryptoClient.encryptJson(await contentKey(backupKey), core.encryptionKeyId, { purpose: "synthetic-control-backup", sourceDatabase: names.controlDatabase, runId: names.runId }, { format: "pg_dump-custom", bytes: controlBytes.toString("base64url"), sha256: sha256(controlBytes) });
            const controlRecovered = await cryptoClient.decryptJson(await contentKey(backupKey), controlEnvelope.envelope, { aad: { purpose: "synthetic-control-backup", sourceDatabase: names.controlDatabase, runId: names.runId }, exactAad: true });
            const restoredBytes = Buffer.from(controlRecovered.bytes, "base64url");
            expect(sha256(restoredBytes) === sha256(controlBytes)).toBe(true);
            const restoredControlDump = path.join(scratch, "restored-control.dump");
            await writeFile(restoredControlDump, restoredBytes, { flag: "wx", mode: 0o600 });
            controlBytes.fill(0); restoredBytes.fill(0);
            const absent = await cluster.query("SELECT 1 FROM pg_database WHERE datname=ANY($1::text[])", [[restoreNames.controlDatabase, restoreNames.tenantDatabase]]);
            expect(absent.rowCount).toBe(0);
            for (const target of [restoreNames.controlDatabase, restoreNames.tenantDatabase]) {
                await formatted("SELECT format('CREATE DATABASE %I TEMPLATE template0', $1::text) sql", [target]); created.push(target);
            }
            await pgTool("pg_restore", ["--dbname", restoreNames.controlDatabase, "--no-owner", "--no-privileges", "--exit-on-error", restoredControlDump]);
            await pgTool("pg_restore", ["--dbname", restoreNames.tenantDatabase, "--no-owner", "--no-privileges", "--exit-on-error", decryptedPath]);
            restoredControl = new Pool(poolConfig(restoreNames.controlDatabase)); restoredTenant = new Pool(poolConfig(restoreNames.tenantDatabase));
            expect(await controlDigest(restoredControl)).toEqual(beforeControl);
            const restoredClient = await restoredTenant.connect();
            try {
                await restoredClient.query("BEGIN READ ONLY");
                expect(compareTenantInvariants(invariant, await captureTenantInvariant(restoredClient))).toEqual([]);
                await restoredClient.query("COMMIT");
            } finally { restoredClient.release(); }
            const restoredMember = await restoredTenant.query("SELECT display_envelope FROM members WHERE id=$1", [memberId]);
            expect(restoredMember.rows[0].display_envelope).toEqual(historicalEnvelope);
            const historicalGrant = await restoredTenant.query("SELECT key_grant.envelope FROM e2ee_key_grants key_grant JOIN e2ee_key_generations generation ON generation.id=key_grant.generation_id WHERE key_grant.device_id=$1 AND generation.tenant_key_id=$2 AND key_grant.status='retired'", [deviceCId, generationOne.tenantKeyId]);
            expect(historicalGrant.rowCount).toBe(1);
            const historicalKey = await openGrant(historicalGrant.rows[0].envelope, deviceC, deviceCId);
            const offlineRecovery = await e2ee.openEncryptedTenantKeyRecoveryBackup(backup.backup, passphrase);
            try {
                const key = await contentKey(offlineRecovery.tenantKey);
                expect(await cryptoClient.decryptJson(key, restoredMember.rows[0].display_envelope)).toEqual(plaintext);
                expect(await cryptoClient.decryptJson(await contentKey(historicalKey.keyBytes), restoredMember.rows[0].display_envelope)).toEqual(plaintext);
                const report = await restoredTenant.query("SELECT artifact_envelope,artifact_sha256,ciphertext_sha256,plaintext_bytes FROM report_versions WHERE id=$1 AND state='ready'", [persistedReport.descriptor.reportId]);
                expect(report.rowCount).toBe(1);
                const row = report.rows[0];
                const reportArtifact = await import(pathToFileURL(path.join(root, "apps/web/lib/report-artifact.ts")).href);
                const bytes = await reportArtifact.decryptReportArtifact({ key, keyId: generationOne.tenantKeyId, descriptor: persistedReport.descriptor, artifact: { envelope: row.artifact_envelope, artifactSha256: row.artifact_sha256, ciphertextSha256: row.ciphertext_sha256, plaintextBytes: Number(row.plaintext_bytes), ciphertextBytes: Number(row.plaintext_bytes) + 16 } });
                try { expect(sha256(bytes) === persistedReport.plaintextSha256).toBe(true); } finally { bytes.fill(0); }
            } finally { historicalKey.keyBytes.fill(0); offlineRecovery.tenantKey.fill(0); }
            const restoredStore = new ControlPlaneStore(restoredControl);
            expect(await restoredStore.getGestionChurchSessionBinding(clientA.sessionId, clientA.identityId, names.tenantId)).toBe(sourceA);
            expect(await restoredStore.getGestionChurchSessionBinding(clientB.sessionId, clientB.identityId, names.tenantId)).toBeNull();
            const restoredApp = { apiConfig: app.apiConfig, database: { control: restoredStore } };
            activeSources.delete(sourceB);
            await expect(requireCurrentGestionChurchAccess(restoredApp, { identityId: clientB.identityId, sessionId: clientB.sessionId, activeTenantId: names.tenantId, authMethod: "federated" })).rejects.toMatchObject({ statusCode: 401 });
            await expect(requireCurrentGestionChurchAccess(restoredApp, { identityId: clientA.identityId, sessionId: clientA.sessionId, activeTenantId: names.tenantId, authMethod: "federated" })).resolves.toBeUndefined();
            const restoredSession = await restoredControl.query("SELECT revoked_at IS NOT NULL revoked FROM auth_sessions WHERE id=$1", [clientB.sessionId]);
            expect(restoredSession.rows[0].revoked).toBe(true);
            const revokedGrant = await restoredTenant.query("SELECT status FROM e2ee_key_grants WHERE id=$1", [grantB.grantId]);
            expect(revokedGrant.rows[0].status).toBe("revoked");
            // No guard is relaxed to route HTTP through a differently named
            // scratch restore. New-device recovery of a retired generation
            // remains an explicit protocol/ceremony gap, not a restore claim.
        } finally {
            activeSources.add(sourceB); backupKey.fill(0);
            for (const pool of [restoredTenant, restoredControl]) await pool?.end();
            assertEphemeralNames(restoreNames);
            expect((await cluster.query("SELECT 1 FROM pg_stat_activity WHERE datname=ANY($1::text[])", [created])).rowCount).toBe(0);
            for (const target of created) {
                // Targets were absent and created above; no protected-name adoption.
                assert.ok([restoreNames.controlDatabase, restoreNames.tenantDatabase].includes(target));
                await formatted("SELECT format('DROP DATABASE %I',$1::text) sql", [target]);
            }
            expect((await cluster.query("SELECT 1 FROM pg_database WHERE datname=ANY($1::text[])", [created])).rowCount).toBe(0);
            assert.equal(path.dirname(path.resolve(scratch)), localRoot);
            assert.ok(path.basename(scratch).startsWith("premium-backup-"));
            await rm(scratch, { recursive: true, force: true });
        }
    }, 45_000);
    it("source logout revokes B only, and role changes fail closed for A", async () => {
        const missingWithPrivateQuery = await rawRequest("GET", "/v1/members?limit=250&privateDiagnostic=fixture-private-email@invalid.example", clientA);
        expect(missingWithPrivateQuery.status).toBe(401);
        expect(missingWithPrivateQuery.body.error.code).toBe("DEVICE_PROOF_REQUIRED");
        const visibleDenials = new Map();
        let beforeSequence;
        for (let page = 0; page < 20; page += 1) {
            const audit = await data("GET", `/v1/audit?limit=200${beforeSequence ? `&beforeSequence=${beforeSequence}` : ""}`, clientA);
            expect(audit.verified).toBe(true);
            for (const event of audit.items) if (event.action === "e2ee.http_session.denied") visibleDenials.set(event.id, event);
            if (audit.items.length < 200) break;
            beforeSequence = audit.items.at(-1).sequence;
        }
        expect(denialReceipts.length).toBeGreaterThan(20);
        for (const receipt of denialReceipts) {
            expect(visibleDenials.get(receipt.id)).toMatchObject({ requestId: receipt.requestId, result: "denied", metadata: { code: receipt.code } });
        }
        console.info(JSON.stringify({ fixture: marker, phase: "tenant-denial-audit-verified", deniedRequestsVerified: denialReceipts.length, tenantApiVisible: true, hashChainVerified: true, secretFreeMetadata: true }));
        activeSources.delete(sourceB);
        expect((await request("GET", "/v1/session", clientB)).status).toBe(401);
        expect((await request("GET", "/v1/session", clientA)).status).toBe(200);
        centralRoles.set(secondSubjectId, ["VIEWER", "NOMINATIONS_COMMISSION_MEMBER"]);
        expect((await request("GET", "/v1/session", clientD)).status).toBe(401);
        clientD = await login(sourceD, secondSubjectId);
        // This new SSO session is deliberately not enrolled because its old
        // device was explicitly retired. No operational route may use an
        // unbound cookie, regardless of its centrally projected role.
        expect((await request("POST", "/v1/custody/keys", clientD, {})).status).toBe(428);
        const bindings = await tenant.query("SELECT role.code FROM role_bindings binding JOIN roles role ON role.id=binding.role_id WHERE binding.identity_id=$1 ORDER BY role.code", [clientD.identityId]);
        expect(bindings.rows.map((item) => item.code)).toEqual(["COMMITTEE_MEMBER"]);
        centralRoles.set(subjectId, ["AUDITOR"]);
        expect((await request("GET", "/v1/session", clientA)).status).toBe(401);
        const sessions = await control.query("SELECT revoked_at IS NOT NULL revoked FROM auth_sessions WHERE id=ANY($1::uuid[])", [[clientA.sessionId, clientB.sessionId]]);
        expect(sessions.rows.every((item) => item.revoked)).toBe(true);
        generationOne.keyBytes.fill(0);
    });
});
