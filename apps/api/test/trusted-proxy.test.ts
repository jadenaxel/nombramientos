import rateLimit from "@fastify/rate-limit";
import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import { fastifyTrustProxy } from "../src/server.js";

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

describe("trusted reverse-proxy request IP resolution", () => {
  it("ignores X-Forwarded-For by default, including for a direct loopback caller", async () => {
    const app = requestIpApp(undefined);
    const response = await app.inject({
      method: "GET",
      url: "/request-ip",
      remoteAddress: "127.0.0.1",
      headers: { "x-forwarded-for": "198.51.100.40" },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ip: "127.0.0.1" });
  });

  it("ignores a spoofed forwarding chain from an untrusted socket peer", async () => {
    const app = requestIpApp(["127.0.0.1/32", "10.0.0.0/8"]);
    const response = await app.inject({
      method: "GET",
      url: "/request-ip",
      remoteAddress: "203.0.113.90",
      headers: { "x-forwarded-for": "198.51.100.40, 10.12.0.8" },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ip: "203.0.113.90", ips: ["203.0.113.90"] });
  });

  it("walks a trusted proxy chain right-to-left and selects the first untrusted client", async () => {
    const app = requestIpApp(["127.0.0.1/32", "10.0.0.0/8"]);
    const response = await app.inject({
      method: "GET",
      url: "/request-ip",
      remoteAddress: "127.0.0.1",
      headers: { "x-forwarded-for": "198.51.100.40, 10.12.0.8" },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      ip: "198.51.100.40",
      ips: ["127.0.0.1", "10.12.0.8", "198.51.100.40"],
    });
  });

  it("does not let an untrusted caller evade IP rate limiting by rotating X-Forwarded-For", async () => {
    const app = await rateLimitedApp(["127.0.0.1/32"]);
    const first = await app.inject({
      method: "GET",
      url: "/limited",
      remoteAddress: "203.0.113.90",
      headers: { "x-forwarded-for": "198.51.100.40" },
    });
    const spoofed = await app.inject({
      method: "GET",
      url: "/limited",
      remoteAddress: "203.0.113.90",
      headers: { "x-forwarded-for": "198.51.100.41" },
    });

    expect(first.statusCode).toBe(200);
    expect(spoofed.statusCode).toBe(429);
  });

  it("rate-limits distinct clients independently behind the configured proxy", async () => {
    const app = await rateLimitedApp(["127.0.0.1/32"]);
    const firstClient = await app.inject({
      method: "GET",
      url: "/limited",
      remoteAddress: "127.0.0.1",
      headers: { "x-forwarded-for": "198.51.100.40" },
    });
    const secondClient = await app.inject({
      method: "GET",
      url: "/limited",
      remoteAddress: "127.0.0.1",
      headers: { "x-forwarded-for": "198.51.100.41" },
    });

    expect(firstClient.statusCode).toBe(200);
    expect(secondClient.statusCode).toBe(200);
  });
});

function requestIpApp(trustedProxyCidrs: readonly string[] | undefined): FastifyInstance {
  const app = Fastify({
    logger: false,
    trustProxy: fastifyTrustProxy(trustedProxyCidrs === undefined ? {} : { trustedProxyCidrs }),
  });
  apps.push(app);
  app.get("/request-ip", async (request) => ({
    ip: request.ip,
    ...(request.ips === undefined ? {} : { ips: request.ips }),
  }));
  return app;
}

async function rateLimitedApp(trustedProxyCidrs: readonly string[]): Promise<FastifyInstance> {
  const app = Fastify({
    logger: false,
    trustProxy: fastifyTrustProxy({ trustedProxyCidrs }),
  });
  apps.push(app);
  await app.register(rateLimit, {
    global: true,
    max: 1,
    timeWindow: "1 minute",
    keyGenerator: (request) => request.ip,
  });
  app.get("/limited", async () => ({ ok: true }));
  return app;
}
