import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { NextRequest } from "next/server.js";

import { canonicalLocalRedirect, proxy } from "../proxy.ts";

const nextConfigSource = readFileSync(new URL("../next.config.ts", import.meta.url), "utf8");

test("keeps canonical cross-authority redirects absolute in the production proxy adapter", () => {
  assert.match(nextConfigSource, /skipProxyUrlNormalize:\s*true/u);
});

test("redirects operational IPv4 loopback requests to the fixed canonical localhost origin", () => {
  const request = new NextRequest("http://attacker.invalid/es/auth/sign-in?next=%2Fes%2Fapp", {
    method: "POST",
    headers: {
      host: "127.0.0.1:3000",
      "x-forwarded-host": "redirect.attacker.invalid:8443",
      "x-forwarded-proto": "https",
    },
  });

  const response = proxy(request);
  assert.equal(response.status, 307);
  assert.equal(response.headers.get("location"), "http://localhost:3000/es/auth/sign-in?next=%2Fes%2Fapp");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("set-cookie"), null);
});

test("redirects the operational IPv6 loopback authority without reflecting it", () => {
  const request = new NextRequest("http://[::1]:3000/fr/auth/accept-invitation?token=opaque", {
    headers: { host: "[::1]:3000" },
  });

  const response = proxy(request);
  assert.equal(response.status, 307);
  assert.equal(response.headers.get("location"), "http://localhost:3000/fr/auth/accept-invitation?token=opaque");
  assert.equal(response.headers.get("set-cookie"), null);
});

test("does not let forwarding headers select or trigger a redirect destination", () => {
  const request = new NextRequest("http://example.invalid/es/auth/sign-in", {
    headers: {
      host: "example.invalid",
      "x-forwarded-host": "127.0.0.1:3000",
      "x-forwarded-proto": "http",
    },
  });

  assert.equal(canonicalLocalRedirect(request), undefined);
});

test("canonicalizes known container ports but leaves canonical and ephemeral QA origins unchanged", () => {
  const containerResponse = proxy(new NextRequest("http://127.0.0.1:3301/es/auth/sign-in?qa=container", {
    headers: { host: "127.0.0.1:3301" },
  }));
  assert.equal(containerResponse.status, 307);
  assert.equal(containerResponse.headers.get("location"), "http://localhost:3301/es/auth/sign-in?qa=container");

  for (const [url, host] of [
    ["http://localhost:3000/es/auth/sign-in", "localhost:3000"],
    ["http://127.0.0.1:49152/es/auth/sign-in", "127.0.0.1:49152"],
    ["http://127.0.0.1:3000/healthz", "127.0.0.1:3000"],
  ] as const) {
    assert.equal(canonicalLocalRedirect(new NextRequest(url, { headers: { host } })), undefined, url);
  }
});

test("canonical responses advertise only the canonical browser API fallback", () => {
  const previous = process.env["NEXT_PUBLIC_API_URL"];
  delete process.env["NEXT_PUBLIC_API_URL"];
  try {
    const response = proxy(new NextRequest("http://localhost:3000/es/auth/sign-in", {
      headers: { host: "localhost:3000" },
    }));
    const csp = response.headers.get("content-security-policy") ?? "";
    assert.match(csp, /connect-src 'self' http:\/\/localhost:4000 ws:\/\/localhost:3000/u);
    assert.doesNotMatch(csp, /127\.0\.0\.1/u);
  } finally {
    if (previous === undefined) delete process.env["NEXT_PUBLIC_API_URL"];
    else process.env["NEXT_PUBLIC_API_URL"] = previous;
  }
});
