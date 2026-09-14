import assert from "node:assert/strict";
import test from "node:test";

import { GET } from "../app/healthz/route.ts";

test("web health is a cacheless cookie-free loopback probe", async () => {
  const response = GET();
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("set-cookie"), null);
  assert.deepEqual(await response.json(), { status: "ok" });
});
