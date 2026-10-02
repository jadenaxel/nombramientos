import { afterEach, describe, expect, it, vi } from "vitest";
import { logGestionChurchUpstreamRejection } from "../src/modules/gestionchurch-upstream-diagnostics.js";

afterEach(() => vi.useRealTimers());

describe("minimized GestionChurch upstream rejection diagnostics", () => {
  it.each(["authorize", "redeem", "organization"] as const)("logs only enumerated %s, numeric status and server observation time", (operation) => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-02T15:26:00.000Z"));
    const logger = { warn: vi.fn() };
    logGestionChurchUpstreamRejection(logger, operation, 429);
    expect(logger.warn).toHaveBeenCalledExactlyOnceWith({
      event: "gestionchurch.upstream_rejected", operation, upstreamStatus: 429,
      observedAt: "2026-10-02T15:26:00.000Z",
    }, "GestionChurch upstream request rejected");
    const record = logger.warn.mock.calls[0]![0] as Record<string, unknown>;
    expect(Object.keys(record).sort()).toEqual(["event", "observedAt", "operation", "upstreamStatus"]);
    for (const unsafe of ["body", "headers", "url", "query", "code", "secret", "token", "sourceSessionId"]) expect(record).not.toHaveProperty(unsafe);
  });
  it.each([200, 302, 399, 600, 429.1, Number.NaN])("does not emit non-error or invalid status %s", (status) => {
    const logger = { warn: vi.fn() };
    logGestionChurchUpstreamRejection(logger, "redeem", status);
    expect(logger.warn).not.toHaveBeenCalled();
  });
  it("does not let a diagnostic logger failure replace a fail-closed rejection", () => {
    expect(() => logGestionChurchUpstreamRejection({ warn: () => { throw new Error("synthetic logger failure"); } }, "authorize", 503)).not.toThrow();
    expect(() => logGestionChurchUpstreamRejection(undefined, "authorize", 503)).not.toThrow();
  });
});
