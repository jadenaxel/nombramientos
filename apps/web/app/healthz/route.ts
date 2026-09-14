const HEALTH_HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
} as const;

export function GET(): Response {
  return Response.json({ status: "ok" }, { headers: HEALTH_HEADERS });
}
