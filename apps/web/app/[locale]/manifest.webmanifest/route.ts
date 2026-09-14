import {
  buildPwaManifest,
  isPwaManifestLocale,
  PWA_MANIFEST_CONTENT_TYPE,
} from "../../../lib/pwa-manifest.ts";

interface ManifestRouteContext {
  readonly params: Promise<{ locale: string }>;
}

export async function GET(_request: Request, { params }: ManifestRouteContext): Promise<Response> {
  const { locale } = await params;
  if (!isPwaManifestLocale(locale)) return new Response(null, { status: 404 });

  return new Response(JSON.stringify(buildPwaManifest(locale)), {
    headers: {
      "cache-control": "public, max-age=3600, stale-while-revalidate=86400",
      "content-type": PWA_MANIFEST_CONTENT_TYPE,
    },
  });
}
