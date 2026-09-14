import type { MetadataRoute } from "next";

import { buildPwaManifest } from "../lib/pwa-manifest.ts";

export default function manifest(): MetadataRoute.Manifest {
  return buildPwaManifest("es");
}
