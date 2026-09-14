import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const nextConfig: NextConfig = {
  output: "standalone",
  // Next's proxy adapter otherwise rewrites an absolute localhost redirect to
  // a path-only Location when its internal request URL already uses localhost.
  // A browser which actually arrived through 127.0.0.1 would then redirect to
  // itself forever and remain outside the canonical WebAuthn origin.
  skipProxyUrlNormalize: true,
  poweredByHeader: false,
  reactStrictMode: true,
  transpilePackages: ["@nombramientos/i18n", "@nombramientos/catalog"],
  turbopack: { root: repositoryRoot },
  async headers() {
    return [{
      source: "/:path*",
      headers: [
        { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
        { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-create=(self), publickey-credentials-get=(self)" },
        { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "X-Frame-Options", value: "DENY" },
      ],
    }];
  },
};

const withNextIntl = createNextIntlPlugin("./i18n/request.ts");

export default withNextIntl(nextConfig);
