import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import "./globals.css";
import "./responsive.css";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "Nombramientos",
  robots: { index: false, follow: false },
  icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
  colorScheme: "light",
  themeColor: "#081b2c",
};

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const requestHeaders = await headers();
  const candidate = requestHeaders.get("x-nombramientos-locale");
  const locale = candidate === "en" || candidate === "fr" ? candidate : "es";
  return (
    <html lang={locale}>
      <body><Providers>{children}</Providers></body>
    </html>
  );
}
