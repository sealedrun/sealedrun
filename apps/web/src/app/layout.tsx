import type { Metadata } from "next";
import type { ReactNode } from "react";

import "./globals.css";

/** Title and description of the single Inspector page. */
export const metadata: Metadata = {
  metadataBase: new URL("https://inspector.sealedrun.com"),
  title: "SealedRun Inspector",
  description: "Verify and inspect SealedRun Record bundles",
  openGraph: {
    type: "website",
    siteName: "SealedRun Inspector",
    url: "https://inspector.sealedrun.com",
  },
};

/** Applies the saved theme (dark by default) before first paint so the page never flashes. */
const themeScript = `(function(){try{var t=localStorage.getItem("sealedrun-theme");if(t!=="light"&&t!=="dark"){t="dark"}document.documentElement.dataset.theme=t}catch(e){document.documentElement.dataset.theme="dark"}})();`;

/** Root HTML shell. Loads the global stylesheet, fonts and the theme attribute. */
export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
