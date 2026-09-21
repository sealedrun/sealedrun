import type { Metadata } from "next";
import type { ReactNode } from "react";

import "./globals.css";

/** Title and description of the single Inspector page. */
export const metadata: Metadata = {
  title: "SealedRun Inspector",
  description: "Verify and inspect SealedRun Record bundles",
};

/** Root HTML shell. Loads the global stylesheet and fonts. */
export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
