import type { MetadataRoute } from "next";

export const dynamic = "force-static";

/** Web app manifest with the SealedRun icons. */
export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "SealedRun Inspector",
    short_name: "Inspector",
    description: "Verify and inspect SealedRun Record bundles",
    start_url: "/",
    display: "standalone",
    background_color: "#05070c",
    theme_color: "#05070c",
    icons: [
      { src: "/icon-192.png", sizes: "192x192", type: "image/png" },
      { src: "/icon-512.png", sizes: "512x512", type: "image/png" },
      { src: "/icon-maskable-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
    ],
  };
}
