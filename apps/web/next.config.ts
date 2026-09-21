import type { NextConfig } from "next";

const apiOrigin = process.env.SEALEDRUN_API_ORIGIN ?? "http://localhost:8080";

const config: NextConfig = {
  output: "export",
  agentRules: false,
  trailingSlash: true,
  reactStrictMode: true,
  async rewrites() {
    if (process.env.NODE_ENV !== "development") return [];
    return [{ source: "/api/:path*", destination: `${apiOrigin}/api/:path*` }];
  },
};

export default config;
