# @sealedrun/web

Next.js inspector for SealedRun bundles. Verification runs entirely in the browser with `@sealedrun/core`;
the recorder API is used only to list stored runs and to store a bundle on request.

```bash
pnpm --filter @sealedrun/web dev     # http://localhost:3000, proxies /api to SEALEDRUN_API_ORIGIN (default :8080)
pnpm --filter @sealedrun/web build   # static export to apps/web/out, served by sealedrun-recorder
```
