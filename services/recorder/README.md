# sealedrun-recorder

FastAPI service that stores verified SealedRun bundles and serves the web inspector.

```bash
uv run sealedrun-recorder            # http://localhost:8080
```

Environment (prefix `SEALEDRUN_`): `DATA_DIR` (default `data/`), `DATABASE_URL` (default SQLite in
`DATA_DIR`), `UI_DIR` (default `apps/web/out`), `PORT`, `MAX_BUNDLE_BYTES`.

| Method | Path                                | Purpose                                             |
| ------ | ----------------------------------- | --------------------------------------------------- |
| GET    | `/api/health`                       | Liveness                                            |
| POST   | `/api/bundles`                      | Upload a bundle; verified before import, 422 if not |
| POST   | `/api/verify`                       | Verify without storing                              |
| GET    | `/api/bundles`, `/api/bundles/{id}` | Imported bundles, manifest and report               |
| GET    | `/api/bundles/{id}/archive`         | Download the original zip                           |
| GET    | `/api/runs`, `/api/runs/{id}`       | Runs                                                |
| GET    | `/api/runs/{id}/records`            | Records of a run in seq order                       |
| GET    | `/api/records/{id}`                 | One record                                          |
| GET    | `/api/records/{id}/payload/{side}`  | Stored request or response body                     |
