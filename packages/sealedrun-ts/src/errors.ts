export class VerificationError extends Error {
  constructor(
    public readonly check: string,
    message: string,
    public readonly runId?: string,
    public readonly seq?: number,
  ) {
    super(`${check}:${runId ? ` run=${runId} seq=${seq}` : ""} ${message}`);
    this.name = "VerificationError";
  }
}
