/**
 * Raised when a record, run or bundle fails verification.
 *
 * @remarks
 * `check` names the failed step (for example `schema`, `chain`, `signature`, `trust`) and is meant
 * for programmatic handling. `runId` and `seq` locate the record when the failure belongs to one.
 */
export class VerificationError extends Error {
  /**
   * @param check - Name of the failed step.
   * @param message - Human-readable detail.
   * @param runId - Run the failure belongs to, if any.
   * @param seq - Sequence number of the failing record, if any.
   */
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
