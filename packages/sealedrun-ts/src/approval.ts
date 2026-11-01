import type { Finding } from "./scope.js";
import type { SealedRunRecord } from "./types.js";

const APPROVAL_EXTENSION = "sealedrun.approval";

/**
 * Tracks the `human_approval` records of one run and matches executed steps to them (SPEC 6.6).
 *
 * @remarks
 * Feed records in seq order through {@link Approvals.findings}. A granted or denied answer is
 * matched, by `payload.request_hash`, to the first later executed step that hashes the same
 * request; one answer covers one step. A `human_approval` without `sealedrun.approval` (written
 * before SPEC 6.6) matches nothing.
 */
export class Approvals {
  private readonly open = new Map<string, { seq: number; decision: string }[]>();

  /** Returns the approval findings of one record. */
  findings(record: SealedRunRecord): Finding[] {
    const { seq, record_id: recordId } = record;
    const requestHash = record.payload?.request_hash;
    if (record.kind === "human_approval") {
      const answer = record.extensions?.[APPROVAL_EXTENSION];
      if (answer && typeof answer === "object" && requestHash) {
        const list = this.open.get(requestHash) ?? [];
        list.push({ seq, decision: (answer as { decision: string }).decision });
        this.open.set(requestHash, list);
      }
      return [];
    }
    if (record.policy?.decision !== "require_approval" || record.outcome === "blocked") return [];
    const answer = requestHash ? this.open.get(requestHash)?.pop() : undefined;
    if (!answer) {
      return [
        {
          check: "approval.missing",
          seq,
          recordId,
          reason: "step required approval but no human_approval for its request precedes it",
        },
      ];
    }
    if (answer.decision === "denied") {
      return [
        {
          check: "approval.denied_but_executed",
          seq,
          recordId,
          reason: `human denied this request at seq ${answer.seq} and the step ran anyway`,
        },
      ];
    }
    return [];
  }
}
