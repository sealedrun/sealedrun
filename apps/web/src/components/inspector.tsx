"use client";

import type { SealedRunRecord } from "@sealedrun/core";
import { useCallback, useEffect, useMemo, useState } from "react";

import { api, type RunSummary } from "@/lib/api";
import { type LocalVerification, verifyLocally } from "@/lib/inspect";

import { DropZone } from "./dropzone";
import { RunFeed } from "./run-feed";

type Source =
  | { kind: "local"; verification: LocalVerification; runId: string }
  | { kind: "server"; run: RunSummary };

export function Inspector() {
  const [local, setLocal] = useState<LocalVerification | null>(null);
  const [serverRuns, setServerRuns] = useState<RunSummary[] | null>(null);
  const [serverError, setServerError] = useState<string | null>(null);
  const [source, setSource] = useState<Source | null>(null);
  const [records, setRecords] = useState<SealedRunRecord[]>([]);
  const [uploadState, setUploadState] = useState<string | null>(null);

  const [refreshTick, setRefreshTick] = useState(0);
  const refreshRuns = useCallback(() => setRefreshTick((n) => n + 1), []);

  useEffect(() => {
    let cancelled = false;
    api
      .runs()
      .then((runs) => {
        if (cancelled) return;
        setServerRuns(runs);
        setServerError(null);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setServerRuns(null);
        setServerError(error instanceof Error ? error.message : "recorder unreachable");
      });
    return () => {
      cancelled = true;
    };
  }, [refreshTick]);

  const onFile = useCallback(async (file: File) => {
    const data = new Uint8Array(await file.arrayBuffer());
    const verification = verifyLocally(file.name, data);
    setLocal(verification);
    setUploadState(null);
    const firstRun = verification.bundle ? [...verification.bundle.runs.keys()][0] : undefined;
    if (verification.bundle && firstRun) {
      setSource({ kind: "local", verification, runId: firstRun });
      setRecords(verification.bundle.runs.get(firstRun) ?? []);
    } else {
      setSource(null);
      setRecords([]);
    }
  }, []);

  const selectLocalRun = (runId: string) => {
    if (!local?.bundle) return;
    setSource({ kind: "local", verification: local, runId });
    setRecords(local.bundle.runs.get(runId) ?? []);
  };

  const selectServerRun = async (run: RunSummary) => {
    setSource({ kind: "server", run });
    setRecords(await api.records(run.run_id));
  };

  const uploadToRecorder = async (file: File) => {
    setUploadState("uploading…");
    try {
      const result = await api.upload(file);
      setUploadState(`stored as ${result.bundle_id}`);
      refreshRuns();
    } catch (error) {
      setUploadState(error instanceof Error ? error.message : "upload failed");
    }
  };

  const payloads = useMemo(
    () => (source?.kind === "local" ? source.verification.bundle?.payloads : undefined),
    [source],
  );

  return (
    <main className="layout">
      <header className="header">
        <h1>SealedRun Inspector</h1>
        <span>
          verify an evidence bundle in your browser, or browse runs stored in the recorder
        </span>
      </header>
      <div className="grid">
        <aside>
          <section className="panel">
            <h2>Verify a bundle</h2>
            <DropZone onFile={onFile} onUpload={local ? uploadToRecorder : undefined} />
            {local && (
              <LocalResult
                verification={local}
                onSelect={selectLocalRun}
                selected={source?.kind === "local" ? source.runId : null}
              />
            )}
            {uploadState && <p className="muted">{uploadState}</p>}
          </section>
          <section className="panel" style={{ marginTop: 16 }}>
            <h2>Recorder runs</h2>
            {serverError && <p className="muted">Recorder not reachable: {serverError}</p>}
            {serverRuns && serverRuns.length === 0 && <p className="muted">No runs stored yet.</p>}
            {serverRuns && serverRuns.length > 0 && (
              <ul className="list">
                {serverRuns.map((run) => (
                  <li
                    key={run.run_id}
                    className={
                      source?.kind === "server" && source.run.run_id === run.run_id
                        ? "selected"
                        : ""
                    }
                    onClick={() => void selectServerRun(run)}
                  >
                    <span className="mono">{run.run_id.slice(0, 13)}…</span>
                    <span className={`status ${run.complete ? "ok" : "warn"}`}>
                      {run.record_count} steps
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </aside>
        <section className="panel">
          <h2>Run</h2>
          {records.length === 0 ? (
            <p className="muted">Drop a bundle or pick a stored run to see its steps.</p>
          ) : (
            <RunFeed
              records={records}
              payloads={payloads}
              payloadUrl={source?.kind === "server" ? api.payloadUrl : undefined}
            />
          )}
        </section>
      </div>
    </main>
  );
}

function LocalResult({
  verification,
  onSelect,
  selected,
}: {
  verification: LocalVerification;
  onSelect: (runId: string) => void;
  selected: string | null;
}) {
  const { report, failure, bundle } = verification;
  return (
    <div style={{ marginTop: 12 }}>
      <div className="line">
        <span className="mono">{verification.fileName}</span>{" "}
        <span className="muted">{(verification.sizeBytes / 1024).toFixed(1)} KB</span>
      </div>
      {report && (
        <p>
          <span className="status ok">verified</span>{" "}
          <span className="muted">
            {report.runs.length} run{report.runs.length === 1 ? "" : "s"}, exporter and principal
            signatures valid
          </span>
        </p>
      )}
      {failure && (
        <p className="error">
          <span className="status bad">failed</span> {failure.check}
          {failure.seq !== undefined ? ` at seq ${failure.seq}` : ""}: {failure.message}
        </p>
      )}
      {bundle && bundle.runs.size > 1 && (
        <ul className="list">
          {[...bundle.runs.keys()].map((runId) => (
            <li
              key={runId}
              className={runId === selected ? "selected" : ""}
              onClick={() => onSelect(runId)}
            >
              <span className="mono">{runId}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
