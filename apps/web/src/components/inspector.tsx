"use client";

import type { SealedRunRecord } from "@sealedrun/core";
import { KeyRound, Server } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from "react";

import { api, type RunSummary, setToken, UnauthorizedError } from "@/lib/api";
import { type LocalVerification, parsePrincipals, verifyLocally } from "@/lib/inspect";
import { trustedStore } from "@/lib/trusted-store";

import { DropZone } from "./dropzone";
import { Logo } from "./logo";
import { RunFeed } from "./run-feed";
import { ThemeToggle } from "./theme-toggle";
import { Verdict } from "./verdict";

/** The two tabs: a bundle file checked in the browser, or runs stored in the recorder. */
type View = "bundle" | "recorder";
/** Connection to the recorder API. `locked` means it answered 401 and needs a token. */
type Recorder =
  | { state: "loading" }
  | { state: "ready"; runs: RunSummary[] }
  | { state: "locked" }
  | { state: "offline"; message: string };

/**
 * The whole Inspector page. It verifies a bundle file locally, re-verifies it when the trusted
 * principal list changes, and browses runs stored in the recorder when one is reachable.
 */
export function Inspector() {
  const [view, setView] = useState<View>("bundle");
  const [local, setLocal] = useState<LocalVerification | null>(null);
  const [localRun, setLocalRun] = useState<string | null>(null);
  const [lastFile, setLastFile] = useState<File | null>(null);
  const [recorder, setRecorder] = useState<Recorder>({ state: "loading" });
  const [serverRun, setServerRun] = useState<RunSummary | null>(null);
  const [serverRecords, setServerRecords] = useState<SealedRunRecord[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const [tokenTried, setTokenTried] = useState(false);
  const trusted = useSyncExternalStore(trustedStore.subscribe, trustedStore.read, () => "");

  const [refreshTick, setRefreshTick] = useState(0);
  const refreshRuns = useCallback(() => setRefreshTick((n) => n + 1), []);

  useEffect(() => {
    let cancelled = false;
    api
      .runs()
      .then((runs) => !cancelled && setRecorder({ state: "ready", runs }))
      .catch((error: unknown) => {
        if (cancelled) return;
        if (error instanceof UnauthorizedError) setRecorder({ state: "locked" });
        else {
          const message = error instanceof Error ? error.message : "no answer";
          setRecorder({ state: "offline", message });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [refreshTick]);

  const verify = useCallback(async (file: File, principals: string) => {
    const data = new Uint8Array(await file.arrayBuffer());
    const verification = verifyLocally(file.name, data, parsePrincipals(principals));
    setLocal(verification);
    setLocalRun(verification.bundle ? ([...verification.bundle.runs.keys()][0] ?? null) : null);
    setNotice(null);
  }, []);

  const onFile = useCallback(
    async (file: File) => {
      setLastFile(file);
      await verify(file, trusted);
    },
    [trusted, verify],
  );

  const onTrustedChange = (value: string) => {
    trustedStore.write(value);
    if (lastFile) void verify(lastFile, value);
  };

  const openExample = async () => {
    const response = await fetch("/example-bundle.zip");
    if (!response.ok) return setNotice("The example bundle is not available in this build.");
    await onFile(new File([await response.blob()], "example-bundle.zip"));
  };

  const onUnauthorized = (error: unknown) => {
    if (!(error instanceof UnauthorizedError)) return false;
    setRecorder({ state: "locked" });
    return true;
  };

  const selectServerRun = async (run: RunSummary) => {
    setServerRun(run);
    try {
      setServerRecords(await api.records(run.run_id));
    } catch (error) {
      if (!onUnauthorized(error)) throw error;
    }
  };

  const store = async () => {
    if (!lastFile) return;
    setNotice("Storing…");
    try {
      const result = await api.upload(lastFile);
      setNotice(`Stored in the recorder as bundle ${result.bundle_id}.`);
      refreshRuns();
    } catch (error) {
      onUnauthorized(error);
      setNotice(error instanceof Error ? error.message : "The recorder refused the bundle.");
    }
  };

  const downloadPayload = (recordId: string, side: "request" | "response") => {
    api.downloadPayload(recordId, side).catch(onUnauthorized);
  };

  const localRecords = useMemo(
    () => (localRun && local?.bundle ? (local.bundle.runs.get(localRun) ?? []) : []),
    [local, localRun],
  );

  return (
    <div className="mx-auto max-w-5xl px-4 pb-24 sm:px-6">
      <header className="flex flex-wrap items-center justify-between gap-3 py-6">
        <p className="flex items-center gap-2.5 text-lg font-semibold tracking-wide">
          <Logo size={22} />
          SealedRun <span className="font-normal text-ink-soft">Inspector</span>
        </p>
        <div className="flex items-center gap-4 text-sm text-ink-soft">
          <a href="https://sealedrun.com" className="hover:text-ink">
            Home
          </a>
          <a href="https://docs.sealedrun.com" className="hover:text-ink">
            Docs
          </a>
          <RecorderStatus recorder={recorder} />
          <ThemeToggle />
        </div>
      </header>

      <nav className="flex gap-1 border-b border-line" aria-label="Source">
        <Tab active={view === "bundle"} onClick={() => setView("bundle")}>
          Check a bundle file
        </Tab>
        <Tab active={view === "recorder"} onClick={() => setView("recorder")}>
          Runs in the recorder
          {recorder.state === "ready" && (
            <span className="ml-1.5 text-ink-soft tabular-nums">{recorder.runs.length}</span>
          )}
        </Tab>
      </nav>

      {view === "bundle" && (
        <main className="pt-8">
          {!local ? (
            <>
              <Welcome onFile={onFile} onExample={() => void openExample()} />
              {notice && <p className="mt-4 text-sm text-bad">{notice}</p>}
            </>
          ) : (
            <div className="space-y-6">
              <Verdict verification={local} />
              <div className="grid gap-4 md:grid-cols-[1fr_auto] md:items-start">
                <TrustedIds value={trusted} onChange={onTrustedChange} />
                <div className="space-y-3 md:w-64">
                  <DropZone onFile={onFile} compact />
                  {local.report && recorder.state === "ready" && (
                    <button type="button" className="btn w-full" onClick={() => void store()}>
                      <Server aria-hidden className="size-4" /> Store in the recorder
                    </button>
                  )}
                  {notice && (
                    <p className="text-sm text-ink-soft [overflow-wrap:anywhere]" role="status">
                      {notice}
                    </p>
                  )}
                </div>
              </div>
              {local.bundle && local.bundle.runs.size > 1 && (
                <RunPicker
                  runs={[...local.bundle.runs.keys()]}
                  selected={localRun}
                  onSelect={setLocalRun}
                />
              )}
              {localRecords.length > 0 && (
                <section>
                  <h2 className="mb-4 text-xl font-semibold tracking-tight">What the agent did</h2>
                  <RunFeed records={localRecords} payloads={local.bundle?.payloads} />
                </section>
              )}
            </div>
          )}
        </main>
      )}

      {view === "recorder" && (
        <main className="pt-8">
          {recorder.state === "loading" && (
            <p className="text-ink-soft">Contacting the recorder…</p>
          )}
          {recorder.state === "offline" && (
            <Empty title="The recorder does not answer">
              This page can still check bundle files. To browse stored runs, start the recorder and
              reload. ({recorder.message})
            </Empty>
          )}
          {recorder.state === "locked" && (
            <TokenForm
              rejected={tokenTried}
              onSubmit={(token) => {
                setToken(token.trim());
                setTokenTried(true);
                setRecorder({ state: "loading" });
                refreshRuns();
              }}
            />
          )}
          {recorder.state === "ready" && recorder.runs.length === 0 && (
            <Empty title="No runs stored yet">
              Check a bundle file first, then choose “Store in the recorder”.
            </Empty>
          )}
          {recorder.state === "ready" && recorder.runs.length > 0 && (
            <div className="grid gap-8 lg:grid-cols-[20rem_1fr]">
              <ul className="space-y-2">
                {recorder.runs.map((run) => (
                  <li key={run.run_id}>
                    <RunRow
                      run={run}
                      selected={serverRun?.run_id === run.run_id}
                      onSelect={() => void selectServerRun(run)}
                    />
                  </li>
                ))}
              </ul>
              <section className="min-w-0">
                {serverRun && serverRecords.length > 0 ? (
                  <RunFeed records={serverRecords} onDownload={downloadPayload} />
                ) : (
                  <p className="text-ink-soft">Pick a run to see its steps.</p>
                )}
              </section>
            </div>
          )}
        </main>
      )}
    </div>
  );
}

/** Tab button in the source switcher. */
function Tab({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-current={active ? "page" : undefined}
      className={`-mb-px cursor-pointer border-b-2 px-3 py-2.5 text-sm font-medium ${
        active ? "border-seal text-ink" : "border-transparent text-ink-soft hover:text-ink"
      }`}
    >
      {children}
    </button>
  );
}

/** Header indicator of the recorder connection state. */
function RecorderStatus({ recorder }: { recorder: Recorder }) {
  const [dot, label] = {
    loading: ["bg-line", "Recorder: connecting"],
    ready: ["bg-ok", "Recorder connected"],
    locked: ["bg-warn", "Recorder needs a token"],
    offline: ["bg-line", "Recorder offline"],
  }[recorder.state];
  return (
    <p className="flex items-center gap-2 text-sm text-ink-soft">
      <span aria-hidden className={`size-2 rounded-full ${dot}`} />
      {label}
    </p>
  );
}

/**
 * Landing view shown before any bundle is opened: headline, drop zone, example link and the
 * three-step explanation.
 */
function Welcome({
  onFile,
  onExample,
}: {
  onFile: (file: File) => void | Promise<void>;
  onExample: () => void;
}) {
  const steps = [
    ["Open a bundle", "A bundle is the .zip an agent operator exports as evidence of a run."],
    [
      "Confirm the signer",
      "Enter the signer's principal id, which you got from them and not from the file.",
    ],
    ["Read the run", "See every step, what left the host, and what policy blocked."],
  ];
  return (
    <div className="grid gap-10 lg:grid-cols-[1fr_20rem]">
      <div>
        <h1 className="max-w-[18ch] text-4xl leading-tight font-semibold tracking-tight">
          Was this agent run tampered with?
        </h1>
        <p className="mt-3 max-w-[60ch] text-ink-soft">
          Open an evidence bundle to check its hash chain and signatures, then read what the agent
          actually did.
        </p>
        <div className="mt-6">
          <DropZone onFile={onFile} />
        </div>
        <p className="mt-4 text-sm text-ink-soft">
          No bundle at hand?{" "}
          <button
            type="button"
            className="cursor-pointer font-medium text-seal underline underline-offset-2"
            onClick={onExample}
          >
            Try the example bundle
          </button>
        </p>
      </div>
      <ol className="space-y-5 lg:pt-3">
        {steps.map(([title, text], index) => (
          <li key={title} className="flex gap-3">
            <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-seal-soft text-sm font-semibold text-seal">
              {index + 1}
            </span>
            <span>
              <span className="block font-semibold">{title}</span>
              <span className="text-sm text-ink-soft">{text}</span>
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}

/** Text area for the principal ids the user trusts. */
function TrustedIds({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return (
    <label className="block">
      <span className="font-semibold">Principal ids you trust</span>
      <span className="mb-2 block text-sm text-ink-soft">
        Paste the id the signer gave you (contract, website, email). Do not copy it from the bundle
        you are checking. One per line.
      </span>
      <textarea
        className="field hash"
        rows={2}
        spellCheck={false}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  );
}

/** Run selector, shown only when a bundle holds more than one run. */
function RunPicker({
  runs,
  selected,
  onSelect,
}: {
  runs: string[];
  selected: string | null;
  onSelect: (runId: string) => void;
}) {
  return (
    <label className="block text-sm">
      <span className="font-semibold">Run</span>
      <select
        className="field hash mt-1"
        value={selected ?? ""}
        onChange={(event) => onSelect(event.target.value)}
      >
        {runs.map((runId) => (
          <option key={runId}>{runId}</option>
        ))}
      </select>
    </label>
  );
}

/**
 * A stored run in the recorder list, with its step count and whether the recorder trusts the
 * signer.
 */
function RunRow({
  run,
  selected,
  onSelect,
}: {
  run: RunSummary;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      className={`w-full cursor-pointer rounded-lg border px-4 py-3 text-left ${
        selected ? "border-seal bg-seal-soft" : "border-line bg-surface hover:border-ink-soft"
      }`}
    >
      <span className="hash block">{run.run_id}</span>
      <span className="mt-1 block text-sm text-ink-soft">
        {run.record_count} steps, {run.complete ? "complete" : "not finished"}
      </span>
      <span
        className={`mt-1 block text-sm font-medium ${run.principal_trusted ? "text-ok" : "text-warn"}`}
        title={`Principal ${run.principal_id}`}
      >
        {run.principal_trusted ? "Signer trusted by this recorder" : "Signer not confirmed"}
      </span>
    </button>
  );
}

/**
 * Asks for the recorder API token after a 401.
 *
 * @param rejected - True once a submitted token has been refused.
 */
function TokenForm({
  onSubmit,
  rejected,
}: {
  onSubmit: (token: string) => void;
  rejected: boolean;
}) {
  const [value, setValue] = useState("");
  return (
    <form
      className="max-w-md"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit(value);
      }}
    >
      <h2 className="flex items-center gap-2 text-xl font-semibold tracking-tight">
        <KeyRound aria-hidden className="size-5 text-seal" /> This recorder needs a token
      </h2>
      <p className="mt-1 text-sm text-ink-soft">
        It is the value of SEALEDRUN_API_TOKEN on the server. It is kept for this tab only.
      </p>
      <div className="mt-4 flex gap-2">
        <input
          className="field"
          type="password"
          autoComplete="off"
          aria-label="API token"
          placeholder="API token"
          value={value}
          onChange={(event) => setValue(event.target.value)}
        />
        <button type="submit" className="btn btn-primary" disabled={!value.trim()}>
          Unlock
        </button>
      </div>
      {rejected && (
        <p className="mt-2 text-sm text-bad" role="alert">
          The recorder did not accept that token. Check it and try again.
        </p>
      )}
    </form>
  );
}

/** Titled message shown in place of the run list. */
function Empty({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="max-w-[60ch]">
      <h2 className="text-xl font-semibold tracking-tight">{title}</h2>
      <p className="mt-1 text-ink-soft">{children}</p>
    </div>
  );
}
