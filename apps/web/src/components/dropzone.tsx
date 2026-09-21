"use client";

import { FileArchive, Upload } from "lucide-react";
import { type ChangeEvent, type DragEvent, useRef, useState } from "react";

/**
 * File target for a bundle .zip. It accepts a drop or opens the file dialog on click.
 *
 * @param onFile - Called with the first dropped or chosen file.
 * @param compact - One-line variant shown once a bundle is already open.
 */
export function DropZone({
  onFile,
  compact = false,
}: {
  onFile: (file: File) => void | Promise<void>;
  compact?: boolean;
}) {
  const [active, setActive] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  const accept = (candidate: File | undefined) => {
    if (candidate) void onFile(candidate);
  };

  const onDrop = (event: DragEvent<HTMLButtonElement>) => {
    event.preventDefault();
    setActive(false);
    accept(event.dataTransfer.files[0]);
  };

  const onChange = (event: ChangeEvent<HTMLInputElement>) => {
    accept(event.target.files?.[0]);
    event.target.value = "";
  };

  return (
    <button
      type="button"
      className={`flex w-full cursor-pointer items-center rounded-lg border-2 border-dashed transition-colors ${
        active ? "border-seal bg-seal-soft" : "border-line bg-surface hover:border-seal"
      } ${compact ? "gap-3 px-4 py-3 text-left" : "flex-col gap-3 px-6 py-12 text-center"}`}
      onClick={() => input.current?.click()}
      onDragOver={(event) => {
        event.preventDefault();
        setActive(true);
      }}
      onDragLeave={() => setActive(false)}
      onDrop={onDrop}
    >
      {compact ? (
        <Upload aria-hidden className="size-4 shrink-0 text-seal" />
      ) : (
        <FileArchive aria-hidden className="size-10 text-seal" strokeWidth={1.5} />
      )}
      <span>
        <span className={compact ? "text-sm font-medium" : "block text-lg font-semibold"}>
          {compact ? "Check another bundle" : "Drop a bundle .zip here"}
        </span>
        {!compact && (
          <span className="mt-1 block text-sm text-ink-soft">
            or click to choose a file. It is checked in this browser and is not uploaded.
          </span>
        )}
      </span>
      <input
        ref={input}
        type="file"
        accept=".zip,application/zip"
        className="hidden"
        onChange={onChange}
      />
    </button>
  );
}
