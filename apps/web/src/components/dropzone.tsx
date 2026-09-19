"use client";

import { type ChangeEvent, type DragEvent, useRef, useState } from "react";

export function DropZone({
  onFile,
  onUpload,
}: {
  onFile: (file: File) => void | Promise<void>;
  onUpload?: (file: File) => void | Promise<void>;
}) {
  const [active, setActive] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const accept = (candidate: File | undefined) => {
    if (!candidate) return;
    setFile(candidate);
    void onFile(candidate);
  };

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setActive(false);
    accept(event.dataTransfer.files[0]);
  };

  const onChange = (event: ChangeEvent<HTMLInputElement>) => accept(event.target.files?.[0]);

  return (
    <div>
      <div
        className={`dropzone ${active ? "active" : ""}`}
        onClick={() => input.current?.click()}
        onDragOver={(event) => {
          event.preventDefault();
          setActive(true);
        }}
        onDragLeave={() => setActive(false)}
        onDrop={onDrop}
      >
        Drop a bundle .zip here or click to choose
        <input ref={input} type="file" accept=".zip,application/zip" onChange={onChange} />
      </div>
      {file && onUpload && (
        <p>
          <button onClick={() => void onUpload(file)}>Store in recorder</button>
        </p>
      )}
    </div>
  );
}
