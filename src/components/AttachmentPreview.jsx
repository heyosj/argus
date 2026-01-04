// src/components/AttachmentPreview.jsx
import { useEffect, useMemo, useState } from "react";

function isPdf(mime, name) {
  const m = (mime || "").toLowerCase();
  if (m.includes("pdf")) return true;
  return (name || "").toLowerCase().endsWith(".pdf");
}

function isTextLike(mime, name) {
  const m = (mime || "").toLowerCase();
  if (m.startsWith("text/")) return true;
  const n = (name || "").toLowerCase();
  return (
    n.endsWith(".txt") ||
    n.endsWith(".log") ||
    n.endsWith(".csv") ||
    n.endsWith(".json") ||
    n.endsWith(".xml") ||
    n.endsWith(".eml") ||
    n.endsWith(".md")
  );
}

export default function AttachmentPreview({ attachment, onClose }) {
  const name = attachment?.name || attachment?.filename || "attachment";
  const mime =
    attachment?.mime || attachment?.content_type || "application/octet-stream";
  const size = attachment?.size || 0;
  const sha256 = attachment?.sha256;

  const blob = attachment?.blob || null;

  const [text, setText] = useState("");
  const [textError, setTextError] = useState(null);

  const objectUrl = useMemo(() => {
    if (!blob) return null;
    try {
      return URL.createObjectURL(blob);
    } catch {
      return null;
    }
  }, [blob]);

  useEffect(() => {
    return () => {
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [objectUrl]);

  useEffect(() => {
    let cancelled = false;
    setText("");
    setTextError(null);

    if (!blob) return;

    if (isTextLike(mime, name)) {
      blob
        .text()
        .then((t) => {
          if (!cancelled) setText(t);
        })
        .catch((err) => {
          if (!cancelled) setTextError(err?.message || "Failed to read text");
        });
    }

    return () => {
      cancelled = true;
    };
  }, [blob, mime, name]);

  if (!blob) {
    return (
      <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-200">
        Preview unavailable — attachment bytes weren&apos;t loaded (only metadata).
      </div>
    );
  }

  // ✅ If parser flagged an invalid PDF or other decode issue, show it.
  if (attachment?.preview_error) {
    return (
      <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-200">
        {attachment.preview_error}
        <div className="mt-2 text-xs text-amber-200/80">
          Tip: try opening the attachment in a new tab to confirm, or verify the
          .eml base64 payload/boundaries.
        </div>
        {objectUrl ? (
          <div className="mt-3 flex gap-2">
            <a
              href={objectUrl}
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 rounded-lg text-xs font-medium border border-amber-500/40 text-amber-100 hover:bg-amber-500/10 transition-colors"
            >
              Open anyway
            </a>
            <a
              href={objectUrl}
              download={name}
              className="px-3 py-1.5 rounded-lg text-xs font-medium border border-amber-500/40 text-amber-100 hover:bg-amber-500/10 transition-colors"
            >
              Download
            </a>
          </div>
        ) : null}
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-700 bg-slate-900/40 overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-slate-700 flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <p className="text-slate-200 font-medium truncate">{name}</p>
            <span className="text-[11px] px-2 py-0.5 rounded-full border border-slate-700 text-slate-300 bg-slate-950/30">
              {mime}
            </span>
          </div>
          <div className="mt-1 flex items-center gap-3 text-xs text-slate-400">
            <span>{Math.max(1, Math.round(size / 1024))}KB</span>
            {sha256 ? (
              <span className="font-mono truncate">
                SHA256: {sha256.slice(0, 12)}…
              </span>
            ) : null}
          </div>
          <div className="mt-2 text-xs text-slate-500">
            Preview renders locally and is read-only. This isn&apos;t a malware
            sandbox, so treat attachments as untrusted.
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          {objectUrl ? (
            <>
              <a
                href={objectUrl}
                target="_blank"
                rel="noreferrer"
                className="px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-700 text-slate-200 hover:bg-slate-800/60 transition-colors"
              >
                Open
              </a>
              <a
                href={objectUrl}
                download={name}
                className="px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-700 text-slate-200 hover:bg-slate-800/60 transition-colors"
              >
                Download
              </a>
            </>
          ) : null}
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
          >
            Close
          </button>
        </div>
      </div>

      {/* Body */}
      <div className="p-4">
        {/* PDF */}
        {isPdf(mime, name) && objectUrl ? (
          <div className="rounded-lg overflow-hidden border border-slate-700 bg-slate-950">
            <iframe
              title={`Preview ${name}`}
              src={objectUrl}
              className="w-full h-[520px]"
            />
          </div>
        ) : null}

        {/* Text */}
        {isTextLike(mime, name) ? (
          <div className="rounded-lg border border-slate-700 bg-slate-950 max-h-[520px] overflow-auto">
            {textError ? (
              <div className="p-4 text-sm text-red-300">
                Failed to preview text: {textError}
              </div>
            ) : (
              <pre className="p-4 text-xs text-slate-200 whitespace-pre-wrap font-mono">
                {text || "Loading preview…"}
              </pre>
            )}
          </div>
        ) : null}

        {/* Fallback */}
        {!isPdf(mime, name) && !isTextLike(mime, name) ? (
          <div className="rounded-lg border border-slate-700 bg-slate-950 p-4 text-sm text-slate-300">
            No inline preview available for this file type.
            <div className="mt-2 text-xs text-slate-400">
              Use <span className="text-slate-200">Open</span> to view it in a
              new tab.
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
