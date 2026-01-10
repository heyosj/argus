import { useState, useCallback, useRef } from "react";
import { parseEmail } from "../utils/emailParser";
import { redactText, defaultRedactionOptions } from "../utils/redactor";
import { extractIOCs } from "../utils/iocExtractor";
import { analyzeThreats } from "../utils/threatAnalyzer";
import RecentAnalyses from "./RecentAnalyses";

export default function ImportView({ onAnalysisComplete, recentAnalyses, onSelectRecent }) {
  const [isDragging, setIsDragging] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [rawEmailContent, setRawEmailContent] = useState("");
  const [showPasteMode, setShowPasteMode] = useState(false);
  const fileInputRef = useRef(null);
  const sampleEmail = `From: "Account Security" <security@example.com>
To: you@example.com
Subject: Action required: confirm your password
Date: Tue, 12 Mar 2024 10:14:22 +0000
Message-ID: <sample-prview-001@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="prview-boundary-1"

--prview-boundary-1
Content-Type: text/plain; charset="UTF-8"

Hi,

We detected a sign-in from a new device. Please confirm your password to keep access.

Confirm here: http://example.com/secure/login

If you do not confirm within 24 hours, access will be limited.

Thanks,
Security Team

--prview-boundary-1
Content-Type: text/plain; name="instructions.txt"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="instructions.txt"

VGhpcyBpcyBhIHNhZmUgc2FtcGxlIGF0dGFjaG1lbnQuCg==
--prview-boundary-1--
`;

  const analyzeEmail = async (contentOrBytes) => {
    const email = await parseEmail(contentOrBytes);
    const redaction = redactText(email.body_text, defaultRedactionOptions);
    const iocs = extractIOCs(email);
    const threat = analyzeThreats(email);
    const analyzed_at =
      new Date().toISOString().replace("T", " ").substring(0, 19) + " UTC";

    return { email, redaction, iocs, threat, analyzed_at };
  };

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback(
    async (e) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragging(false);
      setError(null);

      const files = Array.from(e.dataTransfer.files);
      const emailFile = files.find((f) => f.name.endsWith(".eml") || f.name.endsWith(".msg"));

      if (!emailFile) {
        setError("Please drop an .eml or .msg file");
        return;
      }

      if (emailFile.name.endsWith(".msg")) {
        setError(".msg files are not yet supported. Please use .eml format.");
        return;
      }

      setIsLoading(true);
      try {
        // ✅ Use bytes so attachment decoding/preview works reliably
        const ab = await emailFile.arrayBuffer();
        const bytes = new Uint8Array(ab);

        const result = await analyzeEmail(bytes);
        onAnalysisComplete(result);
      } catch (err) {
        setError(`Failed to parse email: ${err.message}`);
      } finally {
        setIsLoading(false);
      }
    },
    [onAnalysisComplete]
  );

  const handleFileSelect = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.name.endsWith(".msg")) {
      setError(".msg files are not yet supported. Please use .eml format.");
      return;
    }

    setError(null);
    setIsLoading(true);
    try {
      // ✅ Use bytes so attachment decoding/preview works reliably
      const ab = await file.arrayBuffer();
      const bytes = new Uint8Array(ab);

      const result = await analyzeEmail(bytes);
      onAnalysisComplete(result);
    } catch (err) {
      setError(`Failed to parse email: ${err.message}`);
    } finally {
      setIsLoading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const handlePasteSubmit = async () => {
    if (!rawEmailContent.trim()) {
      setError("Please paste email content first");
      return;
    }

    setError(null);
    setIsLoading(true);
    try {
      // Paste mode stays string-based (no binary attachments expected)
      const result = await analyzeEmail(rawEmailContent);
      onAnalysisComplete(result);
      setRawEmailContent("");
      setShowPasteMode(false);
    } catch (err) {
      setError(`Failed to parse email: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSampleEmail = async () => {
    setError(null);
    setIsLoading(true);
    try {
      const result = await analyzeEmail(sampleEmail);
      onAnalysisComplete(result);
    } catch (err) {
      setError(`Failed to parse email: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-6 py-8">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-6">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
              <div className="space-y-3">
                <div>
                  <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Prview</p>
                  <h2 className="text-xl font-semibold text-slate-100">Phishing analysis</h2>
                </div>
                <p className="text-sm text-slate-400 max-w-xl">
                  Inspect headers, URLs, and impersonation indicators in suspicious emails.
                </p>
                <div className="flex flex-wrap gap-2">
                  <span className="px-3 py-1 text-xs rounded-full border border-slate-700 bg-slate-800/60 text-slate-300">
                    Header analysis
                  </span>
                  <span className="px-3 py-1 text-xs rounded-full border border-slate-700 bg-slate-800/60 text-slate-300">
                    URL extraction
                  </span>
                  <span className="px-3 py-1 text-xs rounded-full border border-slate-700 bg-slate-800/60 text-slate-300">
                    Impersonation checks
                  </span>
                </div>
                <p className="text-xs text-slate-500">
                  Analysis runs locally in your browser. Nothing is uploaded.
                </p>
              </div>
              <div className="flex flex-col gap-2">
                <button
                  onClick={handleSampleEmail}
                  disabled={isLoading}
                  className="px-4 py-2 border border-slate-700 text-slate-200 rounded-lg text-sm font-medium hover:border-slate-500 hover:text-slate-100 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
                >
                  Try a sample phishing email
                </button>
              </div>
            </div>
          </div>

          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            className={`relative border-2 border-dashed rounded-xl p-12 text-center transition-all ${
              isDragging
                ? "border-cyan-500 bg-cyan-500/10"
                : "border-slate-700 hover:border-slate-600 bg-slate-800/30"
            }`}
          >
            {isLoading ? (
              <div className="flex flex-col items-center gap-4">
                <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-slate-300">Analyzing email...</p>
              </div>
            ) : (
              <>
                <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-slate-700/50 flex items-center justify-center">
                  <svg
                    className={`w-8 h-8 ${isDragging ? "text-cyan-400" : "text-slate-400"}`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                    />
                  </svg>
                </div>
                <h3 className="text-lg font-medium text-slate-200 mb-2">
                  {isDragging ? "Drop your file here" : "Drop your email file here"}
                </h3>
                <p className="text-slate-400 text-sm mb-4">Supports .eml files</p>

                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".eml"
                  onChange={handleFileSelect}
                  className="hidden"
                />
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition-colors"
                >
                  Or browse files
                </button>
              </>
            )}
          </div>

          {error && (
            <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
              <p className="text-red-400 text-sm">{error}</p>
            </div>
          )}

          <div className="bg-slate-800/50 rounded-xl border border-slate-700 overflow-hidden">
            <button
              onClick={() => setShowPasteMode(!showPasteMode)}
              className="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-slate-700/30 transition-colors"
            >
              <div className="flex items-center gap-3">
                <svg
                  className="w-5 h-5 text-slate-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
                  />
                </svg>
                <span className="text-slate-200 font-medium">Paste raw email source</span>
              </div>
              <svg
                className={`w-5 h-5 text-slate-400 transition-transform ${showPasteMode ? "rotate-180" : ""}`}
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>

            {showPasteMode && (
              <div className="px-6 pb-6 space-y-4">
                <textarea
                  value={rawEmailContent}
                  onChange={(e) => setRawEmailContent(e.target.value)}
                  placeholder="Paste the raw email source here (including headers)..."
                  className="w-full h-48 px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 text-sm font-mono placeholder-slate-500 focus:outline-none focus:border-cyan-500 resize-none"
                />
                <button
                  onClick={handlePasteSubmit}
                  disabled={isLoading || !rawEmailContent.trim()}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg text-sm font-medium transition-colors"
                >
                  Analyze Email
                </button>
              </div>
            )}
          </div>
        </div>

        <div>
          <RecentAnalyses analyses={recentAnalyses} onSelect={onSelectRecent} />
        </div>
      </div>
    </div>
  );
}
