// src/components/AnalysisView.jsx
import { useRef, useState } from "react";
import AttachmentPreview from "./AttachmentPreview";

export default function AnalysisView({ analysis, onExport }) {
  const [showRedacted, setShowRedacted] = useState(true);
  const [activeTab, setActiveTab] = useState("overview");
  const [selectedAttachment, setSelectedAttachment] = useState(null);
  const previewRef = useRef(null);

  if (!analysis) {
    return (
      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-12 text-center">
          <svg
            className="w-16 h-16 mx-auto text-slate-600 mb-4"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
            />
          </svg>
          <h3 className="text-lg font-medium text-slate-200 mb-2">
            No email analyzed
          </h3>
          <p className="text-slate-400">Import an email file to see the analysis</p>
        </div>
      </div>
    );
  }

  const { email, redaction, iocs, threat } = analysis;

  const getThreatLevelStyles = () => {
    switch (threat.level) {
      case "High":
        return "bg-red-500/20 border-red-500/30 text-red-400";
      case "Medium":
        return "bg-amber-500/20 border-amber-500/30 text-amber-400";
      default:
        return "bg-green-500/20 border-green-500/30 text-green-400";
    }
  };

  const getAuthStatusColor = (status) => {
    switch ((status || "").toLowerCase()) {
      case "pass":
        return "text-green-400 bg-green-400/10";
      case "fail":
        return "text-red-400 bg-red-400/10";
      case "softfail":
        return "text-amber-400 bg-amber-400/10";
      default:
        return "text-slate-400 bg-slate-400/10";
    }
  };

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "headers", label: "Headers" },
    { id: "body", label: "Body" },
    { id: "iocs", label: "IOCs" },
  ];

  // Group indicators by category for better display
  const groupedIndicators = threat.indicators.reduce((acc, indicator) => {
    if (!acc[indicator.category]) acc[indicator.category] = [];
    acc[indicator.category].push(indicator);
    return acc;
  }, {});

  // Count high/medium/low severity indicators
  const severityCounts = threat.indicators.reduce((acc, ind) => {
    acc[ind.severity] = (acc[ind.severity] || 0) + 1;
    return acc;
  }, {});

  // Map your parsed attachment object to the preview component’s expected shape.
  // IMPORTANT: preview requires bytes as a Blob/File on `blob` (or `file` / `data`).
  const toPreviewAttachment = (a) => ({
    id: a.id || a.filename,
    name: a.filename,
    mime: a.content_type || a.mime || "",
    size: a.size || 0,
    blob: a.blob || a.file || a.data, // <-- must be a Blob/File
    sha256: a.sha256,
  });

  const handleAttachmentClick = (attachment) => {
    setSelectedAttachment((prev) => {
      const next =
        prev?.filename === attachment.filename ? null : attachment;

      // If opening, scroll preview into view so it’s obvious something happened
      if (next) {
        requestAnimationFrame(() => {
          if (previewRef.current) {
            previewRef.current.scrollIntoView({
              behavior: "smooth",
              block: "nearest",
            });
          }
        });
      }

      return next;
    });
  };

  const selectedHasBytes =
    selectedAttachment?.blob || selectedAttachment?.file || selectedAttachment?.data;

  return (
    <div className="max-w-7xl mx-auto px-6 py-8 space-y-6">
      {/* Threat Level Banner */}
      <div className={`rounded-xl border p-6 ${getThreatLevelStyles()}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-14 h-14 rounded-full bg-current/20 flex items-center justify-center">
              {threat.level === "High" && (
                <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              )}
              {threat.level === "Medium" && (
                <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              )}
              {threat.level === "Low" && (
                <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              )}
            </div>
            <div>
              <div className="flex items-center gap-3">
                <span className="text-xl font-semibold">{threat.level} Risk</span>
                <div className="flex items-center gap-2 text-sm opacity-80">
                  {severityCounts.high > 0 && (
                    <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-300">
                      {severityCounts.high} critical
                    </span>
                  )}
                  {severityCounts.medium > 0 && (
                    <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300">
                      {severityCounts.medium} warning
                    </span>
                  )}
                  {severityCounts.low > 0 && (
                    <span className="px-2 py-0.5 rounded bg-slate-500/20 text-slate-300">
                      {severityCounts.low} info
                    </span>
                  )}
                </div>
              </div>
              <p className="text-sm opacity-90 mt-1">{threat.summary}</p>
            </div>
          </div>
          <button
            onClick={() => onExport()}
            className="px-4 py-2 bg-slate-900/50 hover:bg-slate-900 rounded-lg text-sm font-medium transition-colors"
          >
            Export Report
          </button>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex items-center gap-1 border-b border-slate-700">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.id
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === "overview" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Email Details */}
          <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6">
            <h3 className="text-lg font-medium text-slate-200 mb-4">Email Details</h3>
            <dl className="space-y-3">
              <div>
                <dt className="text-xs text-slate-500 uppercase tracking-wider">Subject</dt>
                <dd className="text-slate-200 font-medium mt-1">{email.subject}</dd>
              </div>
              <div>
                <dt className="text-xs text-slate-500 uppercase tracking-wider">From</dt>
                <dd className="text-slate-200 font-mono text-sm mt-1">{email.from}</dd>
              </div>
              <div>
                <dt className="text-xs text-slate-500 uppercase tracking-wider">To</dt>
                <dd className="text-slate-200 font-mono text-sm mt-1">{email.to}</dd>
              </div>
              {email.reply_to && (
                <div>
                  <dt className="text-xs text-slate-500 uppercase tracking-wider">Reply-To</dt>
                  <dd className="text-slate-200 font-mono text-sm mt-1">{email.reply_to}</dd>
                </div>
              )}
              {email.return_path && (
                <div>
                  <dt className="text-xs text-slate-500 uppercase tracking-wider">Return-Path</dt>
                  <dd className="text-slate-200 font-mono text-sm mt-1">{email.return_path}</dd>
                </div>
              )}
              <div>
                <dt className="text-xs text-slate-500 uppercase tracking-wider">Date</dt>
                <dd className="text-slate-200 text-sm mt-1">{email.date || "Unknown"}</dd>
              </div>
            </dl>
          </div>

          {/* Authentication Results */}
          <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6">
            <h3 className="text-lg font-medium text-slate-200 mb-4">Authentication Results</h3>
            <div className="space-y-3">
              <div className={`flex items-center justify-between p-3 rounded-lg ${getAuthStatusColor(email.authentication.spf_status)}`}>
                <div>
                  <span className="font-medium">SPF</span>
                  <p className="text-xs opacity-75 mt-0.5">Sender Policy Framework</p>
                </div>
                <span className="font-mono font-semibold">{email.authentication.spf_status.toUpperCase()}</span>
              </div>

              <div className={`flex items-center justify-between p-3 rounded-lg ${getAuthStatusColor(email.authentication.dkim_status)}`}>
                <div>
                  <span className="font-medium">DKIM</span>
                  <p className="text-xs opacity-75 mt-0.5">DomainKeys Identified Mail</p>
                </div>
                <span className="font-mono font-semibold">{email.authentication.dkim_status.toUpperCase()}</span>
              </div>

              <div className={`flex items-center justify-between p-3 rounded-lg ${getAuthStatusColor(email.authentication.dmarc_status)}`}>
                <div>
                  <span className="font-medium">DMARC</span>
                  <p className="text-xs opacity-75 mt-0.5">Domain-based Message Authentication</p>
                </div>
                <span className="font-mono font-semibold">{email.authentication.dmarc_status.toUpperCase()}</span>
              </div>
            </div>
          </div>

          {/* Threat Indicators by Category */}
          {Object.keys(groupedIndicators).length > 0 && (
            <div className="md:col-span-2 bg-slate-800/50 rounded-xl border border-slate-700 p-6">
              <h3 className="text-lg font-medium text-slate-200 mb-4">Security Findings</h3>
              <div className="space-y-4">
                {Object.entries(groupedIndicators).map(([category, indicators]) => (
                  <div key={category} className="space-y-2">
                    <h4 className="text-sm font-medium text-slate-400 uppercase tracking-wider">{category}</h4>
                    {indicators.map((indicator, index) => (
                      <div
                        key={index}
                        className={`p-4 rounded-lg border ${
                          indicator.severity === "high"
                            ? "bg-red-500/10 border-red-500/30"
                            : indicator.severity === "medium"
                            ? "bg-amber-500/10 border-amber-500/30"
                            : "bg-slate-900/50 border-slate-700"
                        }`}
                      >
                        <div className="flex items-start gap-3">
                          <div
                            className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${
                              indicator.severity === "high"
                                ? "bg-red-400"
                                : indicator.severity === "medium"
                                ? "bg-amber-400"
                                : "bg-slate-400"
                            }`}
                          />
                          <div className="flex-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span
                                className={`font-medium ${
                                  indicator.severity === "high"
                                    ? "text-red-300"
                                    : indicator.severity === "medium"
                                    ? "text-amber-300"
                                    : "text-slate-300"
                                }`}
                              >
                                {indicator.description}
                              </span>
                            </div>
                            {indicator.details && <p className="text-slate-400 text-sm mt-1">{indicator.details}</p>}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Attachments */}
          {email.attachments.length > 0 && (
            <div className="md:col-span-2 bg-slate-800/50 rounded-xl border border-slate-700 p-6">
              <div className="flex items-center justify-between gap-4 mb-2">
                <h3 className="text-lg font-medium text-slate-200">Attachments</h3>
                <span className="text-xs text-slate-500">
                  Click an attachment to preview
                </span>
              </div>

              <div className="space-y-2">
                {email.attachments.map((attachment, index) => {
                  const isActive =
                    selectedAttachment?.filename === attachment.filename;

                  return (
                    <button
                      key={index}
                      type="button"
                      onClick={() => handleAttachmentClick(attachment)}
                      className={`w-full text-left flex items-center justify-between p-3 rounded-lg border transition-colors cursor-pointer ${
                        isActive
                          ? "bg-slate-900/70 border-cyan-500/30"
                          : "bg-slate-900/50 border-slate-800 hover:bg-slate-900/70 hover:border-slate-700"
                      }`}
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
                            d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13"
                          />
                        </svg>
                        <div>
                          <p className="text-slate-200 font-medium">
                            {attachment.filename}
                          </p>
                          <p className="text-slate-400 text-xs">
                            {attachment.content_type} ({Math.round(attachment.size / 1024)}KB)
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-4">
                        <div className="text-right">
                          <p className="text-xs text-slate-500">SHA256</p>
                          <p className="text-xs font-mono text-slate-400 truncate max-w-48">
                            {attachment.sha256.substring(0, 16)}...
                          </p>
                        </div>

                        <span
                          className={`hidden sm:inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs border ${
                            isActive
                              ? "border-cyan-500/30 text-cyan-300 bg-cyan-500/10"
                              : "border-slate-700 text-slate-300 bg-slate-950/30"
                          }`}
                        >
                          Preview
                          <svg
                            className={`w-4 h-4 transition-transform ${
                              isActive ? "rotate-180" : ""
                            }`}
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={2}
                              d="M19 9l-7 7-7-7"
                            />
                          </svg>
                        </span>
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* Preview area */}
              {selectedAttachment && (
                <div ref={previewRef} className="mt-4">
                  {/* If no bytes exist, show a clear message (prevents “blank” confusion) */}
                  {!selectedHasBytes ? (
                    <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-200">
                      Preview unavailable — attachment bytes weren’t loaded (only metadata).
                      <div className="mt-1 text-xs text-amber-200/80">
                        Make sure your .eml importer stores a <span className="font-mono">Blob</span> (e.g.{" "}
                        <span className="font-mono">attachment.blob</span>) for each attachment.
                      </div>
                    </div>
                  ) : (
                    <AttachmentPreview
                      attachment={toPreviewAttachment(selectedAttachment)}
                      onClose={() => setSelectedAttachment(null)}
                    />
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {activeTab === "headers" && (
        <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6">
          <h3 className="text-lg font-medium text-slate-200 mb-4">Email Headers</h3>
          <div className="space-y-2 max-h-[600px] overflow-y-auto">
            {email.headers.map((header, index) => (
              <div key={index} className="flex gap-3 p-3 bg-slate-900/50 rounded-lg">
                <span className="text-cyan-400 font-mono text-sm min-w-32 flex-shrink-0">
                  {header.name}:
                </span>
                <span className="text-slate-300 font-mono text-sm break-all">
                  {header.value}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === "body" && (
        <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-medium text-slate-200">Email Body</h3>
            <button
              onClick={() => setShowRedacted(!showRedacted)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                showRedacted
                  ? "bg-cyan-500/20 text-cyan-400"
                  : "bg-slate-700 text-slate-300"
              }`}
            >
              {showRedacted ? "Showing Redacted" : "Showing Original"}
            </button>
          </div>
          <div className="bg-slate-900 rounded-lg p-4 max-h-[500px] overflow-y-auto">
            <pre className="text-slate-300 text-sm font-mono whitespace-pre-wrap">
              {showRedacted ? redaction.redacted_text : email.body_text}
            </pre>
          </div>
          {redaction.redaction_count > 0 && (
            <p className="text-slate-400 text-sm mt-3">{redaction.redaction_count} items redacted</p>
          )}
        </div>
      )}

      {activeTab === "iocs" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Domains */}
          {iocs.domains.length > 0 && (
            <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6">
              <h3 className="text-lg font-medium text-slate-200 mb-4">
                Domains ({iocs.domains.length})
              </h3>
              <div className="space-y-2">
                {iocs.domains.map((domain, index) => (
                  <div key={index} className="p-2 bg-slate-900/50 rounded font-mono text-sm text-slate-300">
                    {domain}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* URLs */}
          {iocs.urls.length > 0 && (
            <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6">
              <h3 className="text-lg font-medium text-slate-200 mb-4">
                URLs ({iocs.urls.length})
              </h3>
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {iocs.urls.map((url, index) => (
                  <div key={index} className="p-2 bg-slate-900/50 rounded font-mono text-xs text-slate-300 break-all">
                    {url}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* IP Addresses */}
          {iocs.ip_addresses.length > 0 && (
            <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6">
              <h3 className="text-lg font-medium text-slate-200 mb-4">
                IP Addresses ({iocs.ip_addresses.length})
              </h3>
              <div className="space-y-2">
                {iocs.ip_addresses.map((ip, index) => (
                  <div key={index} className="p-2 bg-slate-900/50 rounded font-mono text-sm text-slate-300">
                    {ip}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Email Addresses */}
          {iocs.email_addresses.length > 0 && (
            <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6">
              <h3 className="text-lg font-medium text-slate-200 mb-4">
                Email Addresses ({iocs.email_addresses.length})
              </h3>
              <div className="space-y-2">
                {iocs.email_addresses.map((addr, index) => (
                  <div key={index} className="p-2 bg-slate-900/50 rounded font-mono text-sm text-slate-300">
                    {addr}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* File Hashes */}
          {iocs.file_hashes.length > 0 && (
            <div className="md:col-span-2 bg-slate-800/50 rounded-xl border border-slate-700 p-6">
              <h3 className="text-lg font-medium text-slate-200 mb-4">File Hashes</h3>
              <div className="space-y-2">
                {iocs.file_hashes.map((hash, index) => (
                  <div key={index} className="p-3 bg-slate-900/50 rounded">
                    <p className="text-slate-200 font-medium text-sm">{hash.filename}</p>
                    <p className="font-mono text-xs text-slate-400 mt-1 break-all">
                      SHA256: {hash.sha256}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Headers of Interest */}
          {iocs.headers_of_interest.length > 0 && (
            <div className="md:col-span-2 bg-slate-800/50 rounded-xl border border-slate-700 p-6">
              <h3 className="text-lg font-medium text-slate-200 mb-4">Headers of Interest</h3>
              <div className="space-y-2">
                {iocs.headers_of_interest.map((header, index) => (
                  <div key={index} className="p-3 bg-slate-900/50 rounded">
                    <div className="flex items-center gap-2">
                      <span className="text-cyan-400 font-mono text-sm">{header.name}:</span>
                      <span className="text-slate-300 font-mono text-sm">{header.value}</span>
                    </div>
                    <p className="text-slate-500 text-xs mt-1">{header.reason}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
