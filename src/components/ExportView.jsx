import { useState } from 'react';
import { exportMarkdown, exportJSON, exportSanitizedEml, downloadFile } from '../utils/exporter';
import { formatIOCsForCopy } from '../utils/iocExtractor';

export default function ExportView({ analysis }) {
  const [exporting, setExporting] = useState(null);
  const [copied, setCopied] = useState(null);
  const [error, setError] = useState(null);

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
              d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
            />
          </svg>
          <h3 className="text-lg font-medium text-slate-200 mb-2">
            No analysis to export
          </h3>
          <p className="text-slate-400">
            Import and analyze an email first
          </p>
        </div>
      </div>
    );
  }

  const exportFormats = [
    {
      id: 'markdown',
      name: 'Markdown Report',
      description: 'Human-readable report with threat analysis, IOCs, and recommendations',
      icon: (
        <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
      ),
      extension: 'md',
      mimeType: 'text/markdown',
    },
    {
      id: 'json',
      name: 'JSON Export',
      description: 'Structured data for programmatic use and integration with other tools',
      icon: (
        <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
        </svg>
      ),
      extension: 'json',
      mimeType: 'application/json',
    },
    {
      id: 'eml',
      name: 'Sanitized Email',
      description: 'Original email with PII redacted, safe to share with colleagues',
      icon: (
        <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
        </svg>
      ),
      extension: 'eml',
      mimeType: 'message/rfc822',
    },
  ];

  const handleExport = async (format) => {
    setExporting(format.id);
    setError(null);

    try {
      let content;
      const filename = `${analysis.email.subject.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 50)}_analysis`;

      switch (format.id) {
        case 'markdown':
          content = exportMarkdown(analysis);
          break;
        case 'json':
          content = exportJSON(analysis);
          break;
        case 'eml':
          content = exportSanitizedEml(analysis);
          break;
        default:
          throw new Error('Unknown format');
      }

      downloadFile(content, `${filename}.${format.extension}`, format.mimeType);
    } catch (err) {
      setError(`Export failed: ${err.message}`);
    } finally {
      setExporting(null);
    }
  };

  const handleCopyIOCs = async () => {
    try {
      const formatted = formatIOCsForCopy(analysis.iocs);
      await navigator.clipboard.writeText(formatted);
      setCopied('iocs');
      setTimeout(() => setCopied(null), 2000);
    } catch (err) {
      setError(`Failed to copy: ${err.message}`);
    }
  };

  const getThreatLevelStyles = () => {
    switch (analysis.threat.level) {
      case 'High':
        return 'border-red-500/30 bg-red-500/10';
      case 'Medium':
        return 'border-amber-500/30 bg-amber-500/10';
      default:
        return 'border-green-500/30 bg-green-500/10';
    }
  };

  const getThreatTextColor = () => {
    switch (analysis.threat.level) {
      case 'High':
        return 'text-red-400';
      case 'Medium':
        return 'text-amber-400';
      default:
        return 'text-green-400';
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-6 py-8 space-y-6">
      {/* Summary Card */}
      <div className={`rounded-xl border p-6 ${getThreatLevelStyles()}`}>
        <div className="flex items-center gap-4">
          <div className={`w-3 h-3 rounded-full ${
            analysis.threat.level === 'High' ? 'bg-red-400' :
            analysis.threat.level === 'Medium' ? 'bg-amber-400' : 'bg-green-400'
          }`} />
          <div>
            <h2 className="text-slate-200 font-medium">{analysis.email.subject}</h2>
            <p className="text-slate-400 text-sm">
              Analyzed: {analysis.analyzed_at} | Threat Level: {' '}
              <span className={getThreatTextColor()}>{analysis.threat.level}</span>
            </p>
          </div>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
          <p className="text-red-400 text-sm">{error}</p>
        </div>
      )}

      {/* Export Formats */}
      <div>
        <h3 className="text-lg font-medium text-slate-200 mb-4">Export Formats</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {exportFormats.map((format) => (
            <button
              key={format.id}
              onClick={() => handleExport(format)}
              disabled={exporting === format.id}
              className="text-left p-6 bg-slate-800/50 rounded-xl border border-slate-700 hover:border-slate-600 hover:bg-slate-800 transition-all group"
            >
              <div className="flex items-start gap-4">
                <div className="text-cyan-500 group-hover:text-cyan-400 transition-colors">
                  {format.icon}
                </div>
                <div className="flex-1">
                  <h4 className="text-slate-200 font-medium mb-1">{format.name}</h4>
                  <p className="text-slate-400 text-sm">{format.description}</p>
                  <p className="text-slate-500 text-xs mt-2">.{format.extension}</p>
                </div>
              </div>
              {exporting === format.id && (
                <div className="mt-4 flex items-center gap-2 text-cyan-400 text-sm">
                  <div className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
                  Exporting...
                </div>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Quick Copy */}
      <div>
        <h3 className="text-lg font-medium text-slate-200 mb-4">Quick Copy</h3>
        <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <h4 className="text-slate-200 font-medium">Copy IOCs to Clipboard</h4>
              <p className="text-slate-400 text-sm mt-1">
                All IOCs formatted for threat intel platforms
              </p>
            </div>
            <button
              onClick={handleCopyIOCs}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                copied === 'iocs'
                  ? 'bg-green-500/20 text-green-400'
                  : 'bg-slate-700 text-slate-200 hover:bg-slate-600'
              }`}
            >
              {copied === 'iocs' ? (
                <span className="flex items-center gap-2">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  Copied!
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                  Copy IOCs
                </span>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* IOC Preview */}
      <div>
        <h3 className="text-lg font-medium text-slate-200 mb-4">IOC Summary</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-4 text-center">
            <p className="text-3xl font-semibold text-cyan-400">
              {analysis.iocs.domains.length}
            </p>
            <p className="text-slate-400 text-sm mt-1">Domains</p>
          </div>
          <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-4 text-center">
            <p className="text-3xl font-semibold text-cyan-400">
              {analysis.iocs.urls.length}
            </p>
            <p className="text-slate-400 text-sm mt-1">URLs</p>
          </div>
          <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-4 text-center">
            <p className="text-3xl font-semibold text-cyan-400">
              {analysis.iocs.ip_addresses.length}
            </p>
            <p className="text-slate-400 text-sm mt-1">IP Addresses</p>
          </div>
          <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-4 text-center">
            <p className="text-3xl font-semibold text-cyan-400">
              {analysis.iocs.file_hashes.length}
            </p>
            <p className="text-slate-400 text-sm mt-1">File Hashes</p>
          </div>
        </div>
      </div>
    </div>
  );
}
