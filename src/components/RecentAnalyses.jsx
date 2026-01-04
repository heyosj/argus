export default function RecentAnalyses({ analyses, onSelect }) {
  const getThreatColor = (level) => {
    switch (level) {
      case 'High':
        return 'bg-red-400';
      case 'Medium':
        return 'bg-amber-400';
      default:
        return 'bg-green-400';
    }
  };

  const getThreatBorderColor = (level) => {
    switch (level) {
      case 'High':
        return 'border-red-400/30';
      case 'Medium':
        return 'border-amber-400/30';
      default:
        return 'border-green-400/30';
    }
  };

  if (!analyses || analyses.length === 0) {
    return (
      <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6">
        <h3 className="text-lg font-medium text-slate-200 mb-4">
          Recent Analyses
        </h3>
        <p className="text-slate-400 text-sm">
          Recent analyses will appear here after you import or paste an email,
          so you can jump back to prior results.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6">
      <h3 className="text-lg font-medium text-slate-200 mb-4">
        Recent Analyses
      </h3>
      <div className="space-y-3">
        {analyses.map((analysis, index) => (
          <button
            key={analysis.email?.id || index}
            onClick={() => onSelect(analysis)}
            className={`w-full text-left p-4 rounded-lg border bg-slate-900/50 hover:bg-slate-900 transition-colors ${getThreatBorderColor(
              analysis.threat?.level
            )}`}
          >
            <div className="flex items-start gap-3">
              <div
                className={`w-2 h-2 rounded-full mt-2 ${getThreatColor(
                  analysis.threat?.level
                )}`}
              />
              <div className="flex-1 min-w-0">
                <p className="text-slate-200 font-medium truncate">
                  {analysis.email?.subject || 'No Subject'}
                </p>
                <p className="text-slate-400 text-sm truncate">
                  {analysis.email?.from || 'Unknown Sender'}
                </p>
                <p className="text-slate-500 text-xs mt-1">
                  {analysis.analyzed_at}
                </p>
              </div>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
