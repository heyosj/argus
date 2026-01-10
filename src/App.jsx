import { useState, useEffect } from 'react';
import Header from './components/Header';
import ImportView from './components/ImportView';
import AnalysisView from './components/AnalysisView';
import ExportView from './components/ExportView';

const STORAGE_KEY = "prview_recent_analyses";
const MAX_RECENT = 20;

function App() {
  const [currentView, setCurrentView] = useState('import');
  const [currentAnalysis, setCurrentAnalysis] = useState(null);
  const [recentAnalyses, setRecentAnalyses] = useState([]);

  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      try {
        setRecentAnalyses(JSON.parse(stored));
      } catch (e) {
        console.error('Failed to load recent analyses:', e);
      }
    }
  }, []);

  const saveToRecent = (analysis) => {
    const updated = [
      analysis,
      ...recentAnalyses.filter((a) => a.email.id !== analysis.email.id),
    ].slice(0, MAX_RECENT);

    setRecentAnalyses(updated);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  };

  const handleAnalysisComplete = (analysis) => {
    setCurrentAnalysis(analysis);
    saveToRecent(analysis);
    setCurrentView('analysis');
  };

  const handleSelectRecent = (analysis) => {
    setCurrentAnalysis(analysis);
    setCurrentView('analysis');
  };

  const handleExport = () => {
    setCurrentView('export');
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col">
      <Header currentView={currentView} onViewChange={setCurrentView} />

      <main className="flex-1">
        {currentView === 'import' && (
          <ImportView
            onAnalysisComplete={handleAnalysisComplete}
            recentAnalyses={recentAnalyses}
            onSelectRecent={handleSelectRecent}
          />
        )}
        {currentView === 'analysis' && (
          <AnalysisView analysis={currentAnalysis} onExport={handleExport} />
        )}
        {currentView === 'export' && <ExportView analysis={currentAnalysis} />}
      </main>

      <footer className="border-t border-slate-800 bg-slate-900/40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-4 text-xs text-slate-500 text-center">
          Built by an analyst, for analysts ·{' '}
          <a
            href="https://www.heyosj.com"
            target="_blank"
            rel="noreferrer"
            className="text-slate-400 hover:text-slate-200 transition-colors"
          >
            @heyosj
          </a>
        </div>
      </footer>
    </div>
  );
}

export default App;
