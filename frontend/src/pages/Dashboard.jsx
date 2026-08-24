import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, CheckCircle, ChevronRight, Loader, AlertTriangle, Info, Network, X, Cpu, Database, Trash2 } from 'lucide-react';

export default function Dashboard() {
  const [targetDir, setTargetDir] = useState('e:\\WEB_DEV\\Projects\\codeShield');
  const [gitToken, setGitToken] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [scanData, setScanData] = useState(null);
  const [history, setHistory] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [fixConfirmModal, setFixConfirmModal] = useState(null);
  const [fixError, setFixError] = useState(null);
  const [fixedFindings, setFixedFindings] = useState({});

  useEffect(() => {
    fetchHistory();
  }, []);

  useEffect(() => {
    let interval;
    if (scanId && (!scanData || scanData.status === 'running')) {
      interval = setInterval(() => {
        fetchScanResult(scanId);
      }, 3000);
    }
    return () => clearInterval(interval);
  }, [scanId, scanData]);

  const fetchHistory = async () => {
    try {
      const res = await fetch('http://localhost:8000/history');
      if (res.ok) {
        const data = await res.json();
        setHistory(data);
      }
    } catch (e) {
      console.error("Failed to fetch history:", e);
    }
  };

  const fetchScanResult = async (id) => {
    try {
      const res = await fetch(`http://localhost:8000/scan/${id}`);
      if (res.ok) {
        const data = await res.json();
        setScanData(data);
        if (data.status === 'completed' || data.status === 'failed') {
          setScanning(false);
          fetchHistory();
        }
      }
    } catch (e) {
      console.error("Failed to fetch scan results:", e);
    }
  };

  const triggerScan = async () => {
    if (!targetDir) return;
    setScanning(true);
    setScanData(null);
    setSelectedFinding(null);
    
    try {
      const res = await fetch('http://localhost:8000/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_dir: targetDir, git_token: gitToken || null })
      });
      if (res.ok) {
        const data = await res.json();
        setScanId(data.scan_id);
      } else {
        setScanning(false);
        alert("Failed to start scan. Check backend.");
      }
    } catch (e) {
      setScanning(false);
      console.error(e);
    }
  };

  const loadHistoricalScan = (id) => {
    setScanId(id);
    setScanData(null);
    setSelectedFinding(null);
    fetchScanResult(id);
  };

  const deleteScan = async (id, e) => {
    e.stopPropagation();
    try {
      const res = await fetch(`http://localhost:8000/history/${id}`, { method: 'DELETE' });
      if (res.ok) {
        if (scanId === id) {
          setScanId(null);
          setScanData(null);
          setSelectedFinding(null);
        }
        fetchHistory();
      }
    } catch (e) {
      console.error("Failed to delete scan:", e);
    }
  };

  const clearHistory = async () => {
    if (!window.confirm("Are you sure you want to clear all history?")) return;
    try {
      const res = await fetch('http://localhost:8000/history', { method: 'DELETE' });
      if (res.ok) {
        setScanId(null);
        setScanData(null);
        setSelectedFinding(null);
        fetchHistory();
      }
    } catch (e) {
      console.error("Failed to clear history:", e);
    }
  };

  const triggerApplyFix = (findingId) => {
    setFixConfirmModal(findingId);
  };

  const confirmApplyFix = async () => {
    if (!fixConfirmModal) return;
    const findingId = fixConfirmModal;
    setFixConfirmModal(null);
    try {
      const res = await fetch(`http://localhost:8000/apply_fix/${findingId}`, { method: 'POST' });
      if (res.ok) {
        setFixedFindings(prev => ({ ...prev, [findingId]: true }));
      } else {
        const error = await res.json();
        setFixError(`Failed to apply fix: ${error.detail}`);
      }
    } catch (e) {
      console.error("Error applying fix:", e);
      setFixError("Error applying fix. Check console.");
    }
  };

  const getRiskBadge = (score) => {
    if (score >= 70) return <span className="bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded text-xs font-mono font-bold flex items-center gap-1.5 w-fit"><ShieldAlert size={12}/> Critical</span>;
    if (score >= 40) return <span className="bg-accent-signal/10 text-accent-signal border border-accent-signal/20 px-2 py-0.5 rounded text-xs font-mono font-bold flex items-center gap-1.5 w-fit"><AlertTriangle size={12}/> Medium</span>;
    return <span className="bg-accent-verified/10 text-accent-verified border border-accent-verified/20 px-2 py-0.5 rounded text-xs font-mono font-bold flex items-center gap-1.5 w-fit"><Info size={12}/> Low</span>;
  };

  return (
    <>
    <div className="min-h-screen p-6 md:p-10 max-w-[1600px] mx-auto font-sans relative overflow-hidden bg-core-bg text-core-text">
      <header className="flex flex-col md:flex-row items-center justify-between mb-12 gap-6 relative z-10">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-core-surface rounded border border-core-border shadow-lg">
            <Shield className="text-core-text w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white font-heading">CodeShield</h1>
            <p className="text-core-muted text-xs uppercase tracking-widest font-bold mt-1 font-mono">Workspace</p>
          </div>
        </div>
        
        <div className="flex flex-col md:flex-row gap-4 items-center w-full md:w-auto">
          <div className="relative group w-full md:w-80">
            <Network className="absolute left-4 top-1/2 -translate-y-1/2 text-core-muted w-4 h-4" />
            <input 
              type="text" 
              value={targetDir} 
              onChange={e => setTargetDir(e.target.value)}
              placeholder="Local Path or GitHub URL"
              className="w-full bg-core-surface border border-core-border rounded-none pl-11 pr-4 py-3 text-sm text-core-text focus:outline-none focus:border-accent-verified focus:ring-1 focus:ring-accent-verified transition-colors font-mono"
            />
          </div>
          <div className="relative group w-full md:w-48">
            <input 
              type="password" 
              value={gitToken} 
              onChange={e => setGitToken(e.target.value)}
              placeholder="Git Token (Optional)"
              className="w-full bg-core-surface border border-core-border rounded-none px-4 py-3 text-sm text-core-text focus:outline-none focus:border-accent-verified focus:ring-1 focus:ring-accent-verified transition-colors font-mono"
            />
          </div>
          <button 
            onClick={triggerScan}
            disabled={scanning}
            className={`px-8 py-3 rounded-none font-heading font-semibold text-sm transition-colors flex items-center gap-2 whitespace-nowrap ${
              scanning 
                ? 'bg-core-surface text-core-muted border border-core-border cursor-not-allowed' 
                : 'bg-accent-signal hover:bg-[#FCD386] text-core-bg'
            }`}
          >
            {scanning ? <><Loader className="animate-spin" size={16}/> Scanning</> : 'Run Scan'}
          </button>
        </div>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 relative z-10">
        {/* Sidebar: History */}
        <div className="lg:col-span-3 space-y-4">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-sm font-bold text-core-muted uppercase tracking-wider font-heading">Scan History</h2>
            {history.length > 0 && (
              <button 
                onClick={clearHistory}
                className="text-xs text-core-muted hover:text-red-400 transition-colors flex items-center gap-1 font-mono"
              >
                <Trash2 size={12} /> Clear All
              </button>
            )}
          </div>
          <div className="space-y-3 max-h-[75vh] overflow-y-auto pr-2">
            {history.length === 0 && <p className="text-core-muted text-sm">No past scans.</p>}
            {history.map(h => (
              <div 
                key={h.id} 
                onClick={() => loadHistoricalScan(h.id)}
                className={`group p-4 rounded border cursor-pointer transition-colors ${
                  scanId === h.id 
                    ? 'bg-core-surface border-accent-verified shadow-lg' 
                    : 'bg-transparent border-core-border hover:bg-core-surface'
                }`}
              >
                <div className="flex justify-between items-center mb-2">
                  <div className="text-xs text-core-muted font-mono">{new Date(h.timestamp).toLocaleTimeString()}</div>
                  <div className="flex items-center gap-3">
                    <button 
                      onClick={(e) => deleteScan(h.id, e)} 
                      className="text-core-muted hover:text-red-400 opacity-0 group-hover:opacity-100 transition-opacity"
                      title="Delete scan"
                    >
                      <Trash2 size={14} />
                    </button>
                    {h.status === 'completed' ? <CheckCircle size={14} className="text-accent-verified"/> : <Loader size={14} className="text-accent-signal animate-spin"/>}
                  </div>
                </div>
                <div className="text-sm font-medium text-core-text truncate font-mono" title={h.target_dir}>
                  {h.target_dir.split('\\').pop() || h.target_dir}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Main Content: Results */}
        <div className="lg:col-span-9 relative">
          {!scanning && !scanData && (
            <div className="bg-core-surface/30 p-16 flex flex-col items-center justify-center text-center h-[600px] border border-dashed border-core-border rounded">
              <Shield className="w-12 h-12 text-core-muted mb-6" />
              <h3 className="text-xl font-bold text-core-text font-heading mb-2">Ready to Scan</h3>
              <p className="text-core-muted text-sm max-w-sm">Enter a target directory and click "Run Scan" to initiate the AI vulnerability triage.</p>
            </div>
          )}

          {scanning && !scanData && (
            <div className="bg-core-surface/30 p-16 flex flex-col items-center justify-center text-center h-[600px] border border-core-border rounded relative overflow-hidden">
              <div className="absolute top-0 left-0 w-full h-[2px] bg-accent-verified shadow-[0_0_20px_4px_rgba(62,214,196,0.7)] animate-scan-line"></div>
              <div className="relative mb-8">
                <Loader className="w-12 h-12 text-accent-verified animate-spin relative z-10" />
              </div>
              <h3 className="text-xl font-bold text-white font-heading mb-3">Analyzing Codebase</h3>
              <p className="text-core-muted text-sm max-w-md leading-relaxed">
                Running static analysis, querying RAG vector database, and generating AI insights...
              </p>
            </div>
          )}

          {scanData && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-core-surface p-6 rounded border border-core-border">
                  <div className="text-core-muted text-xs font-bold uppercase tracking-wider mb-2 font-mono">Total Findings</div>
                  <div className="text-4xl font-light text-white font-mono">{scanData.findings.length}</div>
                </div>
                <div className="bg-core-surface p-6 rounded border border-core-border">
                  <div className="text-core-muted text-xs font-bold uppercase tracking-wider mb-2 font-mono">Critical Risks</div>
                  <div className="text-4xl font-light text-red-400 font-mono">
                    {scanData.findings.filter(f => f.risk_score >= 70).length}
                  </div>
                </div>
                <div className="bg-core-surface p-6 rounded border border-core-border">
                  <div className="text-core-muted text-xs font-bold uppercase tracking-wider mb-2 font-mono">Status</div>
                  <div className="text-2xl font-light text-accent-verified capitalize mt-2 flex items-center gap-3 font-heading">
                    {scanData.status}
                    {scanData.status === 'completed' && <div className="w-2 h-2 rounded-full bg-accent-verified shadow-[0_0_8px_rgba(62,214,196,0.8)]"></div>}
                  </div>
                </div>
              </div>

              <div className="bg-core-surface overflow-hidden border border-core-border rounded">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-core-bg text-core-muted text-xs uppercase tracking-wider font-bold border-b border-core-border font-mono">
                      <th className="p-4 font-semibold">Vulnerability Rule</th>
                      <th className="p-4 font-semibold">Location</th>
                      <th className="p-4 font-semibold text-right">Risk Score</th>
                      <th className="p-4 font-semibold w-12"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-core-border">
                    {scanData.findings.length === 0 && (
                      <tr>
                        <td colSpan="4" className="p-12 text-center text-core-muted font-medium">
                          {scanData.status === 'running' ? 'Scanning in progress...' : 'Zero vulnerabilities detected.'}
                        </td>
                      </tr>
                    )}
                    {scanData.findings
                      .sort((a, b) => b.risk_score - a.risk_score)
                      .map((finding) => (
                      <tr 
                        key={finding.id}
                        className={`hover:bg-core-bg/50 transition-colors cursor-pointer group ${selectedFinding?.id === finding.id ? 'bg-core-bg/80' : ''}`}
                        onClick={() => setSelectedFinding(finding)}
                      >
                        <td className="p-4">
                          <div className="font-semibold text-core-text">{finding.rule_id.split('.').pop() || finding.rule_id}</div>
                          <div className="text-xs text-core-muted mt-1 truncate max-w-xs font-mono">{finding.rule_id}</div>
                        </td>
                        <td className="p-4">
                          <div className="text-xs font-mono text-core-muted bg-core-bg px-2 py-1 rounded border border-core-border inline-block w-fit">
                            {finding.file_path.split('\\').pop()}:{finding.line_number}
                          </div>
                        </td>
                        <td className="p-4 flex justify-end">
                          {getRiskBadge(finding.risk_score)}
                        </td>
                        <td className="p-4 text-core-muted group-hover:text-accent-verified transition-colors">
                          <ChevronRight size={18}/>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Slide-out Side Panel for Details */}
          {selectedFinding && (
            <div className="absolute top-0 right-0 w-full max-w-lg h-full bg-core-bg border-l border-core-border shadow-2xl z-20 animate-slide-in-right flex flex-col">
              <div className="p-6 border-b border-core-border flex justify-between items-center sticky top-0 bg-core-bg">
                <div className="flex items-center gap-3">
                  <Cpu size={20} className="text-accent-verified" />
                  <h3 className="font-bold text-white font-heading">AI Triage Details</h3>
                </div>
                <button 
                  onClick={() => setSelectedFinding(null)}
                  className="p-2 text-core-muted hover:text-white hover:bg-core-surface rounded transition-colors"
                >
                  <X size={20} />
                </button>
              </div>

              <div className="p-6 overflow-y-auto flex-1 space-y-8">
                <div className="bg-core-surface rounded p-5 border border-core-border">
                  <div className="text-xs text-core-muted font-bold uppercase tracking-wider mb-2 font-mono">Rule Triggered</div>
                  <div className="text-sm text-core-text font-mono break-all">{selectedFinding.rule_id}</div>
                  
                  <div className="mt-4 flex gap-6">
                    <div>
                      <div className="text-xs text-core-muted font-bold uppercase tracking-wider mb-2 font-mono">Risk Score</div>
                      {getRiskBadge(selectedFinding.risk_score)}
                    </div>
                    <div>
                      <div className="text-xs text-core-muted font-bold uppercase tracking-wider mb-2 font-mono">Confidence</div>
                      <span className="inline-block bg-core-bg border border-core-border px-2 py-0.5 rounded text-xs font-bold text-core-text font-mono">
                        {selectedFinding.confidence || 'N/A'}
                      </span>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className="text-xs font-bold text-core-muted uppercase tracking-wider mb-3 flex items-center gap-2 font-mono">
                    <div className="w-1.5 h-1.5 rounded-full bg-accent-signal"></div>
                    LLM Analysis
                  </h4>
                  <div className="text-sm text-core-text leading-relaxed bg-core-surface p-5 rounded border border-core-border">
                    {selectedFinding.explanation || 'No explanation provided.'}
                  </div>
                </div>

                <div>
                  <h4 className="text-xs font-bold text-core-muted uppercase tracking-wider mb-3 flex items-center gap-2 font-mono">
                    <div className="w-1.5 h-1.5 rounded-full bg-accent-verified"></div>
                    Recommended Fix
                  </h4>
                  <div className="text-sm text-accent-verified bg-accent-verified/10 p-5 rounded border border-accent-verified/20 leading-relaxed font-mono">
                    {selectedFinding.fix_recommendation || 'No fix recommended.'}
                  </div>
                  {selectedFinding.patch_replacement && (
                    <button 
                      onClick={() => fixedFindings[selectedFinding.id] ? null : triggerApplyFix(selectedFinding.id)}
                      disabled={fixedFindings[selectedFinding.id]}
                      className={`mt-4 w-full py-3 font-bold rounded flex items-center justify-center gap-2 transition-colors ${
                        fixedFindings[selectedFinding.id]
                          ? 'bg-core-bg border border-accent-verified text-accent-verified cursor-default'
                          : 'bg-accent-verified text-core-bg hover:bg-[#FCD386]'
                      }`}
                    >
                      <CheckCircle size={18} />
                      {fixedFindings[selectedFinding.id] ? 'Fix Applied Successfully' : 'Apply Fix to File'}
                    </button>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Custom Confirmation Modal */}
      {fixConfirmModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="bg-core-bg border border-core-border rounded-lg shadow-2xl p-8 max-w-md w-full mx-4">
            <div className="flex items-center gap-4 mb-4 text-accent-signal">
              <AlertTriangle size={32} />
              <h2 className="text-xl font-bold font-heading text-white">Apply Automated Fix?</h2>
            </div>
            <p className="text-core-muted text-sm mb-8 leading-relaxed">
              This will automatically modify the source code file on your disk. Are you sure you want to proceed?
            </p>
            <div className="flex gap-4 justify-end">
              <button 
                onClick={() => setFixConfirmModal(null)}
                className="px-6 py-2 rounded font-semibold text-sm border border-core-border text-core-muted hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button 
                onClick={confirmApplyFix}
                className="px-6 py-2 rounded font-semibold text-sm bg-accent-verified text-core-bg hover:bg-[#FCD386] transition-colors flex items-center gap-2"
              >
                <CheckCircle size={16}/> Confirm Fix
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Custom Error Modal */}
      {fixError && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="bg-core-bg border border-red-500/20 rounded-lg shadow-2xl p-8 max-w-md w-full mx-4">
            <div className="flex items-center gap-4 mb-4 text-red-400">
              <ShieldAlert size={32} />
              <h2 className="text-xl font-bold font-heading text-white">Action Failed</h2>
            </div>
            <p className="text-core-muted text-sm mb-8 leading-relaxed font-mono">
              {fixError}
            </p>
            <div className="flex justify-end">
              <button 
                onClick={() => setFixError(null)}
                className="px-6 py-2 rounded font-semibold text-sm bg-core-surface border border-core-border text-white hover:bg-core-border transition-colors"
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
    </>
  );
}
