import { useState, useEffect, useRef, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import axios from 'axios';
import {
  Shield, ShieldAlert, ShieldCheck, Play, Settings, Activity,
  FileCode, Bug, CheckCircle2, XCircle, Clock,
  ChevronRight, ChevronUp, Search, Loader2, Eye, BarChart3, FileText,
  RefreshCw, Zap, Server, FolderOpen, Folder, Cpu,
  MessageSquare, Sparkles, AlertTriangle
} from 'lucide-react';
import FlowGraph from './FlowGraph.jsx';

const API = '/api';

const PIPELINE_STEPS = [
  { key: 'OrchestratorAgent',    label: 'Orchestrator',  icon: FileCode },
  { key: 'VulnerabilityAgent',   label: 'Vulnerabilities', icon: ShieldAlert },
  { key: 'CodeQualityAgent',     label: 'Code Quality',  icon: Bug },
  { key: 'ReportAgent',          label: 'Report',        icon: FileText },
];

const PROMPT_EXAMPLES = [
  'Check for security vulnerabilities',
  'Find bugs and logical errors',
  'Suggest performance optimizations',
  'Full audit: security, bugs, and optimizations',
];

function severityColor(s) {
  switch ((s || '').toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    default: return '';
  }
}

// ── Inline diff helper ────────────────────────────────────────────────────
function computeDiff(before, after) {
  const a = (before || '').split('\n');
  const b = (after  || '').split('\n');
  const result = [];
  let ai = 0, bi = 0;
  while (ai < a.length || bi < b.length) {
    if (ai < a.length && bi < b.length && a[ai] === b[bi]) {
      result.push({ type: 'same', text: a[ai] }); ai++; bi++;
    } else if (ai < a.length && (bi >= b.length || !b.includes(a[ai]))) {
      result.push({ type: 'removed', text: a[ai] }); ai++;
    } else {
      result.push({ type: 'added', text: b[bi] }); bi++;
    }
  }
  return result;
}

// ── FindingCard component ─────────────────────────────────────────────────
function FindingCard({ finding, index, type }) {
  const [expanded, setExpanded] = useState(false);
  const [section, setSection] = useState('code');

  const severity    = finding.severity || finding.priority || 'info';
  const label       = finding.title || finding.id || `Finding ${index + 1}`;
  const currentCode = finding.current_code || finding.code_snippet || '';
  const fixedCode   = finding.fixed_code || '';
  const hasCurrent  = !!currentCode;
  const hasFixed    = !!fixedCode;
  const diff        = (hasCurrent && hasFixed) ? computeDiff(currentCode, fixedCode) : [];

  return (
    <div className={`finding-card${expanded ? ' expanded' : ''}`}>
      <div className="finding-card-header" onClick={() => setExpanded(e => !e)}>
        <span className={`severity-badge ${severityColor(severity)}`}>{severity.toUpperCase()}</span>
        <span className="finding-card-title">{label}</span>
        {finding.file && (
          <span className="finding-card-file">{finding.file}{finding.line_number ? `:${finding.line_number}` : ''}</span>
        )}
        <span className={`expand-icon${expanded ? ' rotated' : ''}`}>&#9654;</span>
      </div>

      {expanded && (
        <div className="finding-card-body">
          {/* Section tabs */}
          <div className="finding-section-tabs">
            <button className={section === 'code'        ? 'active' : ''} onClick={() => setSection('code')}>Code &amp; Fix</button>
            <button className={section === 'description' ? 'active' : ''} onClick={() => setSection('description')}>Description</button>
            {diff.length > 0 && <button className={section === 'diff' ? 'active' : ''} onClick={() => setSection('diff')}>Diff</button>}
          </div>

          {/* Code & Fix — shown by default */}
          {section === 'code' && (
            <div className="finding-section-content">
              {hasCurrent ? (
                <>
                  <p className="code-label code-label-current">&#10006; Vulnerable / Buggy Code</p>
                  <pre className="code-block code-block-current"><code>{currentCode}</code></pre>
                </>
              ) : (
                <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No code snippet available for this finding.</p>
              )}
              {hasFixed ? (
                <>
                  <p className="code-label code-label-fixed" style={{ marginTop: 12 }}>&#10004; Fixed Code</p>
                  <pre className="code-block code-block-fixed"><code>{fixedCode}</code></pre>
                </>
              ) : (
                <p style={{ color: 'var(--text-muted)', fontSize: 13, marginTop: 8, fontStyle: 'italic' }}>
                  Fix suggestion not available — see Description for manual remediation.
                </p>
              )}
              {finding.fix_explanation && (
                <div className="fix-explanation" style={{ marginTop: 10 }}>
                  <strong>How to fix:</strong> {finding.fix_explanation}
                </div>
              )}
            </div>
          )}

          {section === 'description' && (
            <div className="finding-section-content">
              {finding.owasp_category && <p><strong>OWASP:</strong> {finding.owasp_category}</p>}
              {finding.category && <p><strong>Category:</strong> {finding.category}</p>}
              <p style={{ marginTop: 8, lineHeight: 1.7 }}>{finding.description}</p>
              {finding.fix_explanation && (
                <div className="fix-explanation">
                  <strong>Fix Explanation:</strong> {finding.fix_explanation}
                </div>
              )}
            </div>
          )}

          {section === 'diff' && (
            <div className="finding-section-content">
              <p className="code-label">Unified Diff</p>
              <div className="diff-view">
                {diff.map((line, i) => (
                  <div key={i} className={`diff-line ${line.type === 'removed' ? 'diff-removed' : line.type === 'added' ? 'diff-added' : 'diff-same'}`}>
                    <span className="diff-marker">{line.type === 'removed' ? '-' : line.type === 'added' ? '+' : ' '}</span>
                    <code>{line.text}</code>
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

export default function App() {
  const [projectPath, setProjectPath] = useState('sample_vulnerable_app');
  const [userPrompt, setUserPrompt] = useState('');
  const [scanning, setScanning] = useState(false);
  const [sessionId, setSessionId] = useState(null);
  const [pipelineSteps, setPipelineSteps] = useState({});
  const [result, setResult] = useState(null);
  const [activeTab, setActiveTab] = useState('vulnerabilities');
  const [ollamaConnected, setOllamaConnected] = useState(false);
  const [modelName, setModelName] = useState('');
  const [showSettings, setShowSettings] = useState(false);
  const [settingsModel, setSettingsModel] = useState('');
  const [settingsUrl, setSettingsUrl] = useState('');
  const [error, setError] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [showBrowser, setShowBrowser] = useState(false);
  const [browserCurrent, setBrowserCurrent] = useState('');
  const [browserParent, setBrowserParent] = useState(null);
  const [browserEntries, setBrowserEntries] = useState([]);
  const [browserLoading, setBrowserLoading] = useState(false);
  const eventSourceRef = useRef(null);
  const pipelineDoneRef = useRef(false);
  const fetchResultRef = useRef(null);

  // Health check
  const checkHealth = useCallback(async () => {
    try {
      const { data } = await axios.get(`${API}/health`);
      setOllamaConnected(data.ollama_connected);
      setModelName(data.model);
    } catch {
      setOllamaConnected(false);
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, [checkHealth]);

  // Load config
  const loadConfig = useCallback(async () => {
    try {
      const { data } = await axios.get(`${API}/config`);
      setSettingsModel(data.ollama_model || '');
      setSettingsUrl(data.ollama_base_url || '');
    } catch { /* ignore */ }
  }, []);

  // Backup polling: independent of SSE — catches results even if SSE fails completely
  useEffect(() => {
    if (!scanning || !sessionId) return;
    const interval = setInterval(async () => {
      // SSE already handled it; don't duplicate the work
      if (pipelineDoneRef.current) return;
      try {
        const { data } = await axios.get(`${API}/audit/${sessionId}`);
        if (data.status !== 'running') {
          pipelineDoneRef.current = true;
          if (eventSourceRef.current) eventSourceRef.current.close();
          setResult(data);
          setScanning(false);
          setError(null);
        }
      } catch { /* ignore transient errors; SSE or fetchResult handles persistent failures */ }
    }, 10000); // Poll every 10 s as a safety net
    return () => clearInterval(interval);
  }, [scanning, sessionId]);

  // Save config
  const saveConfig = async () => {
    try {
      await axios.put(`${API}/config`, { ollama_model: settingsModel });
      setModelName(settingsModel);
      setShowSettings(false);
      checkHealth();
    } catch (e) {
      alert('Failed to save config: ' + (e.response?.data?.detail || e.message));
    }
  };

  // SSE stream
  const connectSSE = useCallback((sid, reconnectAttempt = 0) => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }
    if (reconnectAttempt === 0) {
      pipelineDoneRef.current = false;
    }

    const evtSource = new EventSource(`${API}/audit/${sid}/events`);
    eventSourceRef.current = evtSource;

    evtSource.onmessage = (e) => {
      let evt;
      try {
        evt = JSON.parse(e.data);
      } catch {
        return; // ignore malformed events
      }
      const { type, data } = evt;

      if (type === 'heartbeat') {
        return; // keep-alive, nothing to do
      } else if (type === 'agent_start') {
        setPipelineSteps(prev => ({ ...prev, [data.agent]: 'active' }));
      } else if (type === 'agent_complete') {
        setPipelineSteps(prev => ({
          ...prev,
          [data.agent]: data.trace?.status === 'error' ? 'error' : 'complete'
        }));
      } else if (type === 'pipeline_complete') {
        pipelineDoneRef.current = true;
        evtSource.close();
        // Use ref so we always call the latest fetchResult
        if (fetchResultRef.current) fetchResultRef.current(sid);
      } else if (type === 'pipeline_error') {
        pipelineDoneRef.current = true;
        evtSource.close();
        setError(data.error || 'Pipeline failed');
        setScanning(false);
      }
    };

    evtSource.onerror = () => {
      evtSource.close();
      // If pipeline already finished (naturally or via error event), stop.
      if (pipelineDoneRef.current) return;
      // Reconnect up to 3 times before giving up and polling for the result.
      if (reconnectAttempt < 3) {
        setTimeout(() => connectSSE(sid, reconnectAttempt + 1), 2000 * (reconnectAttempt + 1));
      } else {
        // Could not reconnect — try to fetch whatever result is available.
        if (fetchResultRef.current) fetchResultRef.current(sid);
      }
    };
  }, []);

  const fetchResult = useCallback(async (sid, attempt = 0) => {
    try {
      const { data } = await axios.get(`${API}/audit/${sid}`);
      // If the audit is still running, wait and retry (each agent can take several minutes)
      if (data.status === 'running') {
        if (attempt < 90) {
          // Poll every 5s for first 12 attempts, then every 10s (covers up to ~13 min total)
          const delay = attempt < 12 ? 5000 : 10000;
          setTimeout(() => fetchResultRef.current?.(sid, attempt + 1), delay);
          return;
        } else {
          // Exceeded polling budget — pipeline is likely stuck
          setError('Audit is taking too long. The pipeline may be stuck. Please check the server logs.');
          setScanning(false);
          return;
        }
      }
      // Mark agents that didn't run as 'skipped' so FlowGraph shows the correct path
      const ranNames = new Set((data.agent_traces || []).map(t => t.agent_name));
      setPipelineSteps(prev => {
        const updated = { ...prev };
        ['OrchestratorAgent', 'VulnerabilityAgent', 'CodeQualityAgent', 'ReportAgent'].forEach(name => {
          if (!ranNames.has(name) && updated[name] !== 'complete' && updated[name] !== 'error') {
            updated[name] = 'skipped';
          }
        });
        return updated;
      });
      setResult(data);
      setScanning(false);
      setError(null);
    } catch (e) {
      if (attempt < 6) {
        // Retry up to 6 times with increasing delay (handles brief server reloads)
        setTimeout(() => fetchResultRef.current?.(sid, attempt + 1), 2000 * (attempt + 1));
      } else {
        const status = e.response?.status;
        const detail = e.response?.data?.detail || e.message;
        setError(
          status === 404
            ? 'Session not found — the server may have restarted. Please run the scan again.'
            : `Failed to fetch result (HTTP ${status || 'network error'}): ${detail}`
        );
        setScanning(false);
      }
    }
  }, []);

  // Keep the ref in sync with the latest fetchResult so connectSSE always calls it
  fetchResultRef.current = fetchResult;

  const startScan = async () => {
    if (!projectPath.trim()) return;
    setScanning(true);
    setResult(null);
    setError(null);
    setPipelineSteps({});

    try {
      const { data } = await axios.post(`${API}/audit`, {
        project_path: projectPath.trim(),
        user_prompt: userPrompt.trim() || 'Perform a full security audit, find bugs, and suggest optimizations.',
      });
      setSessionId(data.session_id);
      connectSSE(data.session_id);
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
      setScanning(false);
    }
  };

  const loadSession = async (sid) => {
    try {
      const { data } = await axios.get(`${API}/audit/${sid}`);
      setResult(data);
      setSessionId(sid);
      setShowHistory(false);
      setActiveTab('vulnerabilities');
      // Reconstruct pipeline status — mark agents that didn't run as skipped
      const steps = {};
      const ranNames = new Set();
      (data.agent_traces || []).forEach(t => {
        ranNames.add(t.agent_name);
        steps[t.agent_name] = t.status === 'error' ? 'error' : 'complete';
      });
      ['OrchestratorAgent', 'VulnerabilityAgent', 'CodeQualityAgent', 'ReportAgent'].forEach(name => {
        if (!ranNames.has(name)) steps[name] = 'skipped';
      });
      setPipelineSteps(steps);
    } catch (e) {
      setError('Failed to load session');
    }
  };

  const fetchSessions = async () => {
    try {
      const { data } = await axios.get(`${API}/sessions`);
      setSessions(data);
      setShowHistory(true);
    } catch { /* ignore */ }
  };

  const isAbsolutePath = (p) =>
    p && (p.startsWith('/') || /^[A-Za-z]:[\\//]/.test(p));

  const openBrowser = async (path = '') => {
    setBrowserLoading(true);
    setShowBrowser(true);
    setBrowserEntries([]);
    // Use an absolute path as-is; for relative paths start at server CWD
    const resolvedPath = isAbsolutePath(path) ? path : '';
    try {
      const { data } = await axios.get(`${API}/browse`,
        { params: resolvedPath ? { path: resolvedPath } : {} });
      setBrowserCurrent(data.current);
      setBrowserParent(data.parent);
      setBrowserEntries(data.entries);
    } catch (e) {
      console.error('Browse error', e);
      setBrowserCurrent('(error loading directory)');
      setBrowserParent(null);
      setBrowserEntries([]);
    } finally {
      setBrowserLoading(false);
    }
  };

  const selectBrowserFolder = () => {
    setProjectPath(browserCurrent);
    setShowBrowser(false);
  };

  // Stats
  const rawSev = result?.severity_summary || {};
  const sevSummary = Object.fromEntries(
    Object.entries(rawSev).map(([k, v]) => [k.toLowerCase(), v])
  );
  const vulnCount = result?.vulnerabilities?.length || 0;
  const bugCount  = result?.bugs?.length || 0;

  return (
    <>
      {/* Header */}
      <header className="header">
        <div className="header-left">
          <div className="header-logo"><Shield size={20} color="#fff" /></div>
          <div>
            <div className="header-title">Code Security Auditor</div>
            <div className="header-subtitle">Multi-Agent Security Analysis System</div>
          </div>
        </div>
        <div className="header-right">
          <div className={`status-badge ${ollamaConnected ? 'connected' : 'disconnected'}`}>
            <span className="status-dot" />
            {ollamaConnected ? `Ollama · ${modelName}` : 'Ollama Offline'}
          </div>
          <button className="btn btn-secondary btn-sm" onClick={() => { loadConfig(); setShowSettings(true); }}>
            <Settings size={14} /> Settings
          </button>
          <button className="btn btn-secondary btn-sm" onClick={fetchSessions}>
            <Clock size={14} /> History
          </button>
        </div>
      </header>

      <main className="main-content">
        {/* Scan Input */}
        <div className="scan-section fade-in">
          <div className="card">
            <div className="card-header">
              <div className="card-title"><Search size={18} /> Security Scan</div>
            </div>

            {/* Path row */}
            <div className="input-group" style={{ marginBottom: 14 }}>
              <input
                className="input-field"
                value={projectPath}
                onChange={(e) => setProjectPath(e.target.value)}
                placeholder="Enter project path or use Browse"
                onKeyDown={(e) => e.key === 'Enter' && !scanning && startScan()}
                disabled={scanning}
              />
              <button className="btn btn-secondary" onClick={() => openBrowser(projectPath)} disabled={scanning} title="Browse for folder">
                <FolderOpen size={16} /> Browse
              </button>
            </div>

            {/* Prompt area */}
            <div className="prompt-area">
              <div className="prompt-label">
                <Sparkles size={14} />
                <span>Tell the Coordinator what to analyse</span>
              </div>
              <textarea
                className="input-field prompt-textarea"
                value={userPrompt}
                onChange={(e) => setUserPrompt(e.target.value)}
                placeholder="e.g. Check for security vulnerabilities and suggest optimizations"
                rows={2}
                disabled={scanning}
              />
              <div className="prompt-examples">
                {PROMPT_EXAMPLES.map((ex) => (
                  <button
                    key={ex}
                    className="prompt-chip"
                    onClick={() => setUserPrompt(ex)}
                    disabled={scanning}
                  >
                    {ex}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 14 }}>
              <button className="btn btn-primary" onClick={startScan} disabled={scanning || !ollamaConnected}>
                {scanning ? <><Loader2 size={16} className="spinner" /> Scanning...</> : <><Play size={16} /> Start Audit</>}
              </button>
            </div>

            {!ollamaConnected && (
              <p style={{ marginTop: 8, fontSize: 13, color: 'var(--danger)' }}>
                Ollama is not connected. Please start Ollama first.
              </p>
            )}
          </div>
        </div>

        {/* Error */}
        {error && (
          <div className="card fade-in" style={{ marginBottom: 24, borderColor: 'var(--danger)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--danger)' }}>
              <XCircle size={20} />
              <div>
                <strong>Error</strong>
                <p style={{ margin: 0, fontSize: 13, color: 'var(--text-secondary)' }}>{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Live Flow Graph — shown while scanning AND as static result when done */}
        {(scanning || result) && (
          <div className="card fade-in flow-graph-card">
            <div className="card-header" style={{ marginBottom: 12 }}>
              <div className="card-title">
                <Cpu size={18} /> LangGraph Pipeline
                {scanning && <span style={{ fontSize: 12, fontWeight: 400, color: 'var(--text-muted)', marginLeft: 8 }}>live</span>}
              </div>
  
            </div>
            <FlowGraph
              pipelineSteps={pipelineSteps}
            />
          </div>
        )}

        {/* Results */}
        {result && result.status !== 'running' && !scanning && (
          <>
            {/* Stats Grid */}
            <div className="stats-grid fade-in">
              <div className="stat-card total">
                <div className="stat-value">{vulnCount}</div>
                <div className="stat-label">Vulnerabilities</div>
              </div>
              <div className="stat-card critical">
                <div className="stat-value">{sevSummary.critical || 0}</div>
                <div className="stat-label">Critical</div>
              </div>
              <div className="stat-card high">
                <div className="stat-value">{sevSummary.high || 0}</div>
                <div className="stat-label">High</div>
              </div>
              <div className="stat-card medium">
                <div className="stat-value" style={{ color: 'var(--warning)' }}>{bugCount}</div>
                <div className="stat-label">Bugs Found</div>
              </div>
            </div>

            {/* Tabs */}
            <div className="tabs fade-in">
              <button className={`tab ${activeTab === 'vulnerabilities' ? 'active' : ''}`} onClick={() => setActiveTab('vulnerabilities')}>
                <Bug size={13} style={{ marginRight: 6, verticalAlign: -2 }} /> Vulnerabilities {vulnCount > 0 && <span className="tab-badge">{vulnCount}</span>}
              </button>
              <button className={`tab ${activeTab === 'bugs' ? 'active' : ''}`} onClick={() => setActiveTab('bugs')}>
                <MessageSquare size={13} style={{ marginRight: 6, verticalAlign: -2 }} /> Bugs {bugCount > 0 && <span className="tab-badge">{bugCount}</span>}
              </button>
              <button className={`tab ${activeTab === 'agents' ? 'active' : ''}`} onClick={() => setActiveTab('agents')}>
                <Activity size={13} style={{ marginRight: 6, verticalAlign: -2 }} /> Agent Traces
              </button>
              <button className={`tab ${activeTab === 'report' ? 'active' : ''}`} onClick={() => setActiveTab('report')}>
                <FileText size={13} style={{ marginRight: 6, verticalAlign: -2 }} /> Full Report
              </button>
              <button className={`tab ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>
                <BarChart3 size={13} style={{ marginRight: 6, verticalAlign: -2 }} /> Overview
              </button>
            </div>

            {/* Vulnerabilities Tab */}
            {activeTab === 'vulnerabilities' && (
              <div className="card fade-in">
                <div className="card-header">
                  <div className="card-title"><ShieldAlert size={18} /> Detected Vulnerabilities</div>
                  <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>{vulnCount} found</span>
                </div>
                {vulnCount === 0 ? (
                  <div className="empty-state">
                    <ShieldCheck size={48} style={{ color: 'var(--success)', opacity: 0.5 }} />
                    <h2>No Vulnerabilities Found</h2>
                    <p>The scanned project appears to be secure.</p>
                  </div>
                ) : (
                  <div className="findings-list">
                    {(result.vulnerabilities || []).map((v, i) => (
                      <FindingCard key={i} finding={v} index={i} type="vulnerability" />
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Bugs Tab */}
            {activeTab === 'bugs' && (
              <div className="card fade-in">
                <div className="card-header">
                  <div className="card-title"><MessageSquare size={18} /> Bug Findings</div>
                  <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>{bugCount} found</span>
                </div>
                {bugCount === 0 ? (
                  <div className="empty-state">
                    <CheckCircle2 size={48} style={{ color: 'var(--success)', opacity: 0.5 }} />
                    <h2>No Bugs Detected</h2>
                    <p>No logical errors or runtime issues were found.</p>
                  </div>
                ) : (
                  <div className="findings-list">
                    {(result.bugs || []).map((b, i) => (
                      <FindingCard key={i} finding={b} index={i} type="bug" />
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Agent Traces Tab */}
            {activeTab === 'agents' && (
              <div className="card fade-in">
                <div className="card-header">
                  <div className="card-title"><Activity size={18} /> Agent Execution Timeline</div>
                </div>
                <div className="trace-timeline">
                  {(result.agent_traces || []).map((t, i) => (
                    <div className="trace-item" key={i}>
                      <div className={`trace-icon ${t.status === 'error' ? 'error' : 'success'}`}>
                        {t.status === 'error' ? <XCircle size={18} /> : <CheckCircle2 size={18} />}
                      </div>
                      <div className="trace-info">
                        <div className="trace-name">{t.agent_name}</div>
                        <div className="trace-summary">{t.output_summary || 'Completed'}</div>
                      </div>
                      <div className="trace-meta">
                        <span><Clock size={12} style={{ verticalAlign: -2, marginRight: 4 }} />{(t.duration_seconds || 0).toFixed(1)}s</span>
                        <span><Zap size={12} style={{ verticalAlign: -2, marginRight: 4 }} />{(t.tool_calls || []).length} tools</span>
                      </div>
                    </div>
                  ))}
                  {(!result.agent_traces || result.agent_traces.length === 0) && (
                    <div className="empty-state"><p>No agent trace data available.</p></div>
                  )}
                </div>
              </div>
            )}

            {/* Report Tab */}
            {activeTab === 'report' && (
              <div className="card fade-in">
                <div className="card-header">
                  <div className="card-title"><FileText size={18} /> Security Report</div>
                </div>
                {result.full_report ? (
                  <div className="report-view">
                    <ReactMarkdown>{result.full_report}</ReactMarkdown>
                  </div>
                ) : (
                  <div className="empty-state"><p>No report content available.</p></div>
                )}
              </div>
            )}

            {/* Overview Tab */}
            {activeTab === 'overview' && (
              <div className="grid-2 fade-in">
                <div className="card">
                  <div className="card-title"><FileCode size={18} /> Project Info</div>
                  <div style={{ marginTop: 16, fontSize: 14 }}>
                    <p><strong>Path:</strong> <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--info)' }}>{result.project_path}</span></p>
                    <p style={{ marginTop: 8 }}><strong>Files Scanned:</strong> {result.code_structure?.file_count || 0}</p>
                    <p style={{ marginTop: 8 }}><strong>Total Lines:</strong> {result.code_structure?.total_lines || 0}</p>
                    <p style={{ marginTop: 8 }}><strong>Languages:</strong> {(result.code_structure?.languages || []).join(', ') || 'N/A'}</p>
                    <p style={{ marginTop: 8 }}><strong>Frameworks:</strong> {(result.code_structure?.frameworks || []).join(', ') || 'N/A'}</p>
                  </div>
                </div>
                <div className="card">
                  <div className="card-title"><BarChart3 size={18} /> Risk Matrix</div>
                  <div style={{ marginTop: 16, fontSize: 14 }}>
                    {result.risk_matrix && Object.keys(result.risk_matrix).length > 0 ? (
                      Object.entries(result.risk_matrix).map(([cat, level]) => (
                        <div key={cat} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                          <span>{cat}</span>
                          <span className={`severity-badge ${severityColor(String(level))}`}>{String(level)}</span>
                        </div>
                      ))
                    ) : (
                      <p style={{ color: 'var(--text-muted)' }}>No risk matrix data.</p>
                    )}
                  </div>
                </div>
                {result.executive_summary && (
                  <div className="card grid-full">
                    <div className="card-title"><Eye size={18} /> Executive Summary</div>
                    <p style={{ marginTop: 12, fontSize: 14, lineHeight: 1.7, color: 'var(--text-secondary)' }}>
                      {result.executive_summary}
                    </p>
                  </div>
                )}
              </div>
            )}
          </>
        )}

        {/* Empty State */}
        {!scanning && !result && !error && (
          <div className="empty-state fade-in">
            <div className="empty-state-icon"><Shield size={56} /></div>
            <h2>Ready to Scan</h2>
            <p>Enter a project path above and click Start Audit to begin the multi-agent security analysis.</p>
          </div>
        )}
      </main>

      {/* Settings Modal */}
      {showSettings && (
        <div className="modal-overlay" onClick={() => setShowSettings(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-title"><Settings size={20} style={{ verticalAlign: -4, marginRight: 8 }} />Settings</div>
            <label className="modal-label">Ollama Model</label>
            <input
              className="input-field"
              style={{ width: '100%', marginBottom: 12 }}
              value={settingsModel}
              onChange={(e) => setSettingsModel(e.target.value)}
              placeholder="e.g., llama3.2:3b"
            />
            <label className="modal-label">Ollama Base URL</label>
            <input
              className="input-field"
              style={{ width: '100%' }}
              value={settingsUrl}
              disabled
              placeholder="http://localhost:11434"
            />
            <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
              Edit config.json directly to change the base URL.
            </p>
            <div className="modal-actions">
              <button className="btn btn-secondary btn-sm" onClick={() => setShowSettings(false)}>Cancel</button>
              <button className="btn btn-primary btn-sm" onClick={saveConfig}>Save</button>
            </div>
          </div>
        </div>
      )}

      {/* Folder Browser Modal */}
      {showBrowser && (
        <div className="modal-overlay" onClick={() => setShowBrowser(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 560, width: '90vw' }}>
            <div className="modal-title"><FolderOpen size={20} style={{ verticalAlign: -4, marginRight: 8 }} />Browse for Folder</div>

            {/* Current path breadcrumb */}
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--info)', background: 'var(--bg-secondary)', padding: '8px 12px', borderRadius: 'var(--radius-sm)', marginBottom: 12, wordBreak: 'break-all' }}>
              {browserCurrent || '…'}
            </div>

            {/* Up button */}
            {browserParent && (
              <button
                className="btn btn-secondary btn-sm"
                style={{ marginBottom: 10, width: '100%', justifyContent: 'flex-start' }}
                onClick={() => openBrowser(browserParent)}
              >
                <ChevronUp size={14} /> .. (up one level)
              </button>
            )}

            {/* Directory list */}
            <div style={{ maxHeight: 320, overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)' }}>
              {browserLoading ? (
                <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)' }}>
                  <Loader2 size={20} className="spinner" style={{ marginRight: 8 }} /> Loading…
                </div>
              ) : browserEntries.length === 0 ? (
                <div style={{ padding: 16, color: 'var(--text-muted)', fontSize: 13, textAlign: 'center' }}>No subfolders here</div>
              ) : (
                browserEntries.map((entry) => (
                  <div
                    key={entry.path}
                    onClick={() => openBrowser(entry.path)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '10px 14px', cursor: 'pointer',
                      borderBottom: '1px solid var(--border)',
                      fontSize: 14, transition: 'background 0.15s',
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-secondary)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                  >
                    <Folder size={15} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                    {entry.name}
                  </div>
                ))
              )}
            </div>

            <div className="modal-actions" style={{ marginTop: 16 }}>
              <button className="btn btn-secondary btn-sm" onClick={() => setShowBrowser(false)}>Cancel</button>
              <button className="btn btn-primary btn-sm" onClick={selectBrowserFolder}>
                <CheckCircle2 size={14} /> Select This Folder
              </button>
            </div>
          </div>
        </div>
      )}

      {/* History Modal */}
      {showHistory && (
        <div className="modal-overlay" onClick={() => setShowHistory(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 600 }}>
            <div className="modal-title"><Clock size={20} style={{ verticalAlign: -4, marginRight: 8 }} />Scan History</div>
            {sessions.length === 0 ? (
              <p style={{ color: 'var(--text-muted)', fontSize: 14 }}>No previous scans found.</p>
            ) : (
              <div style={{ maxHeight: 400, overflowY: 'auto' }}>
                {sessions.map((s) => (
                  <div
                    key={s.session_id}
                    style={{
                      padding: '12px 16px', borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border)', marginBottom: 8,
                      cursor: 'pointer', transition: 'border-color 0.2s',
                    }}
                    onClick={() => loadSession(s.session_id)}
                    onMouseEnter={(e) => e.currentTarget.style.borderColor = 'var(--accent)'}
                    onMouseLeave={(e) => e.currentTarget.style.borderColor = 'var(--border)'}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--info)' }}>
                        {s.project_path}
                      </span>
                      <span className={`severity-badge ${s.status === 'complete' ? 'low' : s.status === 'error' ? 'critical' : 'medium'}`}>
                        {s.status}
                      </span>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
                      {s.started_at ? new Date(s.started_at).toLocaleString() : ''} · {s.vulnerability_count || 0} vulnerabilities
                    </div>
                  </div>
                ))}
              </div>
            )}
            <div className="modal-actions">
              <button className="btn btn-secondary btn-sm" onClick={() => setShowHistory(false)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
