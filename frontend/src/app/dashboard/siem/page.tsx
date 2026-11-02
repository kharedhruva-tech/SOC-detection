'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { 
  Database, 
  Search, 
  Cpu, 
  Copy, 
  Check, 
  FileCode, 
  Play, 
  Plus, 
  Activity, 
  Loader2, 
  Sliders, 
  X, 
  Eye, 
  ExternalLink,
  Flame,
  AlertTriangle,
  ShieldCheck,
  RotateCcw
} from 'lucide-react';
import { api } from '@/utils/api';

export default function SIEMLogs() {
  const [logs, setLogs] = useState<any[]>([]);
  const [rules, setRules] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [activeTab, setActiveTab] = useState<'logs' | 'correlation' | 'ai-generator'>('logs');
  
  // Selected Event Detail Inspector
  const [selectedEvent, setSelectedEvent] = useState<any | null>(null);

  // Rule Generator Form States
  const [ruleType, setRuleType] = useState<'sigma' | 'yara'>('sigma');
  const [title, setTitle] = useState('Detect Suspicious Curl Download');
  const [description, setDescription] = useState('Detects execution of curl pulling payloads from external domains.');
  const [targetImage, setTargetImage] = useState('curl.exe');
  const [targetCmd, setTargetCmd] = useState('-O http://');
  const [generatedRule, setGeneratedRule] = useState('');
  const [loadingRule, setLoadingRule] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    fetchLogsAndRules();
  }, []);

  const fetchLogsAndRules = async () => {
    try {
      setLoading(true);
      const [alertsData, rulesData] = await Promise.all([
        api.get('/alerts/').catch(() => []),
        api.get('/detection-rules/').catch(() => [])
      ]);
      setLogs(alertsData);
      setRules(rulesData);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoadingRule(true);
    setGeneratedRule('');
    try {
      if (ruleType === 'sigma') {
        const rule = (
          `title: ${title}\n` +
          `id: ${Math.floor(Math.random() * 10000000).toString(16)}-abcd-ef12-3456-7890abcdef12\n` +
          `status: production\n` +
          `description: ${description}\n` +
          `author: Aegis SIEM Threat Team\n` +
          `date: ${new Date().toISOString().slice(0, 10)}\n` +
          `references:\n` +
          `    - Internal SOC Detection Matrix\n` +
          `tags:\n` +
          `    - attack.execution\n` +
          `    - attack.t1059\n` +
          `logsource:\n` +
          `    product: windows\n` +
          `    service: sysmon\n` +
          `detection:\n` +
          `    selection:\n` +
          `        Image|endswith: '\\${targetImage}'\n` +
          (targetCmd ? `        CommandLine|contains: '${targetCmd}'\n` : '') +
          `    condition: selection\n` +
          `falsepositives:\n` +
          `    - Verified administrative operations\n` +
          `level: medium`
        );
        setGeneratedRule(rule);
      } else {
        const indicators = targetCmd ? [targetCmd, targetImage] : [targetImage];
        const cleanName = title.replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_]/g, '');
        const rule = (
          `rule AI_Detect_${cleanName} {\n` +
          `    meta:\n` +
          `        description = "${description}"\n` +
          `        author = "Aegis AI Analyst"\n` +
          `        date = "${new Date().toISOString().slice(0, 10)}"\n` +
          `        severity = "medium"\n\n` +
          `    strings:\n` +
          indicators.map((ind, i) => `        $s${i} = "${ind}" ascii wide nocase`).join('\n') + '\n' +
          `\n    condition:\n` +
          `        all of them\n` +
          `}`
        );
        setGeneratedRule(rule);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingRule(false);
    }
  };

  const handleCopyRule = () => {
    if (!generatedRule) return;
    navigator.clipboard.writeText(generatedRule);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const filteredLogs = logs.filter((log) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      log.title?.toLowerCase().includes(q) ||
      log.category?.toLowerCase().includes(q) ||
      log.rule_id?.toLowerCase().includes(q) ||
      (log.source_ip && log.source_ip.includes(q)) ||
      (log.description && log.description.toLowerCase().includes(q));

    const matchesSeverity =
      severityFilter === 'All' || log.severity?.toLowerCase() === severityFilter.toLowerCase();

    return matchesSearch && matchesSeverity;
  });

  const getSeverityBadge = (severity: string) => {
    const s = severity?.toLowerCase();
    if (s === 'critical') {
      return (
        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-rose-950/40 text-rose-400 border border-rose-500/40 inline-flex items-center gap-1">
          <Flame className="w-3 h-3" /> Critical
        </span>
      );
    }
    if (s === 'high') {
      return (
        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-amber-950/40 text-amber-400 border border-amber-500/40 inline-flex items-center gap-1">
          <AlertTriangle className="w-3 h-3" /> High
        </span>
      );
    }
    if (s === 'medium') {
      return (
        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-yellow-950/30 text-yellow-300 border border-yellow-500/40 inline-flex items-center gap-1">
          <Activity className="w-3 h-3" /> Medium
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 text-xs font-semibold rounded bg-sky-950/30 text-sky-300 border border-sky-500/40 inline-flex items-center gap-1">
        <ShieldCheck className="w-3 h-3" /> Low
      </span>
    );
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto font-sans">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center text-cyan-400">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white font-sans">
                SIEM Log Engine & Event Pipeline
              </h1>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Normalized Telemetry Ingestion · Real-time Parser Pipeline · Sigma & YARA Generation
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={fetchLogsAndRules}
          className="px-3 py-2 text-xs font-mono bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 rounded flex items-center gap-2 transition cursor-pointer self-start sm:self-auto"
        >
          <RotateCcw className="w-3.5 h-3.5" /> Refresh Telemetry
        </button>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 bg-[#0a0e1c] px-4 rounded-t-xl gap-2">
        {[
          { id: 'logs', name: `Normalized Events (${filteredLogs.length})`, icon: Database },
          { id: 'correlation', name: `Correlation Rules (${rules.length || 10})`, icon: Sliders },
          { id: 'ai-generator', name: 'Sigma & YARA Rule Generator', icon: Cpu }
        ].map((tab) => {
          const Icon = tab.icon;
          const isCurrent = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`py-3 px-4 border-b-2 font-mono text-xs flex items-center gap-2 transition-all cursor-pointer ${
                isCurrent
                  ? 'border-cyan-400 text-cyan-300 font-bold bg-cyan-500/10'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-850/50'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.name}</span>
            </button>
          );
        })}
      </div>

      {/* Tab 1: Log Search & Event Stream */}
      {activeTab === 'logs' && (
        <div className="space-y-4">
          {/* Search & Filter Bar */}
          <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
            <div className="relative w-full sm:w-96">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by event title, IP, category, rule ID..."
                className="w-full bg-slate-900/90 border border-slate-800 rounded-lg py-2 pl-9 pr-4 text-xs text-white focus:outline-none focus:border-cyan-400 font-mono transition"
              />
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto font-mono text-xs">
              <span className="text-slate-400 hidden sm:inline">Severity:</span>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="px-3 py-2 bg-slate-900 border border-slate-800 rounded text-slate-200 focus:border-cyan-400 outline-none w-full sm:w-auto"
              >
                <option value="All">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
          </div>

          {/* Log Table */}
          <div className="cyber-card p-0 border border-slate-800 overflow-hidden bg-[#0a0d24]">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/80 text-slate-400 uppercase tracking-widest text-[10px] border-b border-slate-800">
                <tr>
                  <th className="p-4">Timestamp</th>
                  <th className="p-4">Rule / Source</th>
                  <th className="p-4">Event Title</th>
                  <th className="p-4">Category</th>
                  <th className="p-4">Severity</th>
                  <th className="p-4 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {loading ? (
                  <tr>
                    <td colSpan={6} className="p-8 text-center text-slate-500">
                      <div className="w-6 h-6 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
                      Loading normalized telemetry...
                    </td>
                  </tr>
                ) : filteredLogs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-8 text-center text-slate-500">
                      No security events match query filter.
                    </td>
                  </tr>
                ) : (
                  filteredLogs.map((log, idx) => (
                    <tr
                      key={`${log.id || log.event_id || 'log'}-${idx}`}
                      onClick={() => setSelectedEvent(log)}
                      className="hover:bg-slate-800/40 text-slate-300 transition-colors cursor-pointer group"
                    >
                      <td className="p-4 whitespace-nowrap text-slate-400">
                        {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : 'Recent'}
                      </td>
                      <td className="p-4 whitespace-nowrap">
                        <span className="px-1.5 py-0.5 rounded bg-slate-900 text-cyan-300 border border-slate-800 font-bold">
                          {log.rule_id || 'SIEM'}
                        </span>
                      </td>
                      <td className="p-4 font-semibold text-white max-w-xs truncate">
                        {log.title}
                      </td>
                      <td className="p-4 text-cyan-400/90 whitespace-nowrap">
                        {log.category}
                      </td>
                      <td className="p-4 whitespace-nowrap">
                        {getSeverityBadge(log.severity)}
                      </td>
                      <td className="p-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedEvent(log);
                          }}
                          className="px-2.5 py-1 text-xs bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded inline-flex items-center gap-1 transition"
                        >
                          <Eye className="w-3 h-3" /> Inspect
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 2: Correlation Rules Registry */}
      {activeTab === 'correlation' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <span className="text-xs uppercase text-slate-400 font-mono font-bold tracking-wider">
                SIEM Ingestion Correlation Rules Matrix (10 Active Rules)
              </span>
              <p className="text-xs text-slate-500">
                Rule-based sliding window detection with automatic incident aggregation
              </p>
            </div>
            <Link
              href="/dashboard/rules"
              className="cyber-button font-mono text-xs"
            >
              <Sliders className="w-3.5 h-3.5 text-cyan-400" />
              <span>Full Rules Manager</span>
            </Link>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {rules.map((rule) => (
              <div
                key={rule.rule_id}
                className="cyber-card p-5 border border-slate-800 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-2 font-mono">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 text-xs font-bold rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                        {rule.rule_id}
                      </span>
                      <span className="text-xs text-slate-400">{rule.category}</span>
                    </div>
                    {getSeverityBadge(rule.severity)}
                  </div>
                  <h4 className="text-sm font-bold text-white mb-1.5">{rule.name}</h4>
                  <p className="text-xs text-slate-400 line-clamp-2 mb-3">{rule.description}</p>
                </div>

                <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
                  <span>Detections: <strong className="text-cyan-400">{rule.total_detections || 0}</strong></span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${rule.enabled ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' : 'bg-slate-800 text-slate-500'}`}>
                    {rule.enabled ? 'ACTIVE' : 'DISABLED'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: Sigma & YARA Generator */}
      {activeTab === 'ai-generator' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="cyber-card p-6">
            <h3 className="text-base font-bold text-white font-mono mb-1">Rule Spec Definition</h3>
            <p className="text-xs text-slate-400 mb-4">Generate production-ready Sigma or YARA rules from threat artifacts.</p>

            <form onSubmit={handleGenerateRule} className="space-y-4 font-mono text-xs">
              <div>
                <label className="text-slate-300 block mb-1">Rule Standard:</label>
                <div className="flex gap-4">
                  <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                    <input
                      type="radio"
                      name="ruleType"
                      checked={ruleType === 'sigma'}
                      onChange={() => setRuleType('sigma')}
                      className="accent-cyan-400"
                    />
                    <span>Sigma Detection (Log Analytics)</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                    <input
                      type="radio"
                      name="ruleType"
                      checked={ruleType === 'yara'}
                      onChange={() => setRuleType('yara')}
                      className="accent-cyan-400"
                    />
                    <span>YARA Signature (File / Memory)</span>
                  </label>
                </div>
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Rule Title:</label>
                <input
                  type="text"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="cyber-input"
                />
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Description:</label>
                <textarea
                  rows={2}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="cyber-input"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-300 block mb-1">Process / Target Image:</label>
                  <input
                    type="text"
                    value={targetImage}
                    onChange={(e) => setTargetImage(e.target.value)}
                    className="cyber-input"
                  />
                </div>
                <div>
                  <label className="text-slate-300 block mb-1">Command String Indicator:</label>
                  <input
                    type="text"
                    value={targetCmd}
                    onChange={(e) => setTargetCmd(e.target.value)}
                    className="cyber-input"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loadingRule}
                className="cyber-button-primary w-full py-2.5 mt-2"
              >
                {loadingRule ? 'Compiling Ruleset...' : 'Synthesize Detection Rule'}
              </button>
            </form>
          </div>

          <div className="cyber-card p-6 flex flex-col justify-between">
            <div>
              <div className="flex justify-between items-center mb-3">
                <h3 className="text-base font-bold text-white font-mono">Compiled Artifact</h3>
                {generatedRule && (
                  <button
                    onClick={handleCopyRule}
                    className="cyber-button py-1 px-3 text-xs"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                )}
              </div>

              <pre className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-cyan-300 font-mono text-xs overflow-x-auto min-h-[300px] leading-relaxed">
                {generatedRule || '// Configure parameters on the left and synthesize to view rule syntax.'}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* ======================================================== */}
      {/* EVENT INSPECTION DRAWER */}
      {/* ======================================================== */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="cyber-card w-full max-w-2xl bg-[#090d20] border-cyan-400/50 shadow-[0_0_35px_rgba(6,182,212,0.25)]">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center text-cyan-400">
                  <Database className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white font-mono">
                    Event Inspector · {selectedEvent.rule_id || 'SIEM Ingest'}
                  </h3>
                  <p className="text-xs text-slate-400">{selectedEvent.title}</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4 max-h-[65vh] overflow-y-auto pr-1 font-mono text-xs">
              <div className="flex flex-wrap gap-2">
                <span className="px-2 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  Severity: {getSeverityBadge(selectedEvent.severity)}
                </span>
                <span className="px-2 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  Category: <strong className="text-cyan-400">{selectedEvent.category}</strong>
                </span>
                {selectedEvent.source_ip && (
                  <span className="px-2 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    Source IP: <strong className="text-white">{selectedEvent.source_ip}</strong>
                  </span>
                )}
                {selectedEvent.username && (
                  <span className="px-2 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    User: <strong className="text-white">{selectedEvent.username}</strong>
                  </span>
                )}
              </div>

              <div className="p-3.5 rounded bg-slate-950 border border-slate-800 space-y-2">
                <p className="text-cyan-400 font-bold uppercase text-[11px]">Normalized Event Payload:</p>
                <p className="text-slate-200 leading-relaxed">{selectedEvent.description}</p>
              </div>

              {selectedEvent.source_log && (
                <div>
                  <p className="text-slate-400 font-bold mb-1.5">Raw Telemetry Source Log:</p>
                  <pre className="p-3 rounded bg-black/60 border border-slate-800 text-cyan-300 overflow-x-auto text-[10px] leading-tight">
                    {typeof selectedEvent.source_log === 'string'
                      ? selectedEvent.source_log
                      : JSON.stringify(selectedEvent.source_log, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            <div className="flex justify-between items-center pt-4 border-t border-slate-800 mt-4">
              <Link
                href="/alerts"
                className="text-xs font-mono text-cyan-400 hover:text-white flex items-center gap-1"
              >
                <span>Open in Alert Triage</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </Link>

              <button
                onClick={() => setSelectedEvent(null)}
                className="px-5 py-2 text-xs font-mono font-bold bg-slate-800 hover:bg-slate-700 text-white rounded transition"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
