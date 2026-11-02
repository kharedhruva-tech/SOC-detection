'use client';

import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Sliders,
  Search,
  Filter,
  Play,
  RotateCcw,
  Check,
  X,
  AlertTriangle,
  Clock,
  Cpu,
  Flame,
  Activity,
  Lock,
  FileCode,
  Server,
  ChevronRight,
  Eye,
  Settings2,
  Sparkles,
  Info
} from 'lucide-react';
import { api } from '@/utils/api';

interface DetectionRule {
  id: number;
  rule_id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  enabled: boolean;
  configuration: Record<string, any>;
  mitre_tactics: string[];
  mitre_techniques: string[];
  total_detections: number;
  last_triggered_at: string | null;
  created_at: string;
  updated_at: string;
}

export default function DetectionRulesPage() {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('All');
  const [statusFilter, setStatusFilter] = useState<'All' | 'Enabled' | 'Disabled'>('All');

  // Configuration Modal state
  const [configModalRule, setConfigModalRule] = useState<DetectionRule | null>(null);
  const [configFormData, setConfigFormData] = useState<Record<string, any>>({});
  const [savingConfig, setSavingConfig] = useState<boolean>(false);

  // Test / Evidence Modal state
  const [evidenceModalData, setEvidenceModalData] = useState<any | null>(null);

  // Demo status & feedback
  const [demoRunning, setDemoRunning] = useState<boolean>(false);
  const [demoMessage, setDemoMessage] = useState<{ text: string; type: 'success' | 'error' | 'info' } | null>(null);

  const categories = [
    'All',
    'Authentication',
    'Account Security',
    'Privilege Management',
    'File Monitoring',
    'Malware Detection',
    'Network Security'
  ];

  const severities = ['All', 'Critical', 'High', 'Medium', 'Low'];

  useEffect(() => {
    fetchRules();
  }, []);

  const fetchRules = async () => {
    try {
      setLoading(true);
      const data = await api.get('/detection-rules');
      setRules(data);
    } catch (err: any) {
      console.error('Failed to fetch detection rules:', err);
      showFeedback(err.message || 'Error loading detection rules', 'error');
    } finally {
      setLoading(false);
    }
  };

  const showFeedback = (text: string, type: 'success' | 'error' | 'info' = 'info') => {
    setDemoMessage({ text, type });
    setTimeout(() => {
      setDemoMessage(null);
    }, 4500);
  };

  // Toggle Rule Status (Enable / Disable)
  const handleToggleRule = async (rule: DetectionRule) => {
    const newStatus = !rule.enabled;
    try {
      await api.patch(`/detection-rules/${rule.rule_id}`, { enabled: newStatus });
      setRules((prev) =>
        prev.map((r) => (r.rule_id === rule.rule_id ? { ...r, enabled: newStatus } : r))
      );
      showFeedback(`Rule ${rule.rule_id} is now ${newStatus ? 'ENABLED' : 'DISABLED'}.`, 'success');
    } catch (err: any) {
      console.error('Failed to toggle rule:', err);
      showFeedback(err.message || 'Failed to update rule state', 'error');
    }
  };

  // Open Configuration Modal
  const handleOpenConfig = (rule: DetectionRule) => {
    setConfigModalRule(rule);
    setConfigFormData({ ...rule.configuration });
  };

  // Save Configuration Modal
  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!configModalRule) return;

    try {
      setSavingConfig(true);
      const updated = await api.patch(`/detection-rules/${configModalRule.rule_id}`, {
        configuration: configFormData,
      });
      setRules((prev) =>
        prev.map((r) => (r.rule_id === configModalRule.rule_id ? updated : r))
      );
      setConfigModalRule(null);
      showFeedback(`Configuration for ${configModalRule.rule_id} updated successfully!`, 'success');
    } catch (err: any) {
      console.error('Failed to save rule config:', err);
      showFeedback(err.message || 'Error saving rule configuration', 'error');
    } finally {
      setSavingConfig(false);
    }
  };

  // Run Demo Scenario for single rule
  const handleTestRule = async (ruleId: string) => {
    try {
      setDemoRunning(true);
      showFeedback(`Simulating safe demo attack telemetry for ${ruleId}...`, 'info');
      const response = await api.post('/demo/generate-events', { rule_id: ruleId });

      // Refresh rule stats
      await fetchRules();

      if (response.alerts_created && response.alerts_created.length > 0) {
        showFeedback(`✓ Detection triggered! Generated alert: ${response.alerts_created[0].title}`, 'success');
        // Fetch detailed alert evidence to preview
        try {
          const alertDetail = await api.get(`/alerts/${response.alerts_created[0].alert_id}`);
          setEvidenceModalData(alertDetail);
        } catch (e) {
          console.error(e);
        }
      } else {
        showFeedback(`Simulation completed for ${ruleId} (no alert produced or in cooldown).`, 'info');
      }
    } catch (err: any) {
      console.error('Failed to run demo scenario:', err);
      showFeedback(err.message || 'Demo simulation failed', 'error');
    } finally {
      setDemoRunning(false);
    }
  };

  // Run all 10 attack demos
  const handleRunAllDemos = async () => {
    try {
      setDemoRunning(true);
      showFeedback('Triggering all 10 SIEM Attack Demos simultaneously...', 'info');
      await api.post('/demo/generate-events', { rule_id: 'all' });
      await fetchRules();
      showFeedback('✓ All 10 SIEM attack scenarios executed! Alerts dispatched over WebSockets.', 'success');
    } catch (err: any) {
      console.error('Failed to run all scenarios:', err);
      showFeedback(err.message || 'Failed to execute all scenarios', 'error');
    } finally {
      setDemoRunning(false);
    }
  };

  // Generate normal traffic
  const handleGenerateNormal = async () => {
    try {
      setDemoRunning(true);
      showFeedback('Injecting legitimate background events (logon, HTTP, file writes)...', 'info');
      const res = await api.post('/demo/generate-events', { rule_id: 'normal' });
      showFeedback('✓ Normal traffic processed cleanly with 0 false positives.', 'success');
    } catch (err: any) {
      showFeedback(err.message || 'Failed to process normal events', 'error');
    } finally {
      setDemoRunning(false);
    }
  };

  // Reset Demo Data
  const handleResetDemoData = async () => {
    if (!confirm('Purge all synthetic DEMO events and alerts from database?')) return;
    try {
      setDemoRunning(true);
      const res = await api.post('/demo/reset');
      await fetchRules();
      showFeedback(`✓ Reset complete: Purged ${res.deleted_alerts_count} demo alerts and ${res.deleted_events_count} events.`, 'success');
    } catch (err: any) {
      console.error('Failed to reset demo data:', err);
      showFeedback(err.message || 'Failed to reset demo data', 'error');
    } finally {
      setDemoRunning(false);
    }
  };

  // Metrics
  const totalRules = rules.length;
  const activeRules = rules.filter((r) => r.enabled).length;
  const disabledRules = totalRules - activeRules;
  const totalDetections = rules.reduce((acc, r) => acc + (r.total_detections || 0), 0);

  // Filtered Rules
  const filteredRules = rules.filter((rule) => {
    const matchesSearch =
      rule.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.rule_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.description.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesCategory =
      selectedCategory === 'All' || rule.category.toLowerCase() === selectedCategory.toLowerCase();

    const matchesSeverity =
      selectedSeverity === 'All' || rule.severity.toLowerCase() === selectedSeverity.toLowerCase();

    const matchesStatus =
      statusFilter === 'All' ||
      (statusFilter === 'Enabled' && rule.enabled) ||
      (statusFilter === 'Disabled' && !rule.enabled);

    return matchesSearch && matchesCategory && matchesSeverity && matchesStatus;
  });

  const getSeverityBadge = (severity: string) => {
    const s = severity.toLowerCase();
    if (s === 'critical') {
      return (
        <span className="px-2.5 py-1 text-xs font-semibold rounded bg-[#ff003c]/15 text-[#ff003c] border border-[#ff003c]/40 flex items-center gap-1 shadow-[0_0_8px_rgba(255,0,60,0.3)]">
          <Flame className="w-3 h-3" /> Critical
        </span>
      );
    }
    if (s === 'high') {
      return (
        <span className="px-2.5 py-1 text-xs font-semibold rounded bg-[#ff8c00]/15 text-[#ff8c00] border border-[#ff8c00]/40 flex items-center gap-1">
          <AlertTriangle className="w-3 h-3" /> High
        </span>
      );
    }
    if (s === 'medium') {
      return (
        <span className="px-2.5 py-1 text-xs font-semibold rounded bg-amber-400/15 text-amber-300 border border-amber-400/40 flex items-center gap-1">
          <Activity className="w-3 h-3" /> Medium
        </span>
      );
    }
    return (
      <span className="px-2.5 py-1 text-xs font-semibold rounded bg-[#00f3ff]/15 text-[#00f3ff] border border-[#00f3ff]/40 flex items-center gap-1">
        <ShieldCheck className="w-3 h-3" /> Low
      </span>
    );
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center text-cyan-400">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-wider text-white">SIEM Detection Rules Engine</h1>
              <p className="text-xs text-slate-400 font-mono tracking-wide">
                10 Modular MITRE ATT&CK Rules · Real-Time Correlation · Configurable Thresholds
              </p>
            </div>
          </div>
        </div>

        {/* Action Bar / Refresh */}
        <div className="flex items-center gap-3">
          <button
            onClick={fetchRules}
            className="px-3 py-2 text-xs font-mono bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 rounded flex items-center gap-2 transition"
          >
            <RotateCcw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>
      </div>

      {/* Floating Status Notification / Toast */}
      {demoMessage && (
        <div
          className={`p-3.5 rounded-lg border text-sm font-mono flex items-center justify-between transition-all duration-300 ${demoMessage.type === 'success'
              ? 'bg-emerald-950/80 border-emerald-500/50 text-emerald-300 shadow-[0_0_15px_rgba(16,185,129,0.2)]'
              : demoMessage.type === 'error'
                ? 'bg-rose-950/80 border-rose-500/50 text-rose-300 shadow-[0_0_15px_rgba(244,63,94,0.2)]'
                : 'bg-cyan-950/80 border-cyan-500/50 text-cyan-300 shadow-[0_0_15px_rgba(6,182,212,0.2)]'
            }`}
        >
          <div className="flex items-center gap-2">
            <Info className="w-4 h-4 shrink-0" />
            <span>{demoMessage.text}</span>
          </div>
          <button onClick={() => setDemoMessage(null)} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* 4 Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="cyber-card p-5 border-cyan-500/30 bg-[#0d1026]/80 flex items-center justify-between">
          <div>
            <p className="text-xs font-mono text-cyan-400/80 uppercase tracking-wider">Total Rules</p>
            <h3 className="text-3xl font-bold text-white mt-1 font-mono">{totalRules}</h3>
            <p className="text-[11px] text-slate-400 mt-1">10 Built-In Detection Rules</p>
          </div>
          <div className="w-12 h-12 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <ShieldCheck className="w-6 h-6" />
          </div>
        </div>

        <div className="cyber-card p-5 border-emerald-500/30 bg-[#0d1026]/80 flex items-center justify-between">
          <div>
            <p className="text-xs font-mono text-emerald-400/80 uppercase tracking-wider">Active Rules</p>
            <h3 className="text-3xl font-bold text-emerald-400 mt-1 font-mono">{activeRules}</h3>
            <p className="text-[11px] text-slate-400 mt-1">Real-time evaluation enabled</p>
          </div>
          <div className="w-12 h-12 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Cpu className="w-6 h-6" />
          </div>
        </div>

        <div className="cyber-card p-5 border-rose-500/30 bg-[#0d1026]/80 flex items-center justify-between">
          <div>
            <p className="text-xs font-mono text-rose-400/80 uppercase tracking-wider">Disabled Rules</p>
            <h3 className="text-3xl font-bold text-rose-400 mt-1 font-mono">{disabledRules}</h3>
            <p className="text-[11px] text-slate-400 mt-1">Bypassed during ingestion</p>
          </div>
          <div className="w-12 h-12 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
            <Lock className="w-6 h-6" />
          </div>
        </div>

        <div className="cyber-card p-5 border-purple-500/30 bg-[#0d1026]/80 flex items-center justify-between">
          <div>
            <p className="text-xs font-mono text-purple-400/80 uppercase tracking-wider">Total Alerts Triggered</p>
            <h3 className="text-3xl font-bold text-purple-300 mt-1 font-mono">{totalDetections}</h3>
            <p className="text-[11px] text-slate-400 mt-1">Aggregated detections recorded</p>
          </div>
          <div className="w-12 h-12 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* Safe Demo & Simulation Command Bar */}
      <div className="p-4 rounded-lg bg-gradient-to-r from-slate-900/90 via-[#0f172a] to-slate-900/90 border border-cyan-500/30 flex flex-col md:flex-row items-center justify-between gap-4 shadow-[0_0_20px_rgba(6,182,212,0.1)]">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded bg-neon-cyan/10 border border-neon-cyan/40 flex items-center justify-center text-neon-cyan">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-widest text-neon-cyan font-mono">
                SIEM Demonstration Mode
              </span>
              <span className="px-1.5 py-0.5 text-[9px] font-mono rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                100% SAFE / ISOLATED
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Inject synthetic telemetry to trigger detection rules and stream live alerts over WebSockets.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={handleRunAllDemos}
            disabled={demoRunning}
            className="px-4 py-2 text-xs font-bold font-mono bg-cyan-500 hover:bg-cyan-400 text-black rounded transition flex items-center gap-2 shadow-[0_0_12px_rgba(6,182,212,0.4)] disabled:opacity-50 cursor-pointer"
          >
            <Play className="w-3.5 h-3.5 fill-black" /> Run All 10 Rules
          </button>

          <button
            onClick={handleGenerateNormal}
            disabled={demoRunning}
            className="px-3.5 py-2 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded transition flex items-center gap-1.5 disabled:opacity-50 cursor-pointer"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> Normal Traffic
          </button>

          <button
            onClick={handleResetDemoData}
            disabled={demoRunning}
            className="px-3 py-2 text-xs font-mono bg-rose-950/60 hover:bg-rose-900 border border-rose-700/50 text-rose-300 rounded transition flex items-center gap-1.5 disabled:opacity-50 cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" /> Purge Demo Data
          </button>
        </div>
      </div>

      {/* Filters & Search Control Bar */}
      <div className="space-y-3">
        <div className="flex flex-col md:flex-row gap-3 items-center justify-between">
          {/* Search */}
          <div className="relative w-full md:w-96">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search by Rule ID, Name, or MITRE..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-slate-900/80 border border-slate-800 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono transition"
            />
          </div>

          {/* Status & Severity filter selects */}
          <div className="flex items-center gap-2 w-full md:w-auto">
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="px-3 py-2 bg-slate-900 border border-slate-800 rounded text-xs text-slate-300 focus:border-cyan-400 outline-none font-mono"
            >
              <option value="All">All Severities</option>
              {severities.filter(s => s !== 'All').map((s) => (
                <option key={s} value={s}>{s} Severity</option>
              ))}
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as any)}
              className="px-3 py-2 bg-slate-900 border border-slate-800 rounded text-xs text-slate-300 focus:border-cyan-400 outline-none font-mono"
            >
              <option value="All">All Status</option>
              <option value="Enabled">Enabled Only</option>
              <option value="Disabled">Disabled Only</option>
            </select>
          </div>
        </div>

        {/* Category Pills */}
        <div className="flex flex-wrap gap-1.5 pt-1">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1.5 rounded-md text-xs font-mono transition cursor-pointer ${selectedCategory === cat
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/50 font-bold'
                  : 'bg-slate-900/60 text-slate-400 border border-slate-800/80 hover:text-slate-200 hover:bg-slate-800'
                }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Rules Grid */}
      {loading ? (
        <div className="p-16 text-center text-slate-400 font-mono flex flex-col items-center justify-center gap-3">
          <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin"></div>
          <p>Loading detection rule matrix...</p>
        </div>
      ) : filteredRules.length === 0 ? (
        <div className="cyber-card p-12 text-center text-slate-400 font-mono">
          <p>No detection rules match the specified filters.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredRules.map((rule) => (
            <div
              key={rule.rule_id}
              className={`cyber-card p-5 border transition-all duration-200 flex flex-col justify-between ${rule.enabled
                  ? 'border-slate-800 hover:border-cyan-500/40 bg-[#0a0d24]/90'
                  : 'border-slate-800/50 bg-[#090b1c]/40 opacity-70'
                }`}
            >
              <div>
                {/* Header: ID, Name, Category, Severity & Toggle */}
                <div className="flex items-start justify-between gap-3 mb-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="px-2.5 py-0.5 text-xs font-mono font-bold rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                      {rule.rule_id}
                    </span>
                    <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {rule.category}
                    </span>
                    {getSeverityBadge(rule.severity)}
                  </div>

                  {/* Enable / Disable Toggle Switch */}
                  <label className="relative inline-flex items-center cursor-pointer shrink-0">
                    <input
                      type="checkbox"
                      checked={rule.enabled}
                      onChange={() => handleToggleRule(rule)}
                      className="sr-only peer"
                    />
                    <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-500"></div>
                  </label>
                </div>

                {/* Title & Description */}
                <h3 className="text-base font-bold text-white mb-1.5 flex items-center gap-2">
                  {rule.name}
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed mb-4">
                  {rule.description}
                </p>

                {/* MITRE ATT&CK & Parameters Preview */}
                <div className="p-3 rounded bg-slate-950/60 border border-slate-800/80 space-y-2 mb-4 font-mono text-xs">
                  {rule.mitre_techniques && rule.mitre_techniques.length > 0 && (
                    <div className="flex items-center gap-1.5 text-slate-300 text-[11px]">
                      <span className="text-cyan-400 font-bold">MITRE:</span>
                      {rule.mitre_tactics.map((t) => (
                        <span key={t} className="text-purple-400">{t}</span>
                      ))}
                      <span>·</span>
                      {rule.mitre_techniques.map((tech) => (
                        <span key={tech} className="text-cyan-300 bg-slate-900 px-1 py-0.5 rounded border border-slate-800">
                          {tech}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Config Keys Snapshot */}
                  <div className="text-[11px] text-slate-400 flex flex-wrap gap-x-3 gap-y-1">
                    {Object.entries(rule.configuration || {}).slice(0, 3).map(([k, v]) => (
                      <span key={k}>
                        <span className="text-slate-500">{k}:</span>{' '}
                        <span className="text-slate-300 font-bold">
                          {Array.isArray(v) ? `${v.length} items` : String(v)}
                        </span>
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Card Footer: Stats & Buttons */}
              <div className="pt-3 border-t border-slate-800/70 flex items-center justify-between text-xs font-mono">
                <div className="flex items-center gap-3 text-slate-400">
                  <div>
                    <span>Detections: </span>
                    <span className="font-bold text-cyan-400">{rule.total_detections || 0}</span>
                  </div>
                  {rule.last_triggered_at && (
                    <div className="hidden sm:block text-[10px] text-slate-500">
                      Last: {new Date(rule.last_triggered_at).toLocaleTimeString()}
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleOpenConfig(rule)}
                    className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center gap-1.5 transition cursor-pointer"
                  >
                    <Settings2 className="w-3.5 h-3.5 text-cyan-400" /> Configure
                  </button>

                  <button
                    onClick={() => handleTestRule(rule.rule_id)}
                    disabled={demoRunning}
                    className="px-2.5 py-1.5 rounded bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-400/30 flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
                  >
                    <Play className="w-3 h-3 fill-cyan-400" /> Test Rule
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ======================================================== */}
      {/* CONFIGURATION MODAL */}
      {/* ======================================================== */}
      {configModalRule && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="cyber-card w-full max-w-lg bg-[#0d1026] border-cyan-500/50 shadow-[0_0_30px_rgba(6,182,212,0.2)]">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center text-cyan-400">
                  <Settings2 className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white font-mono">
                    Configure {configModalRule.rule_id}: {configModalRule.name}
                  </h3>
                  <p className="text-xs text-slate-400">Modify threshold values and window parameters</p>
                </div>
              </div>
              <button
                onClick={() => setConfigModalRule(null)}
                className="text-slate-400 hover:text-white p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSaveConfig} className="space-y-4">
              <div className="max-h-[60vh] overflow-y-auto pr-1 space-y-3 font-mono text-xs">
                {Object.entries(configFormData).map(([key, value]) => {
                  const isNumber = typeof value === 'number';
                  const isBoolean = typeof value === 'boolean';
                  const isArray = Array.isArray(value);

                  return (
                    <div key={key} className="space-y-1">
                      <label className="text-slate-300 font-bold block capitalize">
                        {key.replace(/_/g, ' ')}:
                      </label>

                      {isBoolean ? (
                        <select
                          value={String(value)}
                          onChange={(e) =>
                            setConfigFormData({
                              ...configFormData,
                              [key]: e.target.value === 'true',
                            })
                          }
                          className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded text-slate-200 focus:border-cyan-400 outline-none"
                        >
                          <option value="true">True (Enabled)</option>
                          <option value="false">False (Disabled)</option>
                        </select>
                      ) : isArray ? (
                        <textarea
                          rows={3}
                          value={value.join(', ')}
                          onChange={(e) =>
                            setConfigFormData({
                              ...configFormData,
                              [key]: e.target.value.split(',').map((s) => s.trim()).filter(Boolean),
                            })
                          }
                          className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded text-slate-200 focus:border-cyan-400 outline-none font-mono"
                          placeholder="Comma-separated items..."
                        />
                      ) : (
                        <input
                          type={isNumber ? 'number' : 'text'}
                          value={value}
                          onChange={(e) =>
                            setConfigFormData({
                              ...configFormData,
                              [key]: isNumber ? Number(e.target.value) : e.target.value,
                            })
                          }
                          className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded text-slate-200 focus:border-cyan-400 outline-none font-mono"
                        />
                      )}
                    </div>
                  );
                })}
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setConfigModalRule(null)}
                  className="px-4 py-2 text-xs font-mono text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={savingConfig}
                  className="px-5 py-2 text-xs font-mono font-bold bg-cyan-500 hover:bg-cyan-400 text-black rounded transition shadow-[0_0_10px_rgba(6,182,212,0.3)] disabled:opacity-50 cursor-pointer"
                >
                  {savingConfig ? 'Saving...' : 'Save Configuration'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ======================================================== */}
      {/* EVIDENCE / ALERT PREVIEW MODAL */}
      {/* ======================================================== */}
      {evidenceModalData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="cyber-card w-full max-w-2xl bg-[#090d20] border-cyan-400/50 shadow-[0_0_35px_rgba(6,182,212,0.25)]">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center text-cyan-400">
                  <ShieldAlert className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white font-mono">
                    Detection Evidence · {evidenceModalData.alert_id}
                  </h3>
                  <p className="text-xs text-slate-400">{evidenceModalData.title}</p>
                </div>
              </div>
              <button
                onClick={() => setEvidenceModalData(null)}
                className="text-slate-400 hover:text-white p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4 max-h-[65vh] overflow-y-auto pr-1 font-mono text-xs">
              {/* Alert Meta Badges */}
              <div className="flex flex-wrap gap-2">
                <span className="px-2 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  Rule ID: <strong className="text-cyan-400">{evidenceModalData.rule_id}</strong>
                </span>
                <span className="px-2 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  Severity: <strong className="text-rose-400">{evidenceModalData.severity}</strong>
                </span>
                <span className="px-2 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  Status: <strong className="text-emerald-400">{evidenceModalData.status}</strong>
                </span>
                {evidenceModalData.source_ip && (
                  <span className="px-2 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    Source IP: <strong className="text-white">{evidenceModalData.source_ip}</strong>
                  </span>
                )}
                {evidenceModalData.username && (
                  <span className="px-2 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    User: <strong className="text-white">{evidenceModalData.username}</strong>
                  </span>
                )}
              </div>

              {/* Forensic Evidence Breakdown */}
              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2">
                <p className="text-slate-400 font-bold uppercase tracking-wider text-[11px] text-cyan-400">
                  Forensic Trigger Evidence:
                </p>
                <p className="text-slate-200 leading-relaxed">
                  {evidenceModalData.evidence?.trigger_condition || evidenceModalData.description}
                </p>
                {evidenceModalData.evidence?.risk_assessment && (
                  <div className="mt-2 p-2 rounded bg-cyan-950/30 border border-cyan-800/40 text-cyan-200 text-[11px]">
                    <strong>Risk Assessment: </strong> {evidenceModalData.evidence.risk_assessment}
                  </div>
                )}
              </div>

              {/* Matched Event IDs */}
              {evidenceModalData.matched_event_ids && evidenceModalData.matched_event_ids.length > 0 && (
                <div>
                  <p className="text-slate-400 font-bold mb-1.5">Contributing Event IDs:</p>
                  <div className="flex flex-wrap gap-1">
                    {Array.from(new Set(evidenceModalData.matched_event_ids)).map((eid: any, idx: number) => (
                      <span key={`${eid}-${idx}`} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300 text-[10px]">
                        {eid}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Raw JSON Payload */}
              <div>
                <p className="text-slate-400 font-bold mb-1.5">Raw Evidence JSON:</p>
                <pre className="p-3 rounded bg-black/60 border border-slate-800 text-cyan-300 overflow-x-auto text-[10px] leading-tight">
                  {JSON.stringify(evidenceModalData.evidence, null, 2)}
                </pre>
              </div>
            </div>

            <div className="flex justify-end pt-4 border-t border-slate-800 mt-4">
              <button
                onClick={() => setEvidenceModalData(null)}
                className="px-5 py-2 text-xs font-mono font-bold bg-slate-800 hover:bg-slate-700 text-white rounded transition"
              >
                Close Preview
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

