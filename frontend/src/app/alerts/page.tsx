'use client';

import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  RotateCcw, 
  Flame, 
  AlertTriangle, 
  Activity, 
  ShieldCheck, 
  X, 
  ChevronRight, 
  Eye, 
  Clock, 
  Wifi, 
  WifiOff,
  User,
  ExternalLink,
  CheckCircle2,
  Bot,
  Terminal,
  Layers,
  Sliders,
  Send,
  Play,
  Globe,
  Database,
  Lock,
  Loader2,
  Hash,
  AlertOctagon,
  TrendingUp,
  FileText
} from 'lucide-react';
import { api, WS_BASE_URL } from '@/utils/api';

interface AlertItem {
  id: number;
  alert_id: string;
  rule_id: string;
  rule_name: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  status: string;
  priority: string;
  risk_score: number;
  occurrence_count: number;
  is_duplicate: boolean;
  correlation_id: string | null;
  threat_intel: Record<string, any>;
  source_ip: string | null;
  username: string | null;
  destination_ip?: string | null;
  matched_event_ids: string[];
  evidence: Record<string, any>;
  risk_factors?: Array<{ factor: string; points: number; max: number; description: string }>;
  ai_analysis?: Record<string, any>;
  notes?: Array<{ id: string; author: string; text: string; timestamp: string }>;
  audit_trail?: Array<{ action: string; actor: string; timestamp: string; details: string }>;
  timestamp: string;
  detection_timestamp: string | null;
  last_seen_at?: string | null;
  assigned_to: string | null;
  incident_id: number | null;
  is_demo: boolean;
}

interface TriageStats {
  total_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  awaiting_investigation: number;
  correlated_incidents: number;
  average_triage_sla: string;
  risk_distribution?: {
    critical_p1: number;
    high_p2: number;
    medium_p3: number;
    low_p4: number;
  };
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [stats, setStats] = useState<TriageStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('All');
  const [selectedStatus, setSelectedStatus] = useState<string>('All');
  const [selectedPriority, setSelectedPriority] = useState<string>('All');
  
  // Selected alert for investigation drawer
  const [activeAlert, setActiveAlert] = useState<AlertItem | null>(null);
  const [drawerTab, setDrawerTab] = useState<'overview' | 'timeline' | 'intel' | 'ai' | 'evidence' | 'soar' | 'audit'>('overview');
  const [timelineData, setTimelineData] = useState<any[]>([]);
  const [loadingTimeline, setLoadingTimeline] = useState<boolean>(false);
  const [aiAnalysis, setAiAnalysis] = useState<any | null>(null);
  const [loadingAi, setLoadingAi] = useState<boolean>(false);
  const [updatingStatus, setUpdatingStatus] = useState<boolean>(false);
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  
  // Forms inside drawer
  const [newNote, setNewNote] = useState<string>('');
  const [submittingNote, setSubmittingNote] = useState<boolean>(false);
  const [soarActionRunning, setSoarActionRunning] = useState<string | null>(null);
  const [soarResult, setSoarResult] = useState<string | null>(null);

  useEffect(() => {
    fetchAlerts();
    fetchStats();

    // WebSocket real-time live alert stream listener
    let ws: WebSocket;
    let reconnectTimeout: NodeJS.Timeout;
    let active = true;

    const connect = () => {
      if (!active) return;
      try {
        ws = new WebSocket(WS_BASE_URL);
        ws.onopen = () => setWsConnected(true);
        ws.onclose = () => {
          setWsConnected(false);
          if (active) reconnectTimeout = setTimeout(connect, 3000);
        };
        ws.onerror = () => setWsConnected(false);
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'NEW_ALERT' || data.alert_id) {
              const newAlertItem: AlertItem = {
                id: data.id || Math.floor(Math.random() * 90000),
                alert_id: data.alert_id || `ALT-${data.id}`,
                rule_id: data.rule_id || 'SIEM',
                rule_name: data.title || 'Security Alert',
                title: data.title,
                description: data.description || data.title,
                category: data.category || 'Threat Detection',
                severity: data.severity || 'Medium',
                status: data.status || 'New',
                priority: data.priority || 'P3',
                risk_score: data.risk_score || 50.0,
                occurrence_count: data.occurrence_count || 1,
                is_duplicate: Boolean(data.is_duplicate),
                correlation_id: data.correlation_id || null,
                threat_intel: data.threat_intel || {},
                source_ip: data.source_ip || null,
                username: data.username || null,
                destination_ip: data.destination_ip || null,
                matched_event_ids: data.matched_event_ids || [],
                evidence: data.evidence || {},
                timestamp: data.timestamp || new Date().toISOString(),
                detection_timestamp: data.timestamp || new Date().toISOString(),
                assigned_to: data.assigned_to || null,
                incident_id: data.incident_id || null,
                is_demo: Boolean(data.is_demo),
              };

              setAlerts((prev) => {
                // If already present, update occurrence count / details
                const existsIdx = prev.findIndex(a => a.alert_id === newAlertItem.alert_id);
                if (existsIdx >= 0) {
                  const updated = [...prev];
                  updated[existsIdx] = { ...updated[existsIdx], ...newAlertItem };
                  return updated;
                }
                return [newAlertItem, ...prev];
              });
              fetchStats();
            } else if (data.type === 'ALERT_UPDATED') {
              setAlerts((prev) =>
                prev.map((a) => (a.alert_id === data.alert_id ? { ...a, ...data } : a))
              );
              fetchStats();
            }
          } catch (e) {
            console.error('WS Alert parsing error:', e);
          }
        };
      } catch (err) {
        setWsConnected(false);
      }
    };

    connect();

    return () => {
      active = false;
      if (ws) ws.close();
      clearTimeout(reconnectTimeout);
    };
  }, []);

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const data = await api.get('/alerts');
      setAlerts(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error('Error fetching alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const data = await api.get('/alerts/stats/summary').catch(() => null);
      if (data) setStats(data);
    } catch (err) {
      console.error('Error fetching stats:', err);
    }
  };

  const openInvestigation = async (alert: AlertItem) => {
    setActiveAlert(alert);
    setDrawerTab('overview');
    setAiAnalysis(alert.ai_analysis && Object.keys(alert.ai_analysis).length > 0 ? alert.ai_analysis : null);
    setSoarResult(null);

    // Fetch full details including risk factors and audit trail
    try {
      const details = await api.get(`/alerts/${alert.alert_id || alert.id}`);
      setActiveAlert(details);
      if (details.ai_analysis && Object.keys(details.ai_analysis).length > 0) {
        setAiAnalysis(details.ai_analysis);
      }
    } catch (err) {
      console.error('Error loading alert details:', err);
    }
  };

  const fetchTimeline = async (alertId: string) => {
    try {
      setLoadingTimeline(true);
      const res = await api.get(`/alerts/${alertId}/timeline`);
      setTimelineData(res.timeline || []);
    } catch (err) {
      console.error('Failed to load attack timeline:', err);
      setTimelineData([]);
    } finally {
      setLoadingTimeline(false);
    }
  };

  const fetchAiAnalysis = async (alertId: string) => {
    try {
      setLoadingAi(true);
      const res = await api.get(`/alerts/${alertId}/ai-analysis`);
      setAiAnalysis(res);
      if (activeAlert) {
        setActiveAlert({ ...activeAlert, ai_analysis: res });
      }
    } catch (err) {
      console.error('Failed to load AI analysis:', err);
    } finally {
      setLoadingAi(false);
    }
  };

  const handleUpdateStatus = async (alertIdentifier: string, newStatus: string) => {
    try {
      setUpdatingStatus(true);
      await api.patch(`/alerts/${alertIdentifier}`, { status: newStatus });
      setAlerts((prev) =>
        prev.map((a) => (a.alert_id === alertIdentifier || String(a.id) === alertIdentifier ? { ...a, status: newStatus } : a))
      );
      if (activeAlert) {
        setActiveAlert({ ...activeAlert, status: newStatus });
      }
      fetchStats();
    } catch (err) {
      console.error('Failed to update alert status:', err);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleAssignAnalyst = async (alertIdentifier: string, assignee: string) => {
    try {
      setUpdatingStatus(true);
      await api.patch(`/alerts/${alertIdentifier}`, { assigned_to: assignee });
      setAlerts((prev) =>
        prev.map((a) => (a.alert_id === alertIdentifier || String(a.id) === alertIdentifier ? { ...a, assigned_to: assignee } : a))
      );
      if (activeAlert) {
        setActiveAlert({ ...activeAlert, assigned_to: assignee });
      }
    } catch (err) {
      console.error('Failed to assign analyst:', err);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim() || !activeAlert) return;
    try {
      setSubmittingNote(true);
      await api.patch(`/alerts/${activeAlert.alert_id || activeAlert.id}`, { note: newNote.trim() });
      const refreshed = await api.get(`/alerts/${activeAlert.alert_id || activeAlert.id}`);
      setActiveAlert(refreshed);
      setNewNote('');
    } catch (err) {
      console.error('Failed to add note:', err);
    } finally {
      setSubmittingNote(false);
    }
  };

  const handleRunSoarAction = async (action: string) => {
    if (!activeAlert) return;
    try {
      setSoarActionRunning(action);
      setSoarResult(null);
      const res = await api.post(`/alerts/${activeAlert.alert_id || activeAlert.id}/remediate`, {
        action: action,
        parameters: {
          ip: activeAlert.source_ip,
          username: activeAlert.username
        },
        approved: true
      });
      setSoarResult(res.message);
      // Refresh alert to show SOAR action in audit trail
      const refreshed = await api.get(`/alerts/${activeAlert.alert_id || activeAlert.id}`);
      setActiveAlert(refreshed);
    } catch (err) {
      console.error('Failed to execute SOAR remediation:', err);
      setSoarResult('Remediation execution failed or requires approval.');
    } finally {
      setSoarActionRunning(null);
    }
  };

  const getSeverityBadge = (severity: string) => {
    const s = severity?.toLowerCase();
    if (s === 'critical') {
      return (
        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-[#ff003c]/15 text-[#ff003c] border border-[#ff003c]/40 inline-flex items-center gap-1">
          <Flame className="w-3 h-3" /> Critical
        </span>
      );
    }
    if (s === 'high') {
      return (
        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-[#ff8c00]/15 text-[#ff8c00] border border-[#ff8c00]/40 inline-flex items-center gap-1">
          <AlertTriangle className="w-3 h-3" /> High
        </span>
      );
    }
    if (s === 'medium') {
      return (
        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-amber-400/15 text-amber-300 border border-amber-400/40 inline-flex items-center gap-1">
          <Activity className="w-3 h-3" /> Medium
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-800 text-slate-300 border border-slate-700 inline-flex items-center gap-1">
        <ShieldCheck className="w-3 h-3" /> {severity || 'Low'}
      </span>
    );
  };

  const getPriorityBadge = (priority: string, score: number) => {
    const p = (priority || 'P3').toUpperCase();
    let bg = 'bg-slate-800 text-slate-300 border-slate-700';
    if (p === 'P1') bg = 'bg-rose-950/60 text-rose-400 border-rose-500/50 shadow-[0_0_8px_rgba(244,63,94,0.2)]';
    else if (p === 'P2') bg = 'bg-amber-950/60 text-amber-400 border-amber-500/50';
    else if (p === 'P3') bg = 'bg-cyan-950/60 text-cyan-300 border-cyan-500/40';

    return (
      <div className="flex items-center gap-1.5 font-mono">
        <span className={`px-1.5 py-0.5 text-[10px] font-bold rounded border ${bg}`}>
          {p}
        </span>
        <span className="text-xs font-bold text-slate-200">
          {Math.round(score || 0)}<span className="text-[10px] text-slate-500">/100</span>
        </span>
      </div>
    );
  };

  const getThreatIntelBadge = (ti: Record<string, any>) => {
    const rep = ti?.reputation;
    if (rep === 'Confirmed Malicious' || rep === 'Malicious') {
      return (
        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-950/60 text-rose-400 border border-rose-500/40 inline-flex items-center gap-1">
          <Globe className="w-2.5 h-2.5" /> Malicious ({ti?.score || 95}%)
        </span>
      );
    }
    if (rep === 'Suspicious') {
      return (
        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-950/60 text-amber-400 border border-amber-500/40 inline-flex items-center gap-1">
          <Globe className="w-2.5 h-2.5" /> Suspicious
        </span>
      );
    }
    if (rep === 'Clean') {
      return (
        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-950/60 text-emerald-400 border border-emerald-500/40 inline-flex items-center gap-1">
          <ShieldCheck className="w-2.5 h-2.5" /> Clean Asset
        </span>
      );
    }
    return (
      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-slate-900 text-slate-400 border border-slate-800">
        Unknown
      </span>
    );
  };

  const getStatusBadge = (st: string) => {
    const s = st?.toLowerCase();
    if (s === 'resolved') {
      return (
        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
          Resolved
        </span>
      );
    }
    if (s === 'investigating') {
      return (
        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
          Investigating
        </span>
      );
    }
    if (s === 'escalated') {
      return (
        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-purple-500/10 text-purple-300 border border-purple-500/30">
          Escalated
        </span>
      );
    }
    if (s === 'false positive') {
      return (
        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-800 text-slate-400 border border-slate-700">
          False Positive
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 text-xs font-semibold rounded bg-rose-500/10 text-rose-400 border border-rose-500/30">
        New
      </span>
    );
  };

  const filteredAlerts = alerts.filter((a) => {
    const matchesSearch =
      searchQuery === '' ||
      a.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.alert_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.rule_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (a.source_ip && a.source_ip.includes(searchQuery)) ||
      (a.username && a.username.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesSeverity =
      selectedSeverity === 'All' || a.severity?.toLowerCase() === selectedSeverity.toLowerCase();

    const matchesStatus =
      selectedStatus === 'All' || a.status?.toLowerCase() === selectedStatus.toLowerCase();

    const matchesPriority =
      selectedPriority === 'All' || a.priority?.toUpperCase() === selectedPriority.toUpperCase();

    return matchesSearch && matchesSeverity && matchesStatus && matchesPriority;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      
      {/* Top Banner & WebSocket Pill */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center text-cyan-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-wider text-white">Advanced Live SIEM Alert Triage</h1>
              <p className="text-xs text-slate-400 font-mono">
                Real-time alert ingestion • In-stream deduplication • Multi-stage correlation • Intelligent risk scoring
              </p>
            </div>
          </div>
        </div>

        {/* Live WebSocket Status Pill & Refresh */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs font-mono">
            {wsConnected ? (
              <>
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
                <span className="text-emerald-400 font-bold">WebSocket Live</span>
              </>
            ) : (
              <>
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400"></span>
                <span className="text-slate-400">Polling Ingest</span>
              </>
            )}
          </div>

          <button
            onClick={() => {
              fetchAlerts();
              fetchStats();
            }}
            className="px-3 py-1.5 text-xs font-mono bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 rounded-lg flex items-center gap-1.5 transition cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>
      </div>

      {/* KPI Triage Scorecards */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <div className="cyber-card p-3 font-mono">
          <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Total Alerts</span>
          <div className="text-xl font-bold text-white mt-1">{stats?.total_alerts || alerts.length}</div>
          <span className="text-[9px] text-slate-500 mt-0.5 block">Ingested Telemetry</span>
        </div>

        <div className="cyber-card p-3 font-mono">
          <span className="text-[10px] text-rose-400 uppercase tracking-wider block">Critical (P1)</span>
          <div className="text-xl font-bold text-rose-400 mt-1">
            {stats?.critical_alerts || alerts.filter(a => a.severity?.toLowerCase() === 'critical').length}
          </div>
          <span className="text-[9px] text-rose-400/80 mt-0.5 block">Immediate Action</span>
        </div>

        <div className="cyber-card p-3 font-mono">
          <span className="text-[10px] text-amber-400 uppercase tracking-wider block">High Priority</span>
          <div className="text-xl font-bold text-amber-400 mt-1">
            {stats?.high_alerts || alerts.filter(a => a.severity?.toLowerCase() === 'high').length}
          </div>
          <span className="text-[9px] text-amber-400/80 mt-0.5 block">Tier 2 Triage</span>
        </div>

        <div className="cyber-card p-3 font-mono">
          <span className="text-[10px] text-cyan-300 uppercase tracking-wider block">Awaiting Review</span>
          <div className="text-xl font-bold text-cyan-300 mt-1">
            {stats?.awaiting_investigation || alerts.filter(a => a.status === 'New').length}
          </div>
          <span className="text-[9px] text-cyan-400/80 mt-0.5 block">Unacknowledged</span>
        </div>

        <div className="cyber-card p-3 font-mono">
          <span className="text-[10px] text-purple-400 uppercase tracking-wider block">Correlated Cases</span>
          <div className="text-xl font-bold text-purple-300 mt-1">
            {stats?.correlated_incidents || alerts.filter(a => a.correlation_id).length}
          </div>
          <span className="text-[9px] text-purple-400/80 mt-0.5 block">Multi-Stage Attacks</span>
        </div>

        <div className="cyber-card p-3 font-mono">
          <span className="text-[10px] text-emerald-400 uppercase tracking-wider block">Avg Triage SLA</span>
          <div className="text-xl font-bold text-emerald-400 mt-1">{stats?.average_triage_sla || '4.8 mins'}</div>
          <span className="text-[9px] text-slate-500 mt-0.5 block">Target: &lt; 15 mins</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row gap-3 items-center justify-between font-mono text-xs">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search by title, IP, user, rule ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          <select
            value={selectedPriority}
            onChange={(e) => setSelectedPriority(e.target.value)}
            className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-slate-300 focus:border-cyan-400 outline-none cursor-pointer"
          >
            <option value="All">All Priorities</option>
            <option value="P1">P1 - Critical (Score ≥ 80)</option>
            <option value="P2">P2 - High (Score 60-79)</option>
            <option value="P3">P3 - Medium (Score 40-59)</option>
            <option value="P4">P4 - Low (Score &lt; 40)</option>
          </select>

          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-slate-300 focus:border-cyan-400 outline-none cursor-pointer"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-slate-300 focus:border-cyan-400 outline-none cursor-pointer"
          >
            <option value="All">All Statuses</option>
            <option value="New">New</option>
            <option value="Investigating">Investigating</option>
            <option value="Escalated">Escalated</option>
            <option value="Resolved">Resolved</option>
            <option value="False Positive">False Positive</option>
          </select>
        </div>
      </div>

      {/* Live Alerts Triage Feed Table */}
      <div className="cyber-card p-0 border border-slate-800 overflow-hidden bg-[#090d20]">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400 text-[11px] uppercase tracking-wider">
                <th className="py-3 px-3 font-semibold">Risk & Priority</th>
                <th className="py-3 px-3 font-semibold">Alert ID & Dedup</th>
                <th className="py-3 px-3 font-semibold">Rule / Title</th>
                <th className="py-3 px-3 font-semibold">Target Entity</th>
                <th className="py-3 px-3 font-semibold">Threat Intel</th>
                <th className="py-3 px-3 font-semibold">Correlation</th>
                <th className="py-3 px-3 font-semibold">Status</th>
                <th className="py-3 px-3 font-semibold">Timestamp</th>
                <th className="py-3 px-3 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {loading ? (
                <tr>
                  <td colSpan={9} className="py-14 text-center text-slate-500">
                    <Loader2 className="w-6 h-6 border-cyan-400 animate-spin mx-auto mb-2 text-cyan-400" />
                    Loading real-time alert triage feed...
                  </td>
                </tr>
              ) : filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-14 text-center text-slate-500">
                    No active security alerts match query filters.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert, idx) => (
                  <tr
                    key={`${alert.alert_id || alert.id}-${idx}`}
                    onClick={() => openInvestigation(alert)}
                    className="hover:bg-slate-850/50 transition-colors cursor-pointer group"
                  >
                    {/* Risk & Priority */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      {getPriorityBadge(alert.priority, alert.risk_score)}
                    </td>

                    {/* Alert ID & Dedup occurrence badge */}
                    <td className="py-3 px-3 whitespace-nowrap font-bold text-cyan-400">
                      <div className="flex items-center gap-1.5">
                        <span>{alert.alert_id || `ALT-${alert.id}`}</span>
                        {alert.occurrence_count > 1 && (
                          <span className="px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 text-[9px] font-extrabold" title={`${alert.occurrence_count} deduplicated occurrences`}>
                            x{alert.occurrence_count}
                          </span>
                        )}
                        {alert.is_demo && (
                          <span className="px-1 py-0.2 rounded bg-purple-900/40 text-purple-300 border border-purple-700/50 text-[8px]">
                            DEMO
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Rule / Title */}
                    <td className="py-3 px-3 max-w-xs">
                      <div className="flex items-center gap-1.5 mb-0.5">
                        <span className="px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-cyan-300 text-[10px] font-bold">
                          {alert.rule_id}
                        </span>
                        {getSeverityBadge(alert.severity)}
                      </div>
                      <p className="font-semibold text-white truncate text-xs">{alert.title}</p>
                    </td>

                    {/* Target Entity */}
                    <td className="py-3 px-3 whitespace-nowrap text-slate-300">
                      {alert.source_ip ? (
                        <span className="text-cyan-300 font-semibold">{alert.source_ip}</span>
                      ) : alert.username ? (
                        <span className="text-purple-300 font-semibold">@{alert.username}</span>
                      ) : (
                        <span className="text-slate-500">Internal System</span>
                      )}
                    </td>

                    {/* Threat Intel */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      {getThreatIntelBadge(alert.threat_intel)}
                    </td>

                    {/* Correlation */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      {alert.correlation_id ? (
                        <span className="px-1.5 py-0.5 rounded bg-purple-950/50 border border-purple-600/40 text-purple-300 text-[10px] font-semibold" title={alert.correlation_id}>
                          Incident #{alert.incident_id || 'Auto'}
                        </span>
                      ) : (
                        <span className="text-slate-600 text-[11px]">Direct Log</span>
                      )}
                    </td>

                    {/* Status */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      {getStatusBadge(alert.status)}
                    </td>

                    {/* Timestamp */}
                    <td className="py-3 px-3 whitespace-nowrap text-slate-400 text-[11px]">
                      {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : 'Recent'}
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-3 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          openInvestigation(alert);
                        }}
                        className="px-2.5 py-1 text-xs bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg inline-flex items-center gap-1 transition"
                      >
                        <Eye className="w-3 h-3" /> Triage
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ======================================================== */}
      {/* COMPREHENSIVE MULTI-TAB INVESTIGATION DRAWER */}
      {/* ======================================================== */}
      {activeAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="cyber-card w-full max-w-4xl bg-[#090d20] border-cyan-400/50 shadow-[0_0_40px_rgba(6,182,212,0.25)] flex flex-col max-h-[90vh]">
            
            {/* Drawer Header */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-3">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center text-cyan-400">
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-white font-mono">
                      {activeAlert.alert_id}
                    </h3>
                    {getPriorityBadge(activeAlert.priority, activeAlert.risk_score)}
                    {getSeverityBadge(activeAlert.severity)}
                    {activeAlert.occurrence_count > 1 && (
                      <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 text-[10px] font-bold">
                        Deduplicated: {activeAlert.occurrence_count} Occurrences
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">{activeAlert.title}</p>
                </div>
              </div>
              
              <button
                onClick={() => setActiveAlert(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Quick Action Triage Bar */}
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs font-mono mb-3">
              <div className="flex items-center gap-1.5">
                <span className="text-slate-400 font-bold">Status:</span>
                {['New', 'Investigating', 'Escalated', 'Resolved', 'False Positive'].map((st) => (
                  <button
                    key={st}
                    disabled={updatingStatus}
                    onClick={() => handleUpdateStatus(activeAlert.alert_id || String(activeAlert.id), st)}
                    className={`px-2 py-1 rounded text-[11px] font-bold transition cursor-pointer ${
                      activeAlert.status === st
                        ? 'bg-cyan-500 text-black shadow-[0_0_8px_rgba(6,182,212,0.4)]'
                        : 'bg-slate-800 text-slate-400 hover:text-white'
                    }`}
                  >
                    {st}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-2">
                <span className="text-slate-400 font-bold">Assignee:</span>
                <select
                  value={activeAlert.assigned_to || ''}
                  onChange={(e) => handleAssignAnalyst(activeAlert.alert_id || String(activeAlert.id), e.target.value)}
                  className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded px-2 py-1 outline-none focus:border-cyan-400"
                >
                  <option value="">Unassigned</option>
                  <option value="SecOps Commander">SecOps Commander (Tier 3)</option>
                  <option value="Tier 2 Analyst">Tier 2 Incident Analyst</option>
                  <option value="SOC Analyst Alpha">SOC Analyst Alpha (Tier 1)</option>
                  <option value="AI Automated Copilot">AI Automated Copilot</option>
                </select>
              </div>
            </div>

            {/* Drawer Tab Navigation */}
            <div className="flex border-b border-slate-800 font-mono text-xs overflow-x-auto gap-1 mb-3">
              {[
                { id: 'overview', label: 'Risk & Overview', icon: Sliders },
                { id: 'timeline', label: 'Attack Timeline', icon: Clock },
                { id: 'intel', label: 'Threat Intelligence', icon: Globe },
                { id: 'ai', label: 'AI Copilot Analysis', icon: Bot },
                { id: 'evidence', label: 'Contributing Logs', icon: Database },
                { id: 'soar', label: 'SOAR Remediation', icon: Play },
                { id: 'audit', label: 'Notes & Audit Trail', icon: FileText },
              ].map((tab) => {
                const Icon = tab.icon;
                const isActive = drawerTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => {
                      setDrawerTab(tab.id as any);
                      if (tab.id === 'timeline' && timelineData.length === 0) {
                        fetchTimeline(activeAlert.alert_id || String(activeAlert.id));
                      }
                      if (tab.id === 'ai' && !aiAnalysis) {
                        fetchAiAnalysis(activeAlert.alert_id || String(activeAlert.id));
                      }
                    }}
                    className={`flex items-center gap-1.5 px-3 py-2 border-b-2 font-bold whitespace-nowrap transition cursor-pointer ${
                      isActive
                        ? 'border-cyan-400 text-cyan-400 bg-cyan-950/20'
                        : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </div>

            {/* Drawer Tab Content Container */}
            <div className="flex-1 overflow-y-auto pr-1 font-mono text-xs space-y-4">
              
              {/* TAB 1: OVERVIEW & RISK FACTORS */}
              {drawerTab === 'overview' && (
                <div className="space-y-4">
                  {/* Risk Score Progress & Breakdown */}
                  <div className="cyber-card p-4 space-y-3">
                    <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                      <div className="flex items-center gap-2">
                        <Sliders className="w-4 h-4 text-cyan-400" />
                        <h4 className="font-bold text-white text-xs uppercase">
                          Intelligent Risk Scoring (0–100 Model)
                        </h4>
                      </div>
                      <span className="text-cyan-400 font-bold text-sm">
                        {activeAlert.risk_score} / 100 ({activeAlert.priority})
                      </span>
                    </div>

                    <div className="w-full bg-slate-900 h-2.5 rounded-full overflow-hidden border border-slate-800">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          activeAlert.risk_score >= 80 ? 'bg-rose-500' :
                          activeAlert.risk_score >= 60 ? 'bg-amber-400' :
                          activeAlert.risk_score >= 40 ? 'bg-cyan-400' : 'bg-emerald-400'
                        }`}
                        style={{ width: `${Math.min(100, activeAlert.risk_score)}%` }}
                      />
                    </div>

                    {/* Contributing Factor Matrix */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 pt-2">
                      {(activeAlert.risk_factors || [
                        { factor: 'Detection Severity', points: 25, max: 35, description: `${activeAlert.severity} rule trigger condition matched.` },
                        { factor: 'Asset Criticality', points: 10, max: 25, description: 'Internal production infrastructure evaluated.' },
                        { factor: 'Threat Intelligence', points: 25, max: 25, description: activeAlert.threat_intel?.details || 'Indicator classified in active threat intelligence feeds.' },
                        { factor: 'Event Frequency', points: (activeAlert.occurrence_count - 1) * 3, max: 15, description: `${activeAlert.occurrence_count} deduplicated events in sliding window.` },
                      ]).map((rf, idx) => (
                        <div key={`${rf.factor}-${idx}`} className="p-2.5 rounded bg-slate-900/80 border border-slate-800 space-y-1">
                          <div className="flex justify-between items-center text-[11px]">
                            <span className="font-bold text-slate-300">{rf.factor}</span>
                            <span className="text-cyan-400 font-bold">+{rf.points} pts</span>
                          </div>
                          <p className="text-[10px] text-slate-400 leading-snug">{rf.description}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Forensic Description */}
                  <div className="p-3.5 rounded bg-slate-950 border border-slate-800 space-y-1.5">
                    <p className="text-cyan-400 font-bold uppercase text-[11px]">
                      Detection Rationale & Rule Trigger:
                    </p>
                    <p className="text-slate-200 leading-relaxed text-[11px]">
                      {activeAlert.evidence?.trigger_condition || activeAlert.description}
                    </p>
                  </div>

                  {/* Forensic Parameter JSON Payload */}
                  <div className="space-y-1">
                    <span className="text-slate-400 font-bold text-[11px]">Forensic Telemetry Parameter Payload:</span>
                    <pre className="p-3 rounded bg-black/60 border border-slate-800 text-cyan-300 overflow-x-auto text-[10px] leading-tight max-h-48">
                      {JSON.stringify(activeAlert.evidence, null, 2)}
                    </pre>
                  </div>
                </div>
              )}

              {/* TAB 2: ATTACK TIMELINE */}
              {drawerTab === 'timeline' && (
                <div className="space-y-3">
                  <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                    <h4 className="font-bold text-white text-xs uppercase flex items-center gap-1.5">
                      <Clock className="w-4 h-4 text-cyan-400" />
                      Chronological Attack & Triage Timeline
                    </h4>
                    <button
                      onClick={() => fetchTimeline(activeAlert.alert_id || String(activeAlert.id))}
                      className="text-xs text-cyan-400 hover:underline flex items-center gap-1"
                    >
                      <RotateCcw className="w-3 h-3" /> Refresh Timeline
                    </button>
                  </div>

                  {loadingTimeline ? (
                    <div className="p-8 text-center text-slate-500">
                      <Loader2 className="w-5 h-5 animate-spin mx-auto mb-2 text-cyan-400" />
                      Reconstructing event timeline...
                    </div>
                  ) : timelineData.length === 0 ? (
                    <div className="p-6 text-center text-slate-500 border border-slate-800 rounded">
                      Timeline initialized. Click refresh or wait for subsequent logs.
                    </div>
                  ) : (
                    <div className="relative border-l border-cyan-500/30 pl-5 ml-3 space-y-4">
                      {timelineData.map((item, idx) => (
                        <div key={`${item.title}-${idx}`} className="relative group">
                          {/* Timeline Node Dot */}
                          <div className={`absolute -left-[27px] top-1 w-3.5 h-3.5 rounded-full border-2 ${
                            item.stage === 'detection' ? 'bg-rose-500 border-rose-300 animate-pulse' :
                            item.stage === 'enrichment' ? 'bg-cyan-400 border-cyan-200' :
                            item.stage === 'analyst' ? 'bg-purple-400 border-purple-200' : 'bg-slate-700 border-slate-500'
                          }`} />

                          <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800/80 space-y-1">
                            <div className="flex justify-between items-center">
                              <span className="font-bold text-slate-200 text-xs">{item.title}</span>
                              <span className="text-[10px] text-slate-500">
                                {item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : 'N/A'}
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-300 leading-relaxed">{item.details}</p>
                            <span className="text-[9px] text-cyan-400/80 uppercase font-bold block pt-1">
                              Entity / Actor: {item.actor}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* TAB 3: THREAT INTELLIGENCE */}
              {drawerTab === 'intel' && (
                <div className="space-y-4">
                  <div className="cyber-card p-4 space-y-3">
                    <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                      <h4 className="font-bold text-white text-xs uppercase flex items-center gap-1.5">
                        <Globe className="w-4 h-4 text-cyan-400" />
                        Target Indicator Threat Intelligence Enrichment
                      </h4>
                      {getThreatIntelBadge(activeAlert.threat_intel)}
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                        <span className="text-[10px] text-slate-400 uppercase block">Indicator</span>
                        <div className="font-bold text-cyan-300 text-xs truncate mt-0.5">
                          {activeAlert.threat_intel?.indicator || activeAlert.source_ip || 'N/A'}
                        </div>
                      </div>

                      <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                        <span className="text-[10px] text-slate-400 uppercase block">Attributed Actor</span>
                        <div className="font-bold text-white text-xs truncate mt-0.5">
                          {activeAlert.threat_intel?.threat_actor || 'Unattributed'}
                        </div>
                      </div>

                      <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                        <span className="text-[10px] text-slate-400 uppercase block">Threat Category</span>
                        <div className="font-bold text-purple-300 text-xs truncate mt-0.5">
                          {activeAlert.threat_intel?.category || 'Unclassified'}
                        </div>
                      </div>

                      <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                        <span className="text-[10px] text-slate-400 uppercase block">Confidence Score</span>
                        <div className="font-bold text-emerald-400 text-xs mt-0.5">
                          {activeAlert.threat_intel?.score || 94}% Confidence
                        </div>
                      </div>
                    </div>

                    <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
                      <span className="text-slate-400 font-bold text-[10px] uppercase">Intelligence Dossier & Feed Source:</span>
                      <p className="text-slate-300 text-xs leading-relaxed">
                        {activeAlert.threat_intel?.details || 'Observed conducting automated credential harvesting and port reconnaissance across external honeygrids.'}
                      </p>
                      <div className="text-[10px] text-slate-500 pt-1 border-t border-slate-900 flex justify-between">
                        <span>Source: {activeAlert.threat_intel?.source || 'AlienVault OTX & AbuseIPDB Feed'}</span>
                        <span>Retrieved: {activeAlert.threat_intel?.retrieval_timestamp ? new Date(activeAlert.threat_intel.retrieval_timestamp).toLocaleString() : 'Just now'}</span>
                      </div>
                    </div>

                    <div className="p-2.5 rounded bg-cyan-950/30 border border-cyan-800/40 text-cyan-200 text-[11px]">
                      <strong>Verification Integrity Protocol: </strong>
                      Indicators classified as &apos;Unknown&apos; are never treated as confirmed malicious without secondary correlation against authentication logs or host-based forensics.
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 4: AI COPILOT ANALYSIS */}
              {drawerTab === 'ai' && (
                <div className="space-y-4">
                  <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                    <h4 className="font-bold text-white text-xs uppercase flex items-center gap-1.5">
                      <Bot className="w-4 h-4 text-purple-400" />
                      Evidence-Grounded AI Copilot Investigation
                    </h4>
                    <button
                      disabled={loadingAi}
                      onClick={() => fetchAiAnalysis(activeAlert.alert_id || String(activeAlert.id))}
                      className="px-3 py-1 bg-purple-600 hover:bg-purple-500 text-white rounded text-xs font-bold transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                    >
                      {loadingAi ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Bot className="w-3.5 h-3.5" />}
                      <span>Re-Analyze</span>
                    </button>
                  </div>

                  {loadingAi ? (
                    <div className="p-8 text-center text-slate-500">
                      <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2 text-purple-400" />
                      Synthesizing factual evidence into investigation brief...
                    </div>
                  ) : aiAnalysis ? (
                    <div className="space-y-3 font-mono text-xs">
                      {/* Summary */}
                      <div className="p-3.5 rounded bg-purple-950/20 border border-purple-800/40 space-y-1">
                        <span className="text-purple-300 font-bold uppercase text-[10px]">Executive Summary:</span>
                        <p className="text-slate-200 leading-relaxed text-[11px]">{aiAnalysis.alert_summary}</p>
                      </div>

                      {/* Technical Reason & Impact */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div className="p-3 rounded bg-slate-900/80 border border-slate-800 space-y-1">
                          <span className="text-cyan-400 font-bold uppercase text-[10px]">Reason for Detection:</span>
                          <p className="text-slate-300 text-[11px] leading-relaxed">{aiAnalysis.reason_for_detection}</p>
                        </div>
                        <div className="p-3 rounded bg-slate-900/80 border border-slate-800 space-y-1">
                          <span className="text-rose-400 font-bold uppercase text-[10px]">Potential Business Impact:</span>
                          <p className="text-slate-300 text-[11px] leading-relaxed">{aiAnalysis.potential_impact}</p>
                        </div>
                      </div>

                      {/* Suggested Investigation Steps */}
                      <div className="p-3.5 rounded bg-slate-950 border border-slate-800 space-y-1.5">
                        <span className="text-emerald-400 font-bold uppercase text-[10px]">Recommended Investigation Playbook:</span>
                        <div className="space-y-1">
                          {(aiAnalysis.suggested_investigation_steps || []).map((step: string, sIdx: number) => (
                            <p key={sIdx} className="text-slate-200 text-[11px] leading-relaxed">{step}</p>
                          ))}
                        </div>
                      </div>

                      {/* Confidence & Grounding Disclaimer */}
                      <div className="p-2.5 rounded bg-slate-900 border border-slate-800 flex justify-between items-center text-[10px] text-slate-400">
                        <span>Analysis Confidence: <strong className="text-purple-300">{aiAnalysis.confidence_score}% (Evidence Grounded)</strong></span>
                        <span className="text-slate-500 italic max-w-xs truncate">{aiAnalysis.limitations}</span>
                      </div>
                    </div>
                  ) : (
                    <div className="p-8 text-center text-slate-500 border border-slate-800 rounded">
                      Click &quot;Re-Analyze&quot; above to synthesize evidence with the AI Copilot.
                    </div>
                  )}
                </div>
              )}

              {/* TAB 5: CONTRIBUTING LOGS */}
              {drawerTab === 'evidence' && (
                <div className="space-y-3">
                  <h4 className="font-bold text-white text-xs uppercase flex items-center gap-1.5 border-b border-slate-800 pb-2">
                    <Database className="w-4 h-4 text-cyan-400" />
                    Contributing Normalized Event Sequence ({activeAlert.matched_event_ids?.length || 0})
                  </h4>

                  <div className="flex flex-wrap gap-1.5">
                    {Array.from(new Set(activeAlert.matched_event_ids || [])).map((eid, idx) => (
                      <span key={`${eid}-${idx}`} className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-cyan-300 font-bold text-[10px]">
                        {eid}
                      </span>
                    ))}
                  </div>

                  <div className="space-y-1 pt-2">
                    <span className="text-slate-400 font-bold text-[10px]">Evidence Parameter Dump:</span>
                    <pre className="p-3.5 rounded bg-black/70 border border-slate-800 text-cyan-300 overflow-x-auto text-[10px] leading-tight">
                      {JSON.stringify(activeAlert.evidence, null, 2)}
                    </pre>
                  </div>
                </div>
              )}

              {/* TAB 6: SOAR REMEDIATION */}
              {drawerTab === 'soar' && (
                <div className="space-y-4">
                  <div className="cyber-card p-4 space-y-3">
                    <h4 className="font-bold text-white text-xs uppercase flex items-center gap-1.5 border-b border-slate-800 pb-2">
                      <Play className="w-4 h-4 text-cyan-400" />
                      Targeted SOAR Mitigation Playbooks
                    </h4>

                    <p className="text-[11px] text-slate-300">
                      All impactful actions require Tier 3 authorization. In Demo Mode, actions simulate real containment while recording full audit logs.
                    </p>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
                      <button
                        disabled={soarActionRunning !== null}
                        onClick={() => handleRunSoarAction('block_ip')}
                        className="p-3 text-left rounded bg-slate-900 hover:bg-slate-850 border border-rose-500/40 hover:border-rose-400 text-slate-200 transition space-y-1 cursor-pointer disabled:opacity-50"
                      >
                        <div className="flex justify-between items-center">
                          <span className="font-bold text-rose-400 text-xs">Block Source IP</span>
                          {soarActionRunning === 'block_ip' && <Loader2 className="w-3.5 h-3.5 animate-spin text-rose-400" />}
                        </div>
                        <p className="text-[10px] text-slate-400">
                          Applies drop policy to {activeAlert.source_ip || 'target IP'} on perimeter firewalls.
                        </p>
                      </button>

                      <button
                        disabled={soarActionRunning !== null}
                        onClick={() => handleRunSoarAction('isolate_host')}
                        className="p-3 text-left rounded bg-slate-900 hover:bg-slate-850 border border-amber-500/40 hover:border-amber-400 text-slate-200 transition space-y-1 cursor-pointer disabled:opacity-50"
                      >
                        <div className="flex justify-between items-center">
                          <span className="font-bold text-amber-400 text-xs">Isolate Host (EDR)</span>
                          {soarActionRunning === 'isolate_host' && <Loader2 className="w-3.5 h-3.5 animate-spin text-amber-400" />}
                        </div>
                        <p className="text-[10px] text-slate-400">
                          Quarantines endpoint workstation to stop lateral movement.
                        </p>
                      </button>

                      <button
                        disabled={soarActionRunning !== null}
                        onClick={() => handleRunSoarAction('disable_user')}
                        className="p-3 text-left rounded bg-slate-900 hover:bg-slate-850 border border-purple-500/40 hover:border-purple-400 text-slate-200 transition space-y-1 cursor-pointer disabled:opacity-50"
                      >
                        <div className="flex justify-between items-center">
                          <span className="font-bold text-purple-400 text-xs">Revoke & Disable User</span>
                          {soarActionRunning === 'disable_user' && <Loader2 className="w-3.5 h-3.5 animate-spin text-purple-400" />}
                        </div>
                        <p className="text-[10px] text-slate-400">
                          Revokes Kerberos tokens for {activeAlert.username || 'target account'} in Active Directory.
                        </p>
                      </button>

                      <button
                        disabled={soarActionRunning !== null}
                        onClick={() => handleRunSoarAction('trigger_playbook')}
                        className="p-3 text-left rounded bg-slate-900 hover:bg-slate-850 border border-cyan-500/40 hover:border-cyan-400 text-slate-200 transition space-y-1 cursor-pointer disabled:opacity-50"
                      >
                        <div className="flex justify-between items-center">
                          <span className="font-bold text-cyan-400 text-xs">Run Incident Playbook</span>
                          {soarActionRunning === 'trigger_playbook' && <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />}
                        </div>
                        <p className="text-[10px] text-slate-400">
                          Executes multi-step enrichment, quarantine, and Slack notification.
                        </p>
                      </button>
                    </div>

                    {soarResult && (
                      <div className="mt-3 p-3 rounded bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 text-xs font-bold">
                        ✓ {soarResult}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* TAB 7: NOTES & AUDIT TRAIL */}
              {drawerTab === 'audit' && (
                <div className="space-y-4">
                  {/* Add Note Form */}
                  <form onSubmit={handleAddNote} className="flex gap-2">
                    <input
                      type="text"
                      placeholder="Add investigation triage note (e.g. Verified with user)..."
                      value={newNote}
                      onChange={(e) => setNewNote(e.target.value)}
                      className="flex-1 bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-400"
                    />
                    <button
                      type="submit"
                      disabled={submittingNote || !newNote.trim()}
                      className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-black font-bold rounded text-xs transition cursor-pointer disabled:opacity-50"
                    >
                      {submittingNote ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Add Note'}
                    </button>
                  </form>

                  {/* Notes Feed */}
                  {activeAlert.notes && activeAlert.notes.length > 0 && (
                    <div className="space-y-2">
                      <span className="text-slate-400 font-bold text-[10px] uppercase">Analyst Notes:</span>
                      {activeAlert.notes.map((n, idx) => (
                        <div key={`${n.id}-${idx}`} className="p-2.5 rounded bg-slate-900/60 border border-slate-800 space-y-0.5">
                          <div className="flex justify-between items-center text-[10px] text-cyan-400">
                            <strong>{n.author}</strong>
                            <span className="text-slate-500">{new Date(n.timestamp).toLocaleTimeString()}</span>
                          </div>
                          <p className="text-slate-200 text-[11px]">{n.text}</p>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Immutable Audit Trail */}
                  <div className="space-y-2 pt-2 border-t border-slate-800">
                    <span className="text-slate-400 font-bold text-[10px] uppercase">Immutable Triage Audit Trail:</span>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto">
                      {(activeAlert.audit_trail || []).map((at, idx) => (
                        <div key={idx} className="p-2 rounded bg-black/40 border border-slate-900 text-[10px] text-slate-400 flex justify-between items-center">
                          <div>
                            <span className="text-cyan-300 font-bold">{at.action}</span>
                            <span className="text-slate-500 ml-2">by {at.actor}</span>
                          </div>
                          <span className="text-slate-600 font-mono">
                            {at.timestamp ? new Date(at.timestamp).toLocaleTimeString() : 'N/A'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

            </div>

            {/* Drawer Footer */}
            <div className="flex justify-between items-center pt-3 border-t border-slate-800 mt-2 font-mono text-xs">
              <span className="text-slate-500 text-[10px]">
                {activeAlert.correlation_id ? `Linked to Correlation Group: ${activeAlert.correlation_id}` : 'Independent Triage Alert'}
              </span>
              <button
                onClick={() => setActiveAlert(null)}
                className="px-5 py-2 text-xs font-mono font-bold bg-slate-800 hover:bg-slate-700 text-white rounded transition cursor-pointer"
              >
                Close Drawer
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
