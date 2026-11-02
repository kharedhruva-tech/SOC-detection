'use client';

import React, { useState, useEffect, useMemo } from 'react';
import Link from 'next/link';
import {
  Users,
  ShieldAlert,
  ShieldCheck,
  Clock,
  Globe,
  Activity,
  Sparkles,
  RotateCw,
  Search,
  Filter,
  X,
  ChevronRight,
  Copy,
  Check,
  ExternalLink,
  AlertTriangle,
  Cpu,
  FileText,
  Database,
  Lock,
  Server,
  TrendingUp,
  Bot,
  Zap,
  CheckCircle2,
  Radio,
  Sliders,
  Eye,
  ArrowUpRight,
  UserCheck,
  AlertOctagon
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
  PieChart,
  Pie,
  AreaChart,
  Area
} from 'recharts';
import { api, WS_BASE_URL } from '@/utils/api';

export interface UEBAProfileItem {
  id: number;
  entity_id: string;
  entity_type: string;
  display_name?: string;
  baseline_status: string;
  risk_score: number;
  risk_level: string;
  learning_started_at?: string;
  last_updated_at?: string;
  baseline_version: number;
  metadata_info?: Record<string, any>;
  anomalies_count: number;
}

export interface UEBAFindingItem {
  id: number;
  finding_id: string;
  entity_id: string;
  entity_type: string;
  anomaly_type: string;
  detection_method: string;
  risk_score: number;
  confidence: number;
  severity: string;
  title: string;
  description: string;
  evidence: Record<string, any>;
  related_event_ids?: string[];
  recommended_steps?: string[];
  status: string;
  assigned_to?: string;
  is_demo?: boolean;
  created_at: string;
}

export default function UEBAPage() {
  const [activeTab, setActiveTab] = useState<'overview' | 'users' | 'entities' | 'findings' | 'demo'>('overview');
  const [stats, setStats] = useState<any>(null);
  const [profiles, setProfiles] = useState<UEBAProfileItem[]>([]);
  const [findings, setFindings] = useState<UEBAFindingItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [wsConnected, setWsConnected] = useState<boolean>(false);

  // Filters for findings
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  const [statusFilter, setStatusFilter] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Selected finding / entity for investigation drawer
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [findingDetail, setFindingDetail] = useState<any>(null);
  const [detailLoading, setDetailLoading] = useState<boolean>(false);

  // Selected profile detail modal
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(null);
  const [profileDetail, setProfileDetail] = useState<any>(null);
  const [profileLoading, setProfileLoading] = useState<boolean>(false);

  // AI Analyst Copilot State
  const [aiAnalysis, setAiAnalysis] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState<boolean>(false);

  // Demo Generation state
  const [demoRunning, setDemoRunning] = useState<boolean>(false);
  const [demoMessage, setDemoMessage] = useState<string | null>(null);

  // Initial data fetch & WebSocket connection
  useEffect(() => {
    fetchUEBAData();

    // WebSocket listener for live findings
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
            if (data.type === 'NEW_UEBA_FINDING' && data.finding_id) {
              const newFinding: UEBAFindingItem = {
                id: Math.floor(Math.random() * 100000),
                finding_id: data.finding_id,
                entity_id: data.entity_id,
                entity_type: data.entity_type || 'user',
                anomaly_type: data.anomaly_type,
                detection_method: data.detection_method,
                risk_score: data.risk_score || 70,
                confidence: 0.85,
                severity: data.severity || 'High',
                title: data.title,
                description: data.description,
                evidence: {},
                status: 'New',
                is_demo: data.is_demo,
                created_at: data.timestamp || new Date().toISOString()
              };

              setFindings((prev) => [newFinding, ...prev.slice(0, 49)]);
              // Increment anomalies count in dashboard stats
              setStats((prev: any) => prev ? {
                ...prev,
                new_findings_count: (prev.new_findings_count || 0) + 1,
                entities_with_anomalies: (prev.entities_with_anomalies || 0) + 1
              } : prev);
            }
          } catch (e) {
            // Ignore parse errors
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

  const fetchUEBAData = async () => {
    try {
      setLoading(true);
      // 1. Dashboard stats
      const statsData = await api.get('/ueba/dashboard').catch(() => null);
      if (statsData) setStats(statsData);

      // 2. Monitored Profiles
      const profilesData = await api.get('/ueba/profiles').catch(() => ({ items: [] }));
      if (profilesData && Array.isArray(profilesData.items)) {
        setProfiles(profilesData.items);
      }

      // 3. Findings list
      const findingsData = await api.get('/ueba/findings').catch(() => ({ items: [] }));
      if (findingsData && Array.isArray(findingsData.items)) {
        setFindings(findingsData.items);
      }
    } catch (err) {
      console.error('Failed to load UEBA data:', err);
    } finally {
      setLoading(false);
    }
  };

  // Fetch finding detail
  useEffect(() => {
    if (!selectedFindingId) {
      setFindingDetail(null);
      setAiAnalysis(null);
      return;
    }
    const fetchDetail = async () => {
      setDetailLoading(true);
      try {
        const data = await api.get(`/ueba/findings/${selectedFindingId}`);
        setFindingDetail(data);
      } catch (err) {
        console.error('Failed to fetch finding detail:', err);
      } finally {
        setDetailLoading(false);
      }
    };
    fetchDetail();
  }, [selectedFindingId]);

  // Fetch profile detail
  useEffect(() => {
    if (!selectedProfileId) {
      setProfileDetail(null);
      return;
    }
    const fetchProf = async () => {
      setProfileLoading(true);
      try {
        const data = await api.get(`/ueba/profiles/${selectedProfileId}`);
        setProfileDetail(data);
      } catch (err) {
        console.error('Failed to fetch profile detail:', err);
      } finally {
        setProfileLoading(false);
      }
    };
    fetchProf();
  }, [selectedProfileId]);

  // Run AI Copilot on finding
  const handleRunAiAnalysis = async (findingId: string) => {
    try {
      setAiLoading(true);
      const res = await api.post('/ueba/ai/analyze', { finding_id: findingId });
      setAiAnalysis(res);
    } catch (err) {
      console.error('AI Analysis failed:', err);
    } finally {
      setAiLoading(false);
    }
  };

  // Update finding status
  const handleUpdateStatus = async (findingId: string, newStatus: string) => {
    try {
      await api.patch(`/ueba/findings/${findingId}`, {
        status: newStatus,
        comments: `Status updated to ${newStatus} by analyst.`
      });
      // Refresh local state
      setFindings((prev) =>
        prev.map((f) => (f.finding_id === findingId ? { ...f, status: newStatus } : f))
      );
      if (findingDetail && findingDetail.finding_id === findingId) {
        setFindingDetail((prev: any) => ({ ...prev, status: newStatus }));
      }
    } catch (err) {
      console.error('Failed to update finding status:', err);
    }
  };

  // Submit Feedback
  const handleSubmitFeedback = async (findingId: string, feedbackType: string) => {
    try {
      await api.post('/ueba/feedback', {
        finding_id: findingId,
        feedback_type: feedbackType,
        comments: `Analyst classified finding as ${feedbackType}.`
      });
      setDemoMessage(`Feedback '${feedbackType}' successfully logged in audit trail.`);
      setTimeout(() => setDemoMessage(null), 4000);
      handleUpdateStatus(findingId, feedbackType === 'False Positive' ? 'False Positive' : 'Investigating');
    } catch (err) {
      console.error('Failed to submit feedback:', err);
    }
  };

  // Trigger Demo Scenario
  const handleTriggerScenario = async (scenario: string) => {
    try {
      setDemoRunning(true);
      setDemoMessage(null);
      const res = await api.post('/ueba/demo/generate', { scenario });
      setDemoMessage(`Scenario executed: ${res.message || 'Synthetic anomaly injected successfully.'}`);
      setTimeout(() => setDemoMessage(null), 5000);
      fetchUEBAData();
    } catch (err: any) {
      setDemoMessage(`Simulation error: ${err.message || 'Server error'}`);
    } finally {
      setDemoRunning(false);
    }
  };

  // Rebuild all baselines
  const handleRebuildBaselines = async () => {
    try {
      setDemoRunning(true);
      const res = await api.post('/ueba/baselines/rebuild');
      setDemoMessage(`Baselines Rebuilt: Processed ${res.rebuilt_count || 0} user & entity profiles.`);
      setTimeout(() => setDemoMessage(null), 5000);
      fetchUEBAData();
    } catch (err: any) {
      setDemoMessage(`Rebuild error: ${err.message || 'Server error'}`);
    } finally {
      setDemoRunning(false);
    }
  };

  // Filtered findings list
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (severityFilter !== 'All' && f.severity?.toLowerCase() !== severityFilter.toLowerCase()) return false;
      if (statusFilter !== 'All' && f.status?.toLowerCase() !== statusFilter.toLowerCase()) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matches =
          f.finding_id.toLowerCase().includes(q) ||
          f.entity_id.toLowerCase().includes(q) ||
          f.title.toLowerCase().includes(q) ||
          f.anomaly_type.toLowerCase().includes(q);
        if (!matches) return false;
      }
      return true;
    });
  }, [findings, severityFilter, statusFilter, searchQuery]);

  // Risk badge styling
  const getRiskBadge = (score: number, level?: string) => {
    const s = level || (score >= 75 ? 'Critical' : score >= 50 ? 'High' : score >= 30 ? 'Medium' : 'Low');
    switch (s.toLowerCase()) {
      case 'critical':
        return 'bg-rose-950/60 text-rose-400 border-rose-500/50';
      case 'high':
        return 'bg-amber-950/60 text-amber-400 border-amber-500/50';
      case 'medium':
        return 'bg-yellow-950/60 text-yellow-300 border-yellow-500/50';
      default:
        return 'bg-emerald-950/60 text-emerald-300 border-emerald-500/50';
    }
  };

  // Baseline Status Badge
  const getBaselineStatusBadge = (st: string) => {
    switch (st) {
      case 'Established':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
            <Check className="w-3 h-3 text-emerald-400" /> Established
          </span>
        );
      case 'Learning':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
            <Activity className="w-3 h-3 text-cyan-400 animate-pulse" /> Learning
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
            <Clock className="w-3 h-3" /> Insufficient Data
          </span>
        );
    }
  };

  // Hourly login distribution mock data from typical baseline
  const hourlyChartData = [
    { hour: '00:00', events: 2 },
    { hour: '02:00', events: 1 },
    { hour: '04:00', events: 0 },
    { hour: '06:00', events: 4 },
    { hour: '08:00', events: 32 },
    { hour: '10:00', events: 78 },
    { hour: '12:00', events: 65 },
    { hour: '14:00', events: 82 },
    { hour: '16:00', events: 70 },
    { hour: '18:00', events: 24 },
    { hour: '20:00', events: 8 },
    { hour: '22:00', events: 4 }
  ];

  const riskPieData = [
    { name: 'Critical', value: stats?.risk_distribution?.Critical || 1, color: '#ef4444' },
    { name: 'High', value: stats?.risk_distribution?.High || 2, color: '#f97316' },
    { name: 'Medium', value: stats?.risk_distribution?.Medium || 3, color: '#eab308' },
    { name: 'Low', value: stats?.risk_distribution?.Low || 8, color: '#10b981' }
  ];

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* 1. Header with Live Telemetry Stream Indicator */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-white font-sans flex items-center gap-2">
              <Users className="w-6 h-6 text-cyan-400" />
              User & Entity Behavior Analytics (UEBA)
            </h1>
            <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
              AURA UEBA v2.4
            </span>
            <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono border bg-slate-900">
              {wsConnected ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-emerald-400 font-semibold">LIVE BASELINE SENSORS</span>
                </>
              ) : (
                <>
                  <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
                  <span className="text-amber-400 font-semibold">CONNECTING...</span>
                </>
              )}
            </div>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Dynamic behavioral baseline learning, statistical Z-score anomaly detection, and explainable risk scoring
          </p>
        </div>

        {/* Global Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={fetchUEBAData}
            disabled={loading}
            className="cyber-button font-mono text-xs"
            title="Refresh UEBA metrics"
          >
            <RotateCw className={`w-3.5 h-3.5 text-cyan-400 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          <button
            onClick={() => setActiveTab('demo')}
            className="cyber-button-primary font-mono text-xs"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Simulate UEBA Scenarios</span>
          </button>
        </div>
      </div>

      {/* Notification Toast */}
      {demoMessage && (
        <div className="p-3 rounded-md bg-cyan-950/60 border border-cyan-500/40 text-cyan-300 text-xs font-mono flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>{demoMessage}</span>
          </div>
          <button onClick={() => setDemoMessage(null)} className="text-cyan-400 hover:text-white">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* 2. Top Metric KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* KPI 1: Monitored Entities */}
        <div className="cyber-card p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
              Monitored Entities
            </span>
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Users className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <h3 className="text-3xl font-extrabold text-white font-mono tracking-tight">
              {stats?.total_monitored_entities ?? profiles.length}
            </h3>
            <p className="text-[11px] font-mono text-slate-400 mt-1">
              <span className="text-cyan-400 font-bold">{stats?.total_monitored_users ?? profiles.filter(p => p.entity_type === 'user').length}</span> Users · <span className="text-slate-300 font-bold">{profiles.filter(p => p.entity_type !== 'user').length}</span> Endpoints/Servers
            </p>
          </div>
        </div>

        {/* KPI 2: Entities With Active Anomalies */}
        <div className="cyber-card p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
              Entities with Anomalies
            </span>
            <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <h3 className="text-3xl font-extrabold text-rose-400 font-mono tracking-tight">
              {stats?.entities_with_anomalies ?? profiles.filter(p => p.anomalies_count > 0).length}
            </h3>
            <p className="text-[11px] font-mono text-rose-300 mt-1 flex items-center gap-1">
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>{stats?.high_risk_entities_count ?? 2} High-Risk Tiers</span>
            </p>
          </div>
        </div>

        {/* KPI 3: New UEBA Findings */}
        <div className="cyber-card p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
              New Anomaly Findings
            </span>
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <h3 className="text-3xl font-extrabold text-amber-400 font-mono tracking-tight">
              {stats?.new_findings_count ?? findings.filter(f => f.status === 'New').length}
            </h3>
            <p className="text-[11px] font-mono text-slate-400 mt-1">
              Total Recorded: <span className="text-white font-bold">{findings.length}</span>
            </p>
          </div>
        </div>

        {/* KPI 4: Established Baselines */}
        <div className="cyber-card p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
              Baseline Status
            </span>
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <h3 className="text-3xl font-extrabold text-emerald-400 font-mono tracking-tight">
              {stats?.baseline_status_breakdown?.Established ?? 3}{' '}
              <span className="text-sm font-normal text-slate-400">Established</span>
            </h3>
            <p className="text-[11px] font-mono text-cyan-400 mt-1">
              {stats?.baseline_status_breakdown?.Learning ?? 1} Profiles in Active Learning
            </p>
          </div>
        </div>
      </div>

      {/* 3. Navigation Tabs */}
      <div className="flex items-center gap-1 border-b border-slate-800 text-xs font-mono">
        <button
          onClick={() => setActiveTab('overview')}
          className={`px-4 py-2.5 font-semibold transition border-b-2 flex items-center gap-2 ${
            activeTab === 'overview'
              ? 'border-cyan-400 text-cyan-400 bg-cyan-950/20'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <Activity className="w-4 h-4" />
          <span>Overview & Heatmaps</span>
        </button>

        <button
          onClick={() => setActiveTab('users')}
          className={`px-4 py-2.5 font-semibold transition border-b-2 flex items-center gap-2 ${
            activeTab === 'users'
              ? 'border-cyan-400 text-cyan-400 bg-cyan-950/20'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <Users className="w-4 h-4" />
          <span>User Profiles ({profiles.filter(p => p.entity_type === 'user').length})</span>
        </button>

        <button
          onClick={() => setActiveTab('entities')}
          className={`px-4 py-2.5 font-semibold transition border-b-2 flex items-center gap-2 ${
            activeTab === 'entities'
              ? 'border-cyan-400 text-cyan-400 bg-cyan-950/20'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <Server className="w-4 h-4" />
          <span>Host & Entity Profiles ({profiles.filter(p => p.entity_type !== 'user').length})</span>
        </button>

        <button
          onClick={() => setActiveTab('findings')}
          className={`px-4 py-2.5 font-semibold transition border-b-2 flex items-center gap-2 ${
            activeTab === 'findings'
              ? 'border-cyan-400 text-cyan-400 bg-cyan-950/20'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          <span>Anomaly Findings ({findings.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('demo')}
          className={`px-4 py-2.5 font-semibold transition border-b-2 flex items-center gap-2 ${
            activeTab === 'demo'
              ? 'border-cyan-400 text-cyan-400 bg-cyan-950/20'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <Sparkles className="w-4 h-4" />
          <span>Simulation Lab</span>
        </button>
      </div>

      {/* 4. TAB CONTENT */}

      {/* TAB 1: OVERVIEW & ANALYTICS */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Login Hour Baseline Distribution */}
            <div className="cyber-card p-6 lg:col-span-2 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <h3 className="text-sm font-bold uppercase text-white font-mono flex items-center gap-2">
                    <Clock className="w-4 h-4 text-cyan-400" />
                    Enterprise Login Hours Distribution Baseline
                  </h3>
                  <p className="text-xs text-slate-400 font-mono">
                    Aggregated historical authentication frequency by hour of day (UTC)
                  </p>
                </div>
                <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/40 border border-emerald-500/40 px-2 py-0.5 rounded">
                  TYPICAL PEAK: 09:00 - 17:00 UTC
                </span>
              </div>

              <div className="h-60">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={hourlyChartData}>
                    <XAxis dataKey="hour" stroke="#475569" fontSize={11} className="font-mono" />
                    <YAxis stroke="#475569" fontSize={11} className="font-mono" />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0b0f19', border: '1px solid #1e293b', borderRadius: '6px' }}
                      labelStyle={{ color: '#94a3b8', fontFamily: 'monospace' }}
                    />
                    <Bar dataKey="events" fill="#00f0ff" radius={[4, 4, 0, 0]}>
                      {hourlyChartData.map((entry, idx) => (
                        <Cell
                          key={`cell-${idx}`}
                          fill={idx < 3 || idx > 10 ? '#ef4444' : '#00f0ff'}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="text-[11px] font-mono text-slate-400 flex items-center justify-between pt-2 border-t border-slate-800/60">
                <span className="flex items-center gap-1.5 text-cyan-400">
                  <span className="w-2.5 h-2.5 rounded bg-cyan-400" /> Standard Business Activity
                </span>
                <span className="flex items-center gap-1.5 text-rose-400">
                  <span className="w-2.5 h-2.5 rounded bg-rose-500" /> Off-Hours Anomaly Trigger Zone
                </span>
              </div>
            </div>

            {/* Risk Score Distribution */}
            <div className="cyber-card p-6 space-y-4">
              <div className="border-b border-slate-800 pb-3">
                <h3 className="text-sm font-bold uppercase text-white font-mono flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-cyan-400" />
                  Entity Risk Distribution
                </h3>
                <p className="text-xs text-slate-400 font-mono">
                  Current behavioral risk classification across entities
                </p>
              </div>

              <div className="h-52">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={riskPieData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={75}
                      paddingAngle={4}
                    >
                      {riskPieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0b0f19', border: '1px solid #1e293b', borderRadius: '6px' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[10px] font-mono">
                {riskPieData.map((d) => (
                  <div key={d.name} className="flex items-center justify-between p-1.5 rounded bg-slate-900 border border-slate-800">
                    <span className="flex items-center gap-1.5" style={{ color: d.color }}>
                      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} />
                      {d.name}
                    </span>
                    <span className="font-bold text-white">{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Recent Findings Quick Table */}
          <div className="cyber-card p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold uppercase text-white font-mono flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-cyan-400" />
                  Live Behavioral Anomaly Stream
                </h3>
                <p className="text-xs text-slate-400 font-mono">
                  Latest security deviations flagged by rule-based and statistical engines
                </p>
              </div>
              <button
                onClick={() => setActiveTab('findings')}
                className="text-xs font-mono text-cyan-400 hover:text-white flex items-center gap-1"
              >
                <span>View All Findings ({findings.length})</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 text-[11px] uppercase">
                  <tr>
                    <th className="py-2.5 px-3">Finding ID</th>
                    <th className="py-2.5 px-3">Entity</th>
                    <th className="py-2.5 px-3">Anomaly Type</th>
                    <th className="py-2.5 px-3">Method</th>
                    <th className="py-2.5 px-3">Risk Score</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3 text-right">Inspect</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-850 bg-slate-950/30">
                  {findings.slice(0, 5).map((f) => (
                    <tr
                      key={f.finding_id}
                      onClick={() => setSelectedFindingId(f.finding_id)}
                      className="hover:bg-slate-900/80 cursor-pointer transition"
                    >
                      <td className="py-2.5 px-3 text-cyan-400 font-bold">{f.finding_id}</td>
                      <td className="py-2.5 px-3 text-slate-200">@{f.entity_id}</td>
                      <td className="py-2.5 px-3 text-white font-semibold">{f.anomaly_type}</td>
                      <td className="py-2.5 px-3 text-slate-400">{f.detection_method}</td>
                      <td className="py-2.5 px-3">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${getRiskBadge(f.risk_score, f.severity)}`}>
                          {f.risk_score}/100 ({f.severity})
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-slate-900 border border-slate-700 text-slate-300">
                          {f.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button className="px-2 py-1 rounded bg-slate-900 border border-slate-700 hover:border-cyan-400 text-cyan-400 text-[11px]">
                          Investigate
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: USER BEHAVIOUR PROFILES */}
      {activeTab === 'users' && (
        <div className="space-y-4">
          <div className="cyber-card p-4 flex items-center justify-between text-xs font-mono">
            <span className="text-slate-300">
              Active Monitored User Identities ({profiles.filter(p => p.entity_type === 'user').length})
            </span>
            <button
              onClick={handleRebuildBaselines}
              disabled={demoRunning}
              className="cyber-button text-xs font-mono"
            >
              <RotateCw className={`w-3.5 h-3.5 text-cyan-400 ${demoRunning ? 'animate-spin' : ''}`} />
              <span>Rebuild All User Baselines</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {profiles
              .filter((p) => p.entity_type === 'user')
              .map((prof) => (
                <div
                  key={prof.entity_id}
                  onClick={() => setSelectedProfileId(prof.entity_id)}
                  className="cyber-card p-5 space-y-4 hover:border-cyan-500/50 cursor-pointer transition"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center font-mono font-bold text-cyan-400">
                        {prof.entity_id.slice(0, 2).toUpperCase()}
                      </div>
                      <div>
                        <h4 className="text-sm font-bold text-white font-mono">@{prof.entity_id}</h4>
                        <span className="text-[11px] text-slate-400 font-mono block">
                          {prof.display_name || 'Standard User Profile'}
                        </span>
                      </div>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getRiskBadge(prof.risk_score, prof.risk_level)}`}>
                      {prof.risk_score}/100
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[11px] font-mono bg-slate-950/60 p-2.5 rounded border border-slate-850">
                    <div>
                      <span className="text-slate-500 block">Baseline Status</span>
                      <div className="mt-0.5">{getBaselineStatusBadge(prof.baseline_status)}</div>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Anomalies Detected</span>
                      <span className={`font-bold mt-0.5 block ${prof.anomalies_count > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                        {prof.anomalies_count} Event(s)
                      </span>
                    </div>
                  </div>

                  <div className="text-[11px] font-mono text-slate-400 space-y-1">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Department:</span>
                      <span className="text-slate-300">{prof.metadata_info?.department || 'Operations'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Baseline Version:</span>
                      <span className="text-cyan-400 font-bold">v{prof.baseline_version}</span>
                    </div>
                  </div>

                  <button className="w-full py-1.5 rounded bg-slate-900 border border-slate-700 hover:border-cyan-400 text-cyan-400 text-xs font-mono flex items-center justify-center gap-1 transition">
                    <Eye className="w-3.5 h-3.5" />
                    <span>Inspect User Baseline</span>
                  </button>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* TAB 3: HOST & ENTITY PROFILES */}
      {activeTab === 'entities' && (
        <div className="space-y-4">
          <div className="cyber-card p-4 flex items-center justify-between text-xs font-mono">
            <span className="text-slate-300">
              Monitored Endpoints, Servers & Service Accounts ({profiles.filter(p => p.entity_type !== 'user').length})
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {profiles
              .filter((p) => p.entity_type !== 'user')
              .map((prof) => (
                <div
                  key={prof.entity_id}
                  onClick={() => setSelectedProfileId(prof.entity_id)}
                  className="cyber-card p-5 space-y-4 hover:border-cyan-500/50 cursor-pointer transition"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-slate-900 border border-slate-700 flex items-center justify-center font-mono font-bold text-purple-400">
                        {prof.entity_type === 'server' ? (
                          <Server className="w-5 h-5" />
                        ) : prof.entity_type === 'service_account' ? (
                          <Bot className="w-5 h-5" />
                        ) : (
                          <Cpu className="w-5 h-5" />
                        )}
                      </div>
                      <div>
                        <h4 className="text-sm font-bold text-white font-mono">{prof.entity_id}</h4>
                        <span className="text-[10px] text-purple-400 font-mono uppercase block">
                          {prof.entity_type}
                        </span>
                      </div>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getRiskBadge(prof.risk_score, prof.risk_level)}`}>
                      {prof.risk_score}/100
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[11px] font-mono bg-slate-950/60 p-2.5 rounded border border-slate-850">
                    <div>
                      <span className="text-slate-500 block">Baseline Status</span>
                      <div className="mt-0.5">{getBaselineStatusBadge(prof.baseline_status)}</div>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Anomalies</span>
                      <span className={`font-bold mt-0.5 block ${prof.anomalies_count > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                        {prof.anomalies_count} Event(s)
                      </span>
                    </div>
                  </div>

                  <button className="w-full py-1.5 rounded bg-slate-900 border border-slate-700 hover:border-cyan-400 text-cyan-400 text-xs font-mono flex items-center justify-center gap-1 transition">
                    <Eye className="w-3.5 h-3.5" />
                    <span>Inspect Entity Baseline</span>
                  </button>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* TAB 4: UEBA FINDINGS (ALERTS) */}
      {activeTab === 'findings' && (
        <div className="cyber-card p-6 space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <h3 className="text-sm font-bold uppercase text-white font-mono flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                UEBA Anomaly Findings Triage
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Investigate, acknowledge, and resolve behavioral deviations detected across entities
              </p>
            </div>

            {/* Filter Bar */}
            <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  placeholder="Search finding, user, type..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded pl-8 pr-2.5 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="All">Severity: All</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>

              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="All">Status: All</option>
                <option value="New">New</option>
                <option value="Investigating">Investigating</option>
                <option value="Escalated">Escalated</option>
                <option value="Resolved">Resolved</option>
                <option value="False Positive">False Positive</option>
              </select>
            </div>
          </div>

          {/* Findings Table */}
          <div className="overflow-x-auto rounded border border-slate-800">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 text-[11px] uppercase">
                <tr>
                  <th className="py-2.5 px-3">Finding ID</th>
                  <th className="py-2.5 px-3">Entity</th>
                  <th className="py-2.5 px-3">Anomaly Category</th>
                  <th className="py-2.5 px-3">Detection Method</th>
                  <th className="py-2.5 px-3">Risk Score</th>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850 bg-slate-950/40">
                {filteredFindings.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-slate-500">
                      No UEBA anomaly findings matching current filters.
                    </td>
                  </tr>
                ) : (
                  filteredFindings.map((f) => (
                    <tr
                      key={f.finding_id}
                      onClick={() => setSelectedFindingId(f.finding_id)}
                      className="hover:bg-slate-900 cursor-pointer transition"
                    >
                      <td className="py-2.5 px-3 text-cyan-400 font-bold">{f.finding_id}</td>
                      <td className="py-2.5 px-3 text-slate-200">@{f.entity_id}</td>
                      <td className="py-2.5 px-3 font-semibold text-white">{f.anomaly_type}</td>
                      <td className="py-2.5 px-3 text-slate-400">{f.detection_method}</td>
                      <td className="py-2.5 px-3">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${getRiskBadge(f.risk_score, f.severity)}`}>
                          {f.risk_score}/100
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">
                        {new Date(f.created_at).toLocaleTimeString()}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-slate-900 border border-slate-700 text-slate-300">
                          {f.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button className="px-2 py-1 rounded bg-slate-900 border border-slate-700 hover:border-cyan-400 text-cyan-400 text-[11px]">
                          Triage
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

      {/* TAB 5: DEMO SIMULATION LAB */}
      {activeTab === 'demo' && (
        <div className="cyber-card p-6 space-y-6">
          <div className="border-b border-slate-800 pb-4">
            <h3 className="text-base font-bold uppercase text-white font-mono flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-cyan-400" />
              UEBA Synthetic Demonstration Lab
            </h3>
            <p className="text-xs text-slate-400 font-mono mt-1">
              Safely inject realistic behavioral anomalies to observe baseline deviation, Z-score calculations, risk scoring, and AI analyst explanations.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 font-mono text-xs">
            {/* Scenario 1 */}
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                  SCENARIO 1
                </span>
                <span className="text-amber-400 font-bold">Medium / High</span>
              </div>
              <h4 className="text-sm font-bold text-white">Unusual Login Time</h4>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                User @jsmith (Finance Lead, typical hours 09:00-17:00 UTC) logs in at 03:15 AM off-hours.
              </p>
              <button
                onClick={() => handleTriggerScenario('unusual_login_time')}
                disabled={demoRunning}
                className="w-full py-2 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 hover:bg-cyan-500/25 transition font-bold"
              >
                {demoRunning ? 'Injecting...' : 'Simulate Off-Hours Login'}
              </button>
            </div>

            {/* Scenario 2 */}
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40">
                  SCENARIO 2
                </span>
                <span className="text-rose-400 font-bold">High Severity</span>
              </div>
              <h4 className="text-sm font-bold text-white">Dormant Account Reactivation</h4>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Account @sarah_hr becomes active and authenticates after 94 days of dormancy.
              </p>
              <button
                onClick={() => handleTriggerScenario('dormant_account')}
                disabled={demoRunning}
                className="w-full py-2 rounded bg-purple-500/15 text-purple-300 border border-purple-500/40 hover:bg-purple-500/25 transition font-bold"
              >
                {demoRunning ? 'Injecting...' : 'Simulate Dormant Reactivation'}
              </button>
            </div>

            {/* Scenario 3 */}
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                  SCENARIO 3
                </span>
                <span className="text-amber-400 font-bold">High Severity</span>
              </div>
              <h4 className="text-sm font-bold text-white">Mass Resource Access</h4>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                User accesses 45 distinct confidential enterprise file shares within 3 minutes (Baseline: 3 shares).
              </p>
              <button
                onClick={() => handleTriggerScenario('mass_resource_access')}
                disabled={demoRunning}
                className="w-full py-2 rounded bg-amber-500/15 text-amber-300 border border-amber-500/40 hover:bg-amber-500/25 transition font-bold"
              >
                {demoRunning ? 'Injecting...' : 'Simulate Mass File Harvesting'}
              </button>
            </div>

            {/* Scenario 4 */}
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                  SCENARIO 4
                </span>
                <span className="text-rose-400 font-bold">High Severity</span>
              </div>
              <h4 className="text-sm font-bold text-white">Authentication Velocity Spike</h4>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Account targeted by 18 rapid failed logins from an uncatalogued international hosting IP.
              </p>
              <button
                onClick={() => handleTriggerScenario('auth_velocity')}
                disabled={demoRunning}
                className="w-full py-2 rounded bg-rose-500/15 text-rose-300 border border-rose-500/40 hover:bg-rose-500/25 transition font-bold"
              >
                {demoRunning ? 'Injecting...' : 'Simulate Auth Velocity Spike'}
              </button>
            </div>

            {/* Scenario 5 */}
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                  SCENARIO 5
                </span>
                <span className="text-rose-400 font-bold">Critical Severity</span>
              </div>
              <h4 className="text-sm font-bold text-white">Massive Data Exfiltration</h4>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Outbound network transfer of 8.45 GB triggers statistical Z-score violation (Z &gt; 6.0).
              </p>
              <button
                onClick={() => handleTriggerScenario('bulk_data_exfiltration')}
                disabled={demoRunning}
                className="w-full py-2 rounded bg-rose-500/15 text-rose-300 border border-rose-500/40 hover:bg-rose-500/25 transition font-bold"
              >
                {demoRunning ? 'Injecting...' : 'Simulate Volumetric Exfiltration'}
              </button>
            </div>

            {/* Run All */}
            <div className="p-4 rounded-lg bg-gradient-to-br from-cyan-950/40 to-slate-900 border border-cyan-500/40 space-y-3 flex flex-col justify-between">
              <div>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                  FULL BATCH
                </span>
                <h4 className="text-sm font-bold text-white mt-2">Execute All 5 Scenarios</h4>
                <p className="text-slate-400 text-[11px] leading-relaxed mt-1">
                  Runs the complete suite of UEBA behavioral anomaly tests simultaneously.
                </p>
              </div>
              <button
                onClick={() => handleTriggerScenario('all')}
                disabled={demoRunning}
                className="w-full py-2.5 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold transition flex items-center justify-center gap-1.5"
              >
                <Sparkles className="w-4 h-4 fill-current" />
                <span>{demoRunning ? 'Simulating Batch...' : 'Simulate All 5 Scenarios'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 5. SLIDE-OVER INVESTIGATION DRAWER (FINDING DETAIL) */}
      {selectedFindingId && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm transition-opacity">
          <div className="w-full max-w-2xl bg-[#090d1a] border-l border-slate-800 h-full overflow-y-auto p-6 space-y-6 flex flex-col shadow-2xl font-mono">
            {/* Header */}
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                    UEBA ANOMALY INVESTIGATOR
                  </span>
                  {findingDetail?.is_demo && (
                    <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-purple-500/20 text-purple-300 border border-purple-500/40">
                      SYNTHETIC DEMO
                    </span>
                  )}
                </div>
                <h3 className="text-lg font-bold text-white mt-1">
                  {findingDetail?.title || selectedFindingId}
                </h3>
                <p className="text-xs text-slate-400">{selectedFindingId}</p>
              </div>
              <button
                onClick={() => setSelectedFindingId(null)}
                className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Body */}
            {detailLoading ? (
              <div className="flex-1 flex items-center justify-center text-slate-500 text-xs">
                <RotateCw className="w-5 h-5 animate-spin text-cyan-400 mr-2" />
                Loading anomaly evidence...
              </div>
            ) : findingDetail ? (
              <div className="space-y-5 text-xs">
                {/* Metric Summary */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Severity</span>
                    <span className={`inline-block mt-1 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border ${getRiskBadge(findingDetail.risk_score, findingDetail.severity)}`}>
                      {findingDetail.severity}
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Risk Score</span>
                    <span className="font-extrabold text-sm text-cyan-400 mt-0.5 block">
                      {findingDetail.risk_score}/100
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Detection Method</span>
                    <span className="font-semibold text-slate-200 mt-1 block truncate">
                      {findingDetail.detection_method}
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Status</span>
                    <span className="font-semibold text-white mt-1 block">{findingDetail.status}</span>
                  </div>
                </div>

                {/* Description */}
                <div className="p-3.5 rounded bg-slate-900/80 border border-slate-800 space-y-1">
                  <span className="text-[10px] text-cyan-400 uppercase font-bold block">
                    Anomaly Description & Context
                  </span>
                  <p className="text-slate-300 leading-relaxed">{findingDetail.description}</p>
                </div>

                {/* Contributing Risk Factors Breakdown */}
                {findingDetail.evidence?.risk_factors && (
                  <div className="p-3.5 rounded bg-slate-900/60 border border-slate-800 space-y-2">
                    <span className="text-[10px] text-slate-400 uppercase font-bold block">
                      Explainable Risk Attribution Factors
                    </span>
                    <div className="space-y-1.5">
                      {findingDetail.evidence.risk_factors.map((rf: any, idx: number) => (
                        <div key={idx} className="flex justify-between items-center text-[11px] p-1.5 rounded bg-slate-950/60 border border-slate-850">
                          <div>
                            <span className="text-white font-semibold">{rf.factor}</span>
                            <span className="text-slate-500 block text-[10px]">{rf.details}</span>
                          </div>
                          <span className="text-cyan-400 font-bold">+{rf.contribution} ({rf.weight})</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Raw Evidence Payload */}
                <div className="space-y-1">
                  <span className="text-[10px] text-slate-400 uppercase font-bold block">
                    Behavioral Deviation Evidence
                  </span>
                  <pre className="p-3 rounded bg-black/80 border border-slate-800 text-[11px] text-cyan-300 overflow-x-auto max-h-44">
                    {JSON.stringify(findingDetail.evidence || {}, null, 2)}
                  </pre>
                </div>

                {/* AI Analyst Copilot */}
                <div className="p-4 rounded-lg bg-gradient-to-br from-cyan-950/30 to-purple-950/20 border border-cyan-500/40 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Bot className="w-4 h-4 text-cyan-400" />
                      <span className="text-xs font-bold text-white">AI Analyst Copilot Investigation</span>
                    </div>
                    <button
                      onClick={() => handleRunAiAnalysis(findingDetail.finding_id)}
                      disabled={aiLoading}
                      className="px-2.5 py-1 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 hover:bg-cyan-500/30 text-[11px] font-bold transition flex items-center gap-1"
                    >
                      <Sparkles className={`w-3 h-3 ${aiLoading ? 'animate-spin' : ''}`} />
                      <span>{aiLoading ? 'Analyzing...' : 'Generate AI Report'}</span>
                    </button>
                  </div>

                  {aiAnalysis ? (
                    <div className="p-3 rounded bg-slate-950/80 border border-slate-800 text-[11px] text-slate-200 whitespace-pre-line leading-relaxed max-h-60 overflow-y-auto">
                      {aiAnalysis.ai_explanation}
                    </div>
                  ) : (
                    <p className="text-[11px] text-slate-400">
                      Click 'Generate AI Report' to produce an evidence-grounded threat explanation comparing this deviation against historical baselines.
                    </p>
                  )}
                </div>

                {/* Recommended Investigation Steps */}
                {findingDetail.recommended_steps && (
                  <div className="p-3.5 rounded bg-slate-900 border border-slate-800 space-y-2">
                    <span className="text-[10px] text-amber-400 uppercase font-bold block">
                      Recommended Next Actions
                    </span>
                    <ul className="space-y-1 text-[11px] text-slate-300">
                      {findingDetail.recommended_steps.map((st: string, idx: number) => (
                        <li key={idx} className="flex items-start gap-1.5">
                          <ChevronRight className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                          <span>{st}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Analyst Triage Actions */}
                <div className="pt-2 border-t border-slate-800 space-y-2">
                  <span className="text-[10px] text-slate-400 uppercase font-bold block">
                    Update Investigation Status
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {['Investigating', 'Escalated', 'Resolved'].map((st) => (
                      <button
                        key={st}
                        onClick={() => handleUpdateStatus(findingDetail.finding_id, st)}
                        className={`px-3 py-1.5 rounded text-xs font-bold transition border ${
                          findingDetail.status === st
                            ? 'bg-cyan-500 text-slate-950 border-cyan-400'
                            : 'bg-slate-900 text-slate-300 border-slate-700 hover:border-slate-500'
                        }`}
                      >
                        Mark {st}
                      </button>
                    ))}
                    <button
                      onClick={() => handleSubmitFeedback(findingDetail.finding_id, 'False Positive')}
                      className="px-3 py-1.5 rounded text-xs font-bold bg-slate-900 text-rose-400 border border-rose-900/60 hover:bg-rose-950/40 transition"
                    >
                      Flag False Positive
                    </button>
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}

      {/* 6. USER/ENTITY PROFILE MODAL */}
      {selectedProfileId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 font-mono">
          <div className="w-full max-w-2xl bg-[#090d1a] border border-slate-800 rounded-xl p-6 space-y-5 max-h-[90vh] overflow-y-auto shadow-2xl">
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                  ENTITY BEHAVIOURAL BASELINE
                </span>
                <h3 className="text-lg font-bold text-white mt-1">
                  @{profileDetail?.entity_id || selectedProfileId}
                </h3>
                <p className="text-xs text-slate-400">{profileDetail?.display_name}</p>
              </div>
              <button
                onClick={() => setSelectedProfileId(null)}
                className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {profileLoading ? (
              <div className="py-12 text-center text-slate-500 text-xs">
                <RotateCw className="w-5 h-5 animate-spin text-cyan-400 mx-auto mb-2" />
                Loading baseline profile metrics...
              </div>
            ) : profileDetail ? (
              <div className="space-y-4 text-xs">
                <div className="grid grid-cols-3 gap-2">
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Risk Score</span>
                    <span className="font-extrabold text-sm text-cyan-400 mt-0.5 block">
                      {profileDetail.risk_score}/100 ({profileDetail.risk_level})
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Learning Status</span>
                    <div className="mt-1">{getBaselineStatusBadge(profileDetail.baseline_status)}</div>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Baseline Version</span>
                    <span className="font-bold text-white mt-1 block">v{profileDetail.baseline_version}</span>
                  </div>
                </div>

                {/* Baselines breakdown */}
                <div className="space-y-2">
                  <h4 className="text-xs uppercase text-slate-400 font-bold">Learned Category Baselines</h4>
                  <div className="space-y-2">
                    {profileDetail.baselines?.map((b: any) => (
                      <div key={b.id} className="p-3 rounded bg-slate-900/60 border border-slate-800 space-y-1.5">
                        <div className="flex justify-between items-center">
                          <span className="text-white font-semibold uppercase text-[11px]">
                            {b.behaviour_category.replace('_', ' ')}
                          </span>
                          <span className="text-[10px] text-cyan-400">
                            Confidence: {Math.round(b.confidence * 100)}% ({b.sample_count} samples)
                          </span>
                        </div>
                        <pre className="p-2 rounded bg-black/60 text-[10px] text-slate-300 overflow-x-auto max-h-28">
                          {JSON.stringify(b.baseline_data, null, 2)}
                        </pre>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
