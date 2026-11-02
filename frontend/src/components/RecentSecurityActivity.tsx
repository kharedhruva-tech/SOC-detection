'use client';

import React, { useState, useEffect, useRef, useMemo } from 'react';
import Link from 'next/link';
import {
  Radio,
  Pause,
  Play,
  RotateCw,
  Search,
  Filter,
  X,
  ChevronRight,
  Copy,
  Check,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Network,
  Cpu,
  FileCode,
  Users,
  Globe,
  Bug,
  Sparkles,
  Layers,
  ArrowUpRight,
  Eye,
  Activity
} from 'lucide-react';
import { api, WS_BASE_URL } from '@/utils/api';

export interface SecurityEventItem {
  id: number;
  event_id: string;
  event_type: string;
  category: string;
  severity: string;
  detection_status: string;
  matched_rule_id?: string | null;
  risk_score?: number;
  source_ip?: string | null;
  username?: string | null;
  dest_ip?: string | null;
  source?: string | null;
  details?: Record<string, any>;
  timestamp: string;
  is_demo?: boolean;
}

export interface SecurityEventDetail extends SecurityEventItem {
  raw_event?: string;
  detection_explanation?: string;
  matched_rule?: {
    rule_id: string;
    name: string;
    description: string;
    severity: string;
    category: string;
    mitre_tactics: string[];
    mitre_techniques: string[];
  } | null;
  related_events?: Array<{
    id: number;
    event_id: string;
    event_type: string;
    category: string;
    severity: string;
    source_ip?: string;
    username?: string;
    timestamp: string;
  }>;
}

const CATEGORIES = [
  'All',
  'Authentication',
  'Network Security',
  'Endpoint Security',
  'File Activity',
  'Account Management',
  'Web Application Security',
  'Malware Indicators'
];

const SEVERITIES = ['All', 'Critical', 'High', 'Medium', 'Low'];
const DETECTION_STATUSES = ['All', 'Alert Triggered', 'Normal', 'Under Triage'];
const TIME_RANGES = [
  { label: 'All Time', value: 'all' },
  { label: 'Last 15m', value: '15m' },
  { label: 'Last 1h', value: '1h' },
  { label: 'Last 24h', value: '24h' }
];

export default function RecentSecurityActivity() {
  const [events, setEvents] = useState<SecurityEventItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [bufferedEvents, setBufferedEvents] = useState<SecurityEventItem[]>([]);
  const [isGeneratingDemo, setIsGeneratingDemo] = useState<boolean>(false);
  const [demoNotice, setDemoNotice] = useState<string | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);

  // Filters
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('All');
  const [selectedStatus, setSelectedStatus] = useState<string>('All');
  const [selectedTimeRange, setSelectedTimeRange] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Selected event for detail drawer
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [eventDetail, setEventDetail] = useState<SecurityEventDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState<boolean>(false);
  const [copiedRaw, setCopiedRaw] = useState<boolean>(false);

  // Pagination
  const [totalCount, setTotalCount] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const pageSize = 15;

  // Ref to hold paused state inside WS listener
  const isPausedRef = useRef(isPaused);
  useEffect(() => {
    isPausedRef.current = isPaused;
  }, [isPaused]);

  // Initial load
  useEffect(() => {
    fetchEvents();
  }, [selectedCategory, selectedSeverity, selectedStatus, selectedTimeRange, page]);

  // Fetch events from API
  const fetchEvents = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (selectedCategory !== 'All') params.append('category', selectedCategory);
      if (selectedSeverity !== 'All') params.append('severity', selectedSeverity.toLowerCase());
      if (selectedStatus !== 'All') params.append('detection_status', selectedStatus);
      if (selectedTimeRange !== 'all') params.append('time_range', selectedTimeRange);
      if (searchQuery.trim()) params.append('search', searchQuery.trim());
      params.append('skip', ((page - 1) * pageSize).toString());
      params.append('limit', pageSize.toString());

      const data = await api.get(`/events?${params.toString()}`);
      if (data && Array.isArray(data.items)) {
        setEvents(data.items);
        setTotalCount(data.total || data.items.length);
        setApiError(null);
      }
    } catch (err: any) {
      console.error('Failed to fetch security events:', err);
      setApiError(err.message || 'Unable to connect to backend server on port 8000.');
    } finally {
      setLoading(false);
    }
  };

  // WebSocket Listener
  useEffect(() => {
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
            if (data.type === 'NEW_EVENT' && data.event_id) {
              const newEvt: SecurityEventItem = {
                id: data.id || Math.floor(Math.random() * 100000),
                event_id: data.event_id,
                event_type: data.event_type || 'system_event',
                category: data.category || 'Authentication',
                severity: data.severity || 'low',
                detection_status: data.detection_status || 'Normal',
                matched_rule_id: data.matched_rule_id,
                risk_score: data.risk_score || 0,
                source_ip: data.source_ip,
                username: data.username,
                dest_ip: data.dest_ip,
                source: data.source || 'Sysmon',
                details: data.details || {},
                timestamp: data.timestamp || new Date().toISOString(),
                is_demo: Boolean(data.is_demo)
              };

              if (isPausedRef.current) {
                // Buffer the event while UI is paused
                setBufferedEvents((prev) => [newEvt, ...prev.slice(0, 99)]);
              } else {
                // Prepend to visible feed, bounded to 100 items to avoid excessive browser memory
                setEvents((prev) => {
                  if (prev.some((e) => e.event_id === newEvt.event_id)) return prev;
                  return [newEvt, ...prev.slice(0, 99)];
                });
                setTotalCount((c) => c + 1);
              }
            }
          } catch (e) {
            // Ignore parse errors or ping responses
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

  // Fetch Event Detail when drawer opens
  useEffect(() => {
    if (!selectedEventId) {
      setEventDetail(null);
      return;
    }

    const fetchDetail = async () => {
      setDetailLoading(true);
      try {
        const detail = await api.get(`/events/${selectedEventId}`);
        setEventDetail(detail);
      } catch (err) {
        console.error('Failed to fetch event detail:', err);
      } finally {
        setDetailLoading(false);
      }
    };

    fetchDetail();
  }, [selectedEventId]);

  // Handle Resume / Flush buffer
  const handleResumeFeed = () => {
    setIsPaused(false);
    if (bufferedEvents.length > 0) {
      setEvents((prev) => {
        const existingIds = new Set(prev.map((e) => e.event_id));
        const filteredNew = bufferedEvents.filter((e) => !existingIds.has(e.event_id));
        return [...filteredNew, ...prev].slice(0, 100);
      });
      setTotalCount((c) => c + bufferedEvents.length);
      setBufferedEvents([]);
    }
  };

  // Generate synthetic demo activity across 7 categories
  const handleGenerateDemo = async () => {
    try {
      setIsGeneratingDemo(true);
      setDemoNotice(null);
      const res = await api.post('/demo/generate-activity');
      setDemoNotice(`Successfully generated ${res.events_count || 10} synthetic security events across all 7 categories.`);
      setTimeout(() => setDemoNotice(null), 5000);
      // Refresh current view
      fetchEvents();
    } catch (err: any) {
      console.error('Demo activity generation failed:', err);
      setDemoNotice('Failed to generate synthetic telemetry: ' + (err.message || 'Server error'));
      setTimeout(() => setDemoNotice(null), 4000);
    } finally {
      setIsGeneratingDemo(false);
    }
  };

  // Clear all filters
  const handleClearFilters = () => {
    setSelectedCategory('All');
    setSelectedSeverity('All');
    setSelectedStatus('All');
    setSelectedTimeRange('all');
    setSearchQuery('');
    setPage(1);
  };

  const hasActiveFilters =
    selectedCategory !== 'All' ||
    selectedSeverity !== 'All' ||
    selectedStatus !== 'All' ||
    selectedTimeRange !== 'all' ||
    searchQuery.trim() !== '';

  // Filter in-memory for instant search if not querying backend
  const filteredEvents = useMemo(() => {
    return events.filter((evt) => {
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matches =
          evt.event_id.toLowerCase().includes(q) ||
          evt.event_type.toLowerCase().includes(q) ||
          (evt.source_ip && evt.source_ip.toLowerCase().includes(q)) ||
          (evt.username && evt.username.toLowerCase().includes(q)) ||
          (evt.source && evt.source.toLowerCase().includes(q));
        if (!matches) return false;
      }
      return true;
    });
  }, [events, searchQuery]);

  // Helper: Category Icon & Style
  const getCategoryBadge = (category: string) => {
    switch (category) {
      case 'Authentication':
        return {
          icon: <Lock className="w-3 h-3 text-blue-400" />,
          cls: 'bg-blue-500/10 text-blue-400 border-blue-500/30'
        };
      case 'Network Security':
        return {
          icon: <Network className="w-3 h-3 text-emerald-400" />,
          cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
        };
      case 'Endpoint Security':
        return {
          icon: <Cpu className="w-3 h-3 text-indigo-400" />,
          cls: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30'
        };
      case 'File Activity':
        return {
          icon: <FileCode className="w-3 h-3 text-teal-400" />,
          cls: 'bg-teal-500/10 text-teal-400 border-teal-500/30'
        };
      case 'Account Management':
        return {
          icon: <Users className="w-3 h-3 text-amber-400" />,
          cls: 'bg-amber-500/10 text-amber-400 border-amber-500/30'
        };
      case 'Web Application Security':
        return {
          icon: <Globe className="w-3 h-3 text-pink-400" />,
          cls: 'bg-pink-500/10 text-pink-400 border-pink-500/30'
        };
      case 'Malware Indicators':
        return {
          icon: <Bug className="w-3 h-3 text-rose-400" />,
          cls: 'bg-rose-500/10 text-rose-400 border-rose-500/30'
        };
      default:
        return {
          icon: <Layers className="w-3 h-3 text-cyan-400" />,
          cls: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
        };
    }
  };

  // Helper: Severity Badge
  const getSeverityBadge = (sev: string) => {
    const s = sev?.toLowerCase() || 'low';
    switch (s) {
      case 'critical':
        return 'bg-rose-950/60 text-rose-400 border-rose-500/50';
      case 'high':
        return 'bg-amber-950/60 text-amber-400 border-amber-500/50';
      case 'medium':
        return 'bg-yellow-950/60 text-yellow-300 border-yellow-500/50';
      default:
        return 'bg-sky-950/60 text-sky-300 border-sky-500/50';
    }
  };

  // Helper: Detection Status Badge
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'Alert Triggered':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-pulse" />
            Alert Triggered
          </span>
        );
      case 'Under Triage':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            Under Triage
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono text-emerald-300 bg-emerald-500/15 border border-emerald-500/30">
            <Check className="w-3 h-3 text-emerald-400" />
            Normal
          </span>
        );
    }
  };

  return (
    <div className="cyber-card p-6 space-y-5">
      {/* 1. Header & Live Feed Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Activity className="w-5 h-5 text-cyan-400" />
              Recent Security Activity
            </h2>
            <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
              SIEM TELEMETRY STREAM
            </span>
            {/* Live WebSocket Status Pill */}
            <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono border bg-slate-900">
              {wsConnected ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-emerald-400 font-semibold">LIVE STREAM ACTIVE</span>
                </>
              ) : (
                <>
                  <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
                  <span className="text-amber-400 font-semibold">RECONNECTING...</span>
                </>
              )}
            </div>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Real-time multi-source security event ingestion, threat rule correlation, and MITRE categorization
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Pause / Resume Button with Buffer Count Badge */}
          {isPaused ? (
            <button
              onClick={handleResumeFeed}
              className="px-3 py-1.5 rounded-md text-xs font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/50 hover:bg-amber-500/30 flex items-center gap-2 transition"
              title="Resume live ingestion"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Resume Stream</span>
              {bufferedEvents.length > 0 && (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-amber-500 text-slate-950 font-extrabold animate-bounce">
                  +{bufferedEvents.length}
                </span>
              )}
            </button>
          ) : (
            <button
              onClick={() => setIsPaused(true)}
              className="px-3 py-1.5 rounded-md text-xs font-mono text-slate-300 bg-slate-900 border border-slate-700 hover:border-slate-500 flex items-center gap-1.5 transition"
              title="Pause visible feed (ingestion continues in background)"
            >
              <Pause className="w-3.5 h-3.5 text-slate-400" />
              <span>Pause Feed</span>
            </button>
          )}

          {/* Refresh History */}
          <button
            onClick={fetchEvents}
            disabled={loading}
            className="px-3 py-1.5 rounded-md text-xs font-mono text-slate-300 bg-slate-900 border border-slate-700 hover:border-cyan-500/50 flex items-center gap-1.5 transition"
            title="Refresh event history from database"
          >
            <RotateCw className={`w-3.5 h-3.5 text-cyan-400 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          {/* Generate Synthetic Demo Telemetry */}
          <button
            onClick={handleGenerateDemo}
            disabled={isGeneratingDemo}
            className="px-3 py-1.5 rounded-md text-xs font-mono font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 hover:bg-cyan-500/25 flex items-center gap-1.5 transition"
            title="Inject 10 safe synthetic security events across all 7 categories"
          >
            <Sparkles className={`w-3.5 h-3.5 text-cyan-400 ${isGeneratingDemo ? 'animate-spin' : ''}`} />
            <span>{isGeneratingDemo ? 'Simulating...' : 'Simulate Telemetry'}</span>
          </button>
        </div>
      </div>

      {/* Demo Notification Toast */}
      {demoNotice && (
        <div className="p-2.5 rounded-md bg-cyan-950/60 border border-cyan-500/40 text-cyan-300 text-xs font-mono flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>{demoNotice}</span>
          </div>
          <button onClick={() => setDemoNotice(null)} className="text-cyan-400 hover:text-white">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Buffer Pause Alert Banner */}
      {isPaused && bufferedEvents.length > 0 && (
        <div className="p-2.5 rounded-md bg-amber-950/40 border border-amber-500/40 text-amber-300 text-xs font-mono flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Pause className="w-4 h-4 text-amber-400 shrink-0" />
            <span>
              UI stream paused. <strong>{bufferedEvents.length}</strong> new incoming events held in buffer without freezing collection.
            </span>
          </div>
          <button
            onClick={handleResumeFeed}
            className="px-2 py-0.5 rounded bg-amber-500 text-slate-950 text-[11px] font-bold hover:bg-amber-400 transition"
          >
            Flush & Resume
          </button>
        </div>
      )}

      {/* Backend API Connection Error Banner */}
      {apiError && (
        <div className="p-3 rounded-md bg-rose-950/60 border border-rose-500/50 text-rose-300 text-xs font-mono flex items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{apiError}</span>
          </div>
          <button
            onClick={fetchEvents}
            className="px-2.5 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-[11px] font-bold text-white transition shrink-0"
          >
            Retry Connection
          </button>
        </div>
      )}

      {/* 2. Multi-Criteria Filters Bar */}
      <div className="bg-slate-900/60 border border-slate-800/90 rounded-lg p-3 space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2 text-xs font-mono">
          {/* Search Box */}
          <div className="lg:col-span-2 relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search IP, user, event ID, type..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-2.5 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-2 text-slate-400 hover:text-white"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Category Filter */}
          <div>
            <select
              value={selectedCategory}
              onChange={(e) => {
                setSelectedCategory(e.target.value);
                setPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 cursor-pointer"
            >
              {CATEGORIES.map((cat) => (
                <option key={cat} value={cat}>
                  Category: {cat}
                </option>
              ))}
            </select>
          </div>

          {/* Severity Filter */}
          <div>
            <select
              value={selectedSeverity}
              onChange={(e) => {
                setSelectedSeverity(e.target.value);
                setPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 cursor-pointer"
            >
              {SEVERITIES.map((sev) => (
                <option key={sev} value={sev}>
                  Severity: {sev}
                </option>
              ))}
            </select>
          </div>

          {/* Detection Status Filter */}
          <div>
            <select
              value={selectedStatus}
              onChange={(e) => {
                setSelectedStatus(e.target.value);
                setPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 cursor-pointer"
            >
              {DETECTION_STATUSES.map((st) => (
                <option key={st} value={st}>
                  Status: {st}
                </option>
              ))}
            </select>
          </div>

          {/* Time Range Filter */}
          <div>
            <select
              value={selectedTimeRange}
              onChange={(e) => {
                setSelectedTimeRange(e.target.value);
                setPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 cursor-pointer"
            >
              {TIME_RANGES.map((tr) => (
                <option key={tr.value} value={tr.value}>
                  Time: {tr.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Filter Summary & Clear */}
        <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-1 border-t border-slate-800/50">
          <div>
            Showing <span className="text-cyan-400 font-bold">{filteredEvents.length}</span> events
            {totalCount > 0 && (
              <span>
                {' '}(Total in DB: <span className="text-white font-semibold">{totalCount}</span>)
              </span>
            )}
          </div>
          {hasActiveFilters && (
            <button
              onClick={handleClearFilters}
              className="text-rose-400 hover:text-rose-300 flex items-center gap-1 transition"
            >
              <X className="w-3 h-3" />
              <span>Clear Visible Filters</span>
            </button>
          )}
        </div>
      </div>

      {/* 3. Live Security Activity Event Table */}
      <div className="overflow-x-auto rounded-lg border border-slate-800/90">
        <table className="w-full text-left font-mono text-xs">
          <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 text-[11px] uppercase tracking-wider">
            <tr>
              <th className="py-2.5 px-3">Timestamp</th>
              <th className="py-2.5 px-3">Event Type</th>
              <th className="py-2.5 px-3">Category</th>
              <th className="py-2.5 px-3">Source IP / Host</th>
              <th className="py-2.5 px-3">Username</th>
              <th className="py-2.5 px-3">Severity</th>
              <th className="py-2.5 px-3">Detection Status</th>
              <th className="py-2.5 px-3">Source</th>
              <th className="py-2.5 px-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-850 bg-slate-950/30">
            {loading && events.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-8 text-center text-slate-500 font-mono">
                  <div className="flex items-center justify-center gap-2">
                    <RotateCw className="w-4 h-4 animate-spin text-cyan-400" />
                    <span>Loading security events telemetry...</span>
                  </div>
                </td>
              </tr>
            ) : filteredEvents.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-10 text-center text-slate-500 font-mono">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <ShieldCheck className="w-8 h-8 text-slate-600" />
                    <span>No security events match the current filter criteria.</span>
                    {hasActiveFilters && (
                      <button
                        onClick={handleClearFilters}
                        className="text-xs text-cyan-400 hover:underline mt-1"
                      >
                        Reset filters to view all incoming activity
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ) : (
              filteredEvents.map((evt) => {
                const catBadge = getCategoryBadge(evt.category);
                const isSelected = selectedEventId === evt.event_id;

                return (
                  <tr
                    key={evt.event_id || evt.id}
                    onClick={() => setSelectedEventId(evt.event_id)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-cyan-950/30 border-l-2 border-cyan-400'
                        : 'hover:bg-slate-900/80'
                    }`}
                  >
                    {/* Timestamp */}
                    <td className="py-2.5 px-3 whitespace-nowrap text-slate-300">
                      {evt.timestamp ? (
                        <div>
                          <span>{new Date(evt.timestamp).toLocaleTimeString()}</span>
                          <span className="text-[10px] text-slate-500 block">
                            {new Date(evt.timestamp).toISOString().split('T')[0]}
                          </span>
                        </div>
                      ) : (
                        'Just now'
                      )}
                    </td>

                    {/* Event Type */}
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className="font-semibold text-white">{evt.event_type}</span>
                        {evt.is_demo && (
                          <span className="text-[9px] font-bold px-1 rounded bg-slate-800 text-cyan-300 border border-cyan-500/30">
                            DEMO
                          </span>
                        )}
                      </div>
                      <span className="text-[10px] text-slate-500 block truncate max-w-[130px]">
                        {evt.event_id}
                      </span>
                    </td>

                    {/* Category */}
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium border ${catBadge.cls}`}
                      >
                        {catBadge.icon}
                        <span>{evt.category}</span>
                      </span>
                    </td>

                    {/* Source IP / Host */}
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className="text-cyan-400 font-mono">
                        {evt.source_ip || evt.dest_ip || 'Local'}
                      </span>
                    </td>

                    {/* Username */}
                    <td className="py-2.5 px-3 whitespace-nowrap text-slate-300">
                      {evt.username ? (
                        <span className="text-slate-200 font-medium">{evt.username}</span>
                      ) : (
                        <span className="text-slate-600">-</span>
                      )}
                    </td>

                    {/* Severity */}
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border ${getSeverityBadge(
                          evt.severity
                        )}`}
                      >
                        {evt.severity}
                      </span>
                    </td>

                    {/* Detection Status */}
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      {getStatusBadge(evt.detection_status)}
                    </td>

                    {/* Source */}
                    <td className="py-2.5 px-3 whitespace-nowrap text-slate-400 text-[11px]">
                      {evt.source || 'Sysmon'}
                    </td>

                    {/* Action */}
                    <td className="py-2.5 px-3 whitespace-nowrap text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEventId(evt.event_id);
                        }}
                        className="px-2 py-1 rounded bg-slate-900 border border-slate-700 hover:border-cyan-400 text-cyan-400 text-[11px] font-mono transition"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* 4. Event Detail Slide-over Drawer / Modal */}
      {selectedEventId && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm transition-opacity">
          <div className="w-full max-w-xl bg-[#090d1a] border-l border-slate-800 h-full overflow-y-auto p-6 space-y-6 flex flex-col shadow-2xl">
            {/* Drawer Header */}
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                    EVENT INSPECTOR
                  </span>
                  {eventDetail?.is_demo && (
                    <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-purple-500/20 text-purple-300 border border-purple-500/40">
                      SYNTHETIC DEMO
                    </span>
                  )}
                </div>
                <h3 className="text-lg font-bold text-white font-mono mt-1">
                  {eventDetail?.event_type || selectedEventId}
                </h3>
                <p className="text-xs text-slate-400 font-mono">{selectedEventId}</p>
              </div>
              <button
                onClick={() => setSelectedEventId(null)}
                className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Detail Body */}
            {detailLoading ? (
              <div className="flex-1 flex items-center justify-center text-slate-500 font-mono text-xs">
                <RotateCw className="w-5 h-5 animate-spin text-cyan-400 mr-2" />
                Retrieving full event evidence...
              </div>
            ) : eventDetail ? (
              <div className="space-y-5 flex-1">
                {/* Status & Risk Score Summary */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-xs">
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Severity</span>
                    <span
                      className={`inline-block mt-1 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border ${getSeverityBadge(
                        eventDetail.severity
                      )}`}
                    >
                      {eventDetail.severity}
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Category</span>
                    <span className="font-semibold text-slate-200 mt-1 block truncate">
                      {eventDetail.category}
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Risk Score</span>
                    <span
                      className={`font-extrabold text-sm mt-0.5 block ${
                        (eventDetail.risk_score || 0) >= 70
                          ? 'text-rose-400'
                          : (eventDetail.risk_score || 0) >= 40
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      {eventDetail.risk_score ? `${eventDetail.risk_score}/100` : '0/100'}
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Detection Status</span>
                    <div className="mt-1">{getStatusBadge(eventDetail.detection_status)}</div>
                  </div>
                </div>

                {/* Matched SIEM Detection Rule (if triggered) */}
                {eventDetail.matched_rule ? (
                  <div className="p-4 rounded-lg bg-rose-950/25 border border-rose-500/40 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4 text-rose-400" />
                        <span className="text-xs font-mono font-bold text-rose-300">
                          Matched Rule: {eventDetail.matched_rule.rule_id}
                        </span>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 border border-rose-500/50 text-rose-400 uppercase font-bold">
                        {eventDetail.matched_rule.severity}
                      </span>
                    </div>
                    <p className="text-xs font-semibold text-white font-mono">
                      {eventDetail.matched_rule.name}
                    </p>
                    <p className="text-xs text-slate-300 font-mono">
                      {eventDetail.matched_rule.description}
                    </p>

                    {/* MITRE ATT&CK Mapping */}
                    {eventDetail.matched_rule.mitre_tactics && eventDetail.matched_rule.mitre_tactics.length > 0 && (
                      <div className="pt-2 border-t border-rose-900/40 flex flex-wrap gap-1.5 text-[10px] font-mono">
                        <span className="text-slate-400">MITRE Tactics:</span>
                        {eventDetail.matched_rule.mitre_tactics.map((t) => (
                          <span
                            key={t}
                            className="px-1.5 py-0.2 rounded bg-slate-900 text-rose-300 border border-rose-500/30"
                          >
                            {t}
                          </span>
                        ))}
                        {eventDetail.matched_rule.mitre_techniques?.map((tech) => (
                          <span
                            key={tech}
                            className="px-1.5 py-0.2 rounded bg-slate-900 text-cyan-300 border border-cyan-500/30"
                          >
                            {tech}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/30 flex items-center gap-2 text-xs font-mono text-emerald-300">
                    <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>
                      Normal Event Baseline: This activity evaluated cleanly with no active SIEM threshold violations.
                    </span>
                  </div>
                )}

                {/* Analyst Detection Explanation */}
                {eventDetail.detection_explanation && (
                  <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1 font-mono text-xs">
                    <span className="text-[10px] text-cyan-400 uppercase tracking-wider block font-bold">
                      SIEM Detection Engine Analysis
                    </span>
                    <p className="text-slate-300 leading-relaxed">
                      {eventDetail.detection_explanation}
                    </p>
                  </div>
                )}

                {/* Identity & Telemetry Details */}
                <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2 font-mono text-xs">
                  <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-bold">
                    Entity & Host Indicators
                  </span>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
                    <div>
                      <span className="text-slate-500 text-[10px] block">Source IP</span>
                      <span className="text-cyan-400 font-bold">{eventDetail.source_ip || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px] block">Destination IP</span>
                      <span className="text-slate-300">{eventDetail.dest_ip || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px] block">Username / Account</span>
                      <span className="text-slate-200">{eventDetail.username || 'System / Anonymous'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px] block">Event Sensor Source</span>
                      <span className="text-slate-300">{eventDetail.source || 'Generic'}</span>
                    </div>
                  </div>
                </div>

                {/* Raw Log Evidence JSON */}
                <div className="space-y-1 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">
                      Original Normalized Log Payload
                    </span>
                    <button
                      onClick={() => {
                        const payload = eventDetail.raw_event || JSON.stringify(eventDetail.details, null, 2);
                        navigator.clipboard.writeText(payload);
                        setCopiedRaw(true);
                        setTimeout(() => setCopiedRaw(false), 2000);
                      }}
                      className="text-[10px] text-cyan-400 hover:text-white flex items-center gap-1 transition"
                    >
                      {copiedRaw ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span className="text-emerald-400">Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy Raw JSON</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-3 rounded-lg bg-black/80 border border-slate-800 text-[11px] text-cyan-300 overflow-x-auto max-h-56 leading-tight">
                    {eventDetail.raw_event
                      ? typeof eventDetail.raw_event === 'string'
                        ? (() => {
                            try {
                              return JSON.stringify(JSON.parse(eventDetail.raw_event), null, 2);
                            } catch {
                              return eventDetail.raw_event;
                            }
                          })()
                        : JSON.stringify(eventDetail.raw_event, null, 2)
                      : JSON.stringify(eventDetail.details || {}, null, 2)}
                  </pre>
                </div>

                {/* Related Events Timeline (±30 minutes) */}
                {eventDetail.related_events && eventDetail.related_events.length > 0 && (
                  <div className="space-y-2 font-mono text-xs">
                    <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-bold">
                      Correlated Events (Same IP / Identity ±30m)
                    </span>
                    <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                      {eventDetail.related_events.map((rel) => (
                        <div
                          key={rel.event_id}
                          onClick={() => setSelectedEventId(rel.event_id)}
                          className="p-2 rounded bg-slate-900 border border-slate-800 hover:border-cyan-500/40 cursor-pointer flex items-center justify-between transition text-[11px]"
                        >
                          <div>
                            <span className="text-white font-semibold">{rel.event_type}</span>
                            <span className="text-slate-500 block text-[10px]">{rel.event_id}</span>
                          </div>
                          <div className="text-right">
                            <span
                              className={`text-[9px] px-1 py-0.2 rounded border uppercase ${getSeverityBadge(
                                rel.severity
                              )}`}
                            >
                              {rel.severity}
                            </span>
                            <span className="text-[10px] text-slate-500 block">
                              {new Date(rel.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Bottom Action: Direct Triage in SOC Alerts */}
                {eventDetail.detection_status === 'Alert Triggered' && (
                  <div className="pt-2">
                    <Link
                      href="/alerts"
                      className="w-full py-2.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-mono font-bold text-xs flex items-center justify-center gap-2 transition"
                    >
                      <ShieldAlert className="w-4 h-4" />
                      <span>Investigate in SOC Alerts Workbench</span>
                      <ArrowUpRight className="w-4 h-4" />
                    </Link>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-12 text-slate-500 font-mono text-xs">
                Event detail not found.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

