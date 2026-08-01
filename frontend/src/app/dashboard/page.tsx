'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/navigation';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertOctagon, 
  Clock, 
  Zap, 
  Layers, 
  Activity,
  ArrowUpRight
} from 'lucide-react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell
} from 'recharts';
import WorldAttackMap from '@/components/WorldAttackMap';
import { api, WS_BASE_URL } from '@/utils/api';

interface AlertStream {
  id: number;
  title: string;
  category: string;
  severity: string;
  timestamp: string;
  status: string;
}

export default function SOCDashboard() {
  const [stats, setStats] = useState<any>(null);
  const [alerts, setAlerts] = useState<AlertStream[]>([]);
  const [liveFeed, setLiveFeed] = useState<AlertStream[]>([]);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    
    // Load historical summary reports
    const fetchStats = async () => {
      try {
        const data = await api.get('/reports/summary');
        setStats(data);
      } catch (err) {
        console.error("Failed fetching stats", err);
      }
    };
    fetchStats();

    // Load initial recent alerts
    const fetchAlerts = async () => {
      try {
        const data = await api.get('/alerts/?status=New');
        setAlerts(data.slice(0, 5));
      } catch (err) {
        console.error("Failed fetching alerts", err);
      }
    };
    fetchAlerts();

    // Socket listener for live alerts
    let ws: WebSocket;
    let reconnectTimeout: NodeJS.Timeout;
    let active = true;

    const connect = () => {
      if (!active) return;
      ws = new WebSocket(WS_BASE_URL);

      ws.onmessage = (event) => {
        try {
          const alert = JSON.parse(event.data);
          if (alert.id) {
            // Add to live stream lists
            setLiveFeed(prev => [alert, ...prev].slice(0, 6));
            // Increment counts in stats locally for snappy feedback
            setStats((prevStats: any) => {
              if (!prevStats) return null;
              return {
                ...prevStats,
                total_alerts: prevStats.total_alerts + 1,
                new_alerts: prevStats.new_alerts + 1,
              };
            });
          }
        } catch (e) {
          // Ping response or invalid JSON
        }
      };

      ws.onclose = () => {
        if (active) {
          reconnectTimeout = setTimeout(connect, 3000);
        }
      };
    };

    connect();

    return () => {
      active = false;
      if (ws) ws.close();
      clearTimeout(reconnectTimeout);
    };
  }, []);

  if (!mounted) return null;

  // Visual severity colors
  const severityColor = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical': return 'text-neon-red border-neon-red/30 bg-neon-red/5';
      case 'high': return 'text-orange-500 border-orange-500/30 bg-orange-500/5';
      case 'medium': return 'text-neon-yellow border-neon-yellow/30 bg-neon-yellow/5';
      default: return 'text-neon-cyan border-neon-cyan/30 bg-neon-cyan/5';
    }
  };

  // Recharts styling configs
  const chartData = stats?.threat_trends || [
    { month: 'Feb', incidents: 8 },
    { month: 'Mar', incidents: 12 },
    { month: 'Apr', incidents: 10 },
    { month: 'May', incidents: 17 },
    { month: 'Jun', incidents: 15 },
    { month: 'Jul', incidents: 20 }
  ];

  const barData = [
    { name: 'Ransomware', count: 4, color: '#ff0055' },
    { name: 'Cred Abuse', count: 8, color: '#ffcc00' },
    { name: 'Lateral Mvmt', count: 3, color: '#bd00ff' },
    { name: 'Exfil', count: 5, color: '#00f0ff' }
  ];

  return (
    <div className="space-y-6">
      
      {/* 1. Header Area */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold tracking-wide text-slate-100 uppercase">
            SOC Operations Control
          </h2>
          <p className="text-xs text-slate-500 font-mono mt-0.5">
            PLATFORM STAGE // REAL-TIME MONITORING AND DETECTION PIPELINES
          </p>
        </div>
        <div className="flex gap-2">
          <div className="flex items-center gap-1.5 bg-[#0a0c20] px-3.5 py-2 rounded-lg border border-slate-800 text-[11px] font-mono text-slate-400">
            <span className="w-1.5 h-1.5 rounded-full bg-neon-green animate-pulse" />
            AGENT DEPLOYMENTS: 125 ACTIVE
          </div>
        </div>
      </div>

      {/* 2. Stat Counts Widgets */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        
        {/* Active Incidents */}
        <div className="glass-panel p-5 rounded-xl border-slate-800 flex justify-between items-start">
          <div className="space-y-2">
            <span className="text-[10px] text-slate-500 font-mono uppercase tracking-widest font-bold">
              Active Incidents
            </span>
            <p className="text-3xl font-extrabold text-slate-100 font-mono">
              {stats?.open_incidents !== undefined ? stats.open_incidents : 3}
            </p>
            <span className="text-[10px] text-red-500 font-mono flex items-center gap-1">
              <span className="w-1 h-1 rounded-full bg-red-500 animate-ping" />
              SLA BREACH RISK
            </span>
          </div>
          <div className="p-3 bg-red-950/20 border border-red-900/40 rounded-lg text-red-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
        </div>

        {/* Real-time Alerts */}
        <div className="glass-panel p-5 rounded-xl border-slate-800 flex justify-between items-start">
          <div className="space-y-2">
            <span className="text-[10px] text-slate-500 font-mono uppercase tracking-widest font-bold">
              Raw Event Alerts
            </span>
            <p className="text-3xl font-extrabold text-slate-100 font-mono">
              {stats?.total_alerts !== undefined ? stats.total_alerts : 18}
            </p>
            <span className="text-[10px] text-neon-green font-mono">
              + {stats?.new_alerts || 0} NEW UNACKNOWLEDGED
            </span>
          </div>
          <div className="p-3 bg-neon-green/10 border border-neon-green/20 rounded-lg text-neon-green">
            <Activity className="w-6 h-6" />
          </div>
        </div>

        {/* SLA Compliance */}
        <div className="glass-panel p-5 rounded-xl border-slate-800 flex justify-between items-start">
          <div className="space-y-2">
            <span className="text-[10px] text-slate-500 font-mono uppercase tracking-widest font-bold">
              SLA Response
            </span>
            <p className="text-3xl font-extrabold text-slate-100 font-mono">
              {stats?.average_response_time || "12m"}
            </p>
            <span className="text-[10px] text-neon-cyan font-mono">
              98.2% SLA TARGET MET
            </span>
          </div>
          <div className="p-3 bg-neon-cyan/10 border border-neon-cyan/20 rounded-lg text-neon-cyan">
            <Clock className="w-6 h-6" />
          </div>
        </div>

        {/* Vulnerable Exposure */}
        <div className="glass-panel p-5 rounded-xl border-slate-800 flex justify-between items-start">
          <div className="space-y-2">
            <span className="text-[10px] text-slate-500 font-mono uppercase tracking-widest font-bold">
              Exposure Risk
            </span>
            <p className="text-3xl font-extrabold text-slate-100 font-mono">
              {stats?.unpatched_vulns !== undefined ? stats.unpatched_vulns : 2}
            </p>
            <span className="text-[10px] text-neon-yellow font-mono">
              {stats?.critical_vulns || 1} CRITICAL CVSS VULNS
            </span>
          </div>
          <div className="p-3 bg-neon-yellow/10 border border-neon-yellow/20 rounded-lg text-neon-yellow">
            <Layers className="w-6 h-6" />
          </div>
        </div>

      </div>

      {/* 3. Live Attack Map Row */}
      <WorldAttackMap />

      {/* 4. Charts & Live Alerts Feeds */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Side: Graphs */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Incident Area Chart */}
          <div className="glass-panel p-6 rounded-xl border-slate-800">
            <h3 className="text-sm font-bold tracking-wide uppercase text-slate-200 mb-4 font-mono">
              Incident Volumetric Trends
            </h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorIncidents" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.2}/>
                      <stop offset="95%" stopColor="#00f0ff" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="month" stroke="#475569" fontSize={11} className="font-mono" />
                  <YAxis stroke="#475569" fontSize={11} className="font-mono" />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#090b1c', border: '1px solid #1e293b', borderRadius: '8px' }}
                    labelStyle={{ color: '#94a3b8', fontFamily: 'monospace' }}
                  />
                  <Area type="monotone" dataKey="incidents" stroke="#00f0ff" strokeWidth={2} fillOpacity={1} fill="url(#colorIncidents)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Alert Categories Chart */}
          <div className="glass-panel p-6 rounded-xl border-slate-800">
            <h3 className="text-sm font-bold tracking-wide uppercase text-slate-200 mb-4 font-mono">
              Alert Categorical Distribution
            </h3>
            <div className="h-44">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData} layout="vertical" margin={{ top: 5, right: 10, left: 10, bottom: 5 }}>
                  <XAxis type="number" stroke="#475569" fontSize={10} hide />
                  <YAxis dataKey="name" type="category" stroke="#94a3b8" fontSize={11} width={80} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#090b1c', border: '1px solid #1e293b', borderRadius: '8px' }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={14}>
                    {barData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

        </div>

        {/* Right Side: Live WebSocket & DB Alerts Feed */}
        <div className="glass-panel p-6 rounded-xl border-slate-800 flex flex-col h-[500px]">
          <div className="flex justify-between items-center mb-4 border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold tracking-wide uppercase text-slate-200 font-mono">
                SIEM Ingest Stream
              </h3>
              <span className="text-[9px] font-mono text-neon-green tracking-widest block font-bold">
                CONNECTED // LIVE TELEMETRY
              </span>
            </div>
            <Activity className="w-4 h-4 text-neon-green animate-pulse" />
          </div>

          {/* Alerts Feed List */}
          <div className="flex-1 overflow-y-auto space-y-3 pr-1">
            
            {/* Live streaming WebSocket alerts take priority, falling back to db logs */}
            {liveFeed.length > 0 ? (
              liveFeed.map((alert, idx) => (
                <div 
                  key={`live-${alert.id}-${idx}`}
                  className="p-3 bg-[#0d142d]/80 rounded-lg border border-neon-cyan/30 flex flex-col gap-1.5 shadow-[0_0_10px_rgba(0,240,255,0.05)] animate-pulse"
                >
                  <div className="flex justify-between items-start">
                    <span className="text-xs font-bold text-slate-200 truncate pr-2">{alert.title}</span>
                    <span className={`text-[8px] font-mono px-1.5 py-0.5 rounded border uppercase ${severityColor(alert.severity)}`}>
                      {alert.severity}
                    </span>
                  </div>
                  <div className="flex justify-between items-center text-[10px] font-mono text-slate-400">
                    <span className="text-neon-cyan">{alert.category}</span>
                    <span>{new Date(alert.timestamp).toLocaleTimeString()}</span>
                  </div>
                </div>
              ))
            ) : null}

            {/* Static database alerts */}
            {alerts.map((alert) => (
              <div 
                key={alert.id}
                className="p-3 bg-[#070919]/60 rounded-lg border border-slate-800/80 hover:border-slate-700 flex flex-col gap-1.5 transition-colors duration-300"
              >
                <div className="flex justify-between items-start">
                  <span className="text-xs font-semibold text-slate-300 truncate pr-2">{alert.title}</span>
                  <span className={`text-[8px] font-mono px-1.5 py-0.5 rounded border uppercase ${severityColor(alert.severity)}`}>
                    {alert.severity}
                  </span>
                </div>
                <div className="flex justify-between items-center text-[10px] font-mono text-slate-400">
                  <span className="text-slate-500">{alert.category}</span>
                  <span>{new Date(alert.timestamp).toLocaleTimeString()}</span>
                </div>
              </div>
            ))}

            {alerts.length === 0 && liveFeed.length === 0 && (
              <div className="h-full flex items-center justify-center text-xs text-slate-600 font-mono">
                WAITING FOR LIVE INGESTS...
              </div>
            )}
          </div>
        </div>

      </div>

    </div>
  );
}
