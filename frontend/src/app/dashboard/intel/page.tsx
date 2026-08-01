'use client';

import React, { useState, useEffect } from 'react';
import { Briefcase, Search, ShieldCheck, ShieldAlert, Layers, Grid, Cpu, Loader2 } from 'lucide-react';
import { api } from '@/utils/api';

export default function ThreatIntel() {
  const [iocQuery, setIocQuery] = useState('185.220.101.4');
  const [iocType, setIocType] = useState('IP');
  const [checking, setChecking] = useState(false);
  const [reputationResult, setReputationResult] = useState<any>(null);
  
  // Heatmap state
  const [heatmap, setHeatmap] = useState<Record<string, number>>({});

  useEffect(() => {
    fetchHeatmap();
  }, []);

  const fetchHeatmap = async () => {
    try {
      const data = await api.get('/intel/mitre-heatmap');
      setHeatmap(data);
    } catch (err) {
      console.error(err);
    }
  };

  const handleCheckReputation = async (e: React.FormEvent) => {
    e.preventDefault();
    setChecking(true);
    setReputationResult(null);
    try {
      const res = await api.post('/intel/reputation-check', {
        value: iocQuery,
        type: iocType
      });
      setReputationResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setChecking(false);
    }
  };

  // MITRE ATT&CK Schema
  const mitreTactics = [
    { name: "Initial Access", techniques: [{ id: "T1078", name: "Valid Accounts" }, { id: "T1190", name: "Exploit Public Application" }] },
    { name: "Execution", techniques: [{ id: "T1059", name: "Command Scripting" }, { id: "T1047", name: "Windows Management (WMI)" }] },
    { name: "Persistence", techniques: [{ id: "T1053", name: "Scheduled Task" }, { id: "T1547", name: "Registry Run Keys" }] },
    { name: "Privilege Escalation", techniques: [{ id: "T1068", name: "Exploit Vulnerability" }, { id: "T1548", name: "Bypass UAC" }] },
    { name: "Defense Evasion", techniques: [{ id: "T1218", name: "System Binary Proxy Execution" }, { id: "T1070", name: "Clear Logs" }] },
    { name: "Credential Access", techniques: [{ id: "T1110", name: "Brute Force" }, { id: "T1003", name: "OS Credential Dumping" }] },
    { name: "Lateral Movement", techniques: [{ id: "T1021", name: "Remote Services" }, { id: "T1570", name: "Lateral Tool Transfer" }] },
    { name: "Exfiltration", techniques: [{ id: "T1048", name: "Exfiltration Alternative Protocol" }, { id: "T1020", name: "Automated Exfiltration" }] },
    { name: "Impact", techniques: [{ id: "T1486", name: "Data Encrypted for Impact" }, { id: "T1489", name: "Service Stopping" }] }
  ];

  // Logic to color matrix cell based on detection counts
  const getCellColor = (techId: string) => {
    const hits = heatmap[techId] || 0;
    if (hits === 0) return 'bg-slate-900/40 border-slate-950 text-slate-500';
    if (hits >= 4) return 'bg-red-950/60 border-neon-red/50 text-neon-red shadow-[0_0_10px_rgba(255,0,85,0.1)]';
    if (hits >= 2) return 'bg-orange-950/60 border-orange-500/50 text-orange-400';
    return 'bg-yellow-950/60 border-yellow-500/50 text-neon-yellow';
  };

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold tracking-wide text-slate-100 uppercase">
          Threat Intelligence Hub
        </h2>
        <p className="text-xs text-slate-500 font-mono mt-0.5">
          IOC AUDITING // REPUTATION CHECKS // MITRE ATT&CK HEATMAPS
        </p>
      </div>

      {/* Row 1: Reputation checking & IOC search */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* Verification Form */}
        <div className="glass-panel p-5 rounded-xl border-slate-800 space-y-4">
          <h3 className="text-xs uppercase text-slate-400 font-mono tracking-widest font-bold flex items-center gap-1.5">
            <Search className="w-4 h-4 text-neon-cyan" /> Indicator Reputation Lookup
          </h3>

          <form onSubmit={handleCheckReputation} className="space-y-4 font-mono text-xs">
            <div className="flex gap-4">
              <div className="flex-1 flex flex-col gap-1">
                <label className="text-[10px] text-slate-500 uppercase">Indicator Value</label>
                <input
                  type="text"
                  value={iocQuery}
                  onChange={(e) => setIocQuery(e.target.value)}
                  required
                  placeholder="e.g. IP, Domain, SHA-256 Hash..."
                  className="bg-slate-950 border border-slate-850 rounded p-2 text-xs text-slate-200 focus:outline-none focus:border-neon-cyan"
                />
              </div>

              <div className="flex flex-col gap-1 w-28">
                <label className="text-[10px] text-slate-500 uppercase">Type</label>
                <select
                  value={iocType}
                  onChange={(e) => setIocType(e.target.value)}
                  className="bg-slate-950 border border-slate-850 rounded p-2 text-xs text-slate-350 focus:outline-none cursor-pointer"
                >
                  <option value="IP">IP Address</option>
                  <option value="Domain">Domain</option>
                  <option value="Hash">SHA-256 Hash</option>
                  <option value="URL">URL</option>
                </select>
              </div>
            </div>

            <button
              type="submit"
              disabled={checking}
              className="w-full py-2.5 rounded bg-neon-cyan text-black font-extrabold uppercase tracking-wider flex items-center justify-center gap-1.5 transition-all duration-300 disabled:opacity-50 cursor-pointer shadow-[0_0_10px_rgba(0,240,255,0.15)]"
            >
              {checking ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Verifying IOC...</span>
                </>
              ) : (
                <span>Check Reputation</span>
              )}
            </button>
          </form>
        </div>

        {/* Verification Output */}
        <div className="glass-panel p-5 rounded-xl border-slate-800 flex flex-col justify-between min-h-[175px]">
          <span className="text-[10px] uppercase text-slate-500 font-mono tracking-widest font-bold">
            Reputation Feedback Audit
          </span>

          {checking ? (
            <div className="flex-1 flex items-center justify-center text-slate-500 font-mono text-xs">
              SCANNING GLOBALLY INTEGRATED TI FEEDS...
            </div>
          ) : reputationResult ? (
            <div className="flex-1 flex flex-col justify-center gap-3 font-mono text-xs mt-3">
              <div className="flex justify-between items-center">
                <span className="text-slate-200 font-semibold truncate max-w-[200px]">{reputationResult.value}</span>
                <span className={`px-2 py-0.5 rounded border text-[9px] font-bold uppercase ${
                  reputationResult.reputation === 'Malicious' ? 'text-neon-red border-neon-red/30 bg-neon-red/5' : 'text-neon-green border-neon-green/30 bg-neon-green/5'
                }`}>
                  {reputationResult.reputation} (Score: {reputationResult.score}%)
                </span>
              </div>
              <div className="bg-slate-950/60 p-3 rounded border border-slate-850 text-[10px] text-slate-400 space-y-1">
                <p><span className="text-slate-500">Actor Profile:</span> {reputationResult.threat_actor}</p>
                <p><span className="text-slate-500">Description:</span> {reputationResult.details}</p>
                <p className="text-[9px] text-slate-600 font-semibold pt-1 border-t border-slate-900">FEED: {reputationResult.source}</p>
              </div>
            </div>
          ) : (
            <div className="flex-1 flex items-center justify-center text-xs text-slate-600 font-mono text-center">
              ENTER AN INDICATOR VALUE ON THE LEFT TO AUDIT ENRICHMENT DATA.
            </div>
          )}
        </div>

      </div>

      {/* Row 2: MITRE Heatmap Matrix */}
      <div className="glass-panel p-6 rounded-xl border-slate-800 space-y-4">
        <div className="flex justify-between items-center border-b border-slate-850 pb-3">
          <div className="flex items-center gap-2">
            <Grid className="w-5 h-5 text-neon-purple" />
            <h3 className="text-xs uppercase text-slate-200 font-mono tracking-widest font-bold">
              MITRE ATT&CK Matrix (Active Heatmap)
            </h3>
          </div>
          <span className="text-[9px] font-mono text-slate-500">
            DYNAMIC ALERTS CO-RELATION MAPPED LIVE
          </span>
        </div>

        {/* Matrix Grid */}
        <div className="grid grid-cols-2 md:grid-cols-5 xl:grid-cols-9 gap-3">
          {mitreTactics.map((tactic, idx) => (
            <div key={idx} className="space-y-2 border border-slate-900 p-2.5 rounded bg-slate-950/40">
              <h5 className="text-[9px] font-extrabold uppercase font-mono tracking-wider text-slate-400 truncate border-b border-slate-900 pb-1.5">
                {tactic.name}
              </h5>
              <div className="space-y-2">
                {tactic.techniques.map((tech) => (
                  <div
                    key={tech.id}
                    className={`p-2.5 rounded border text-[9px] font-mono leading-relaxed transition-all duration-300 flex flex-col gap-1 cursor-pointer select-none ${getCellColor(tech.id)}`}
                  >
                    <span className="font-bold">{tech.id}</span>
                    <span className="leading-snug truncate block">{tech.name}</span>
                    {heatmap[tech.id] > 0 && (
                      <span className="text-[8px] opacity-80 mt-1 block">({heatmap[tech.id]} detections)</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
