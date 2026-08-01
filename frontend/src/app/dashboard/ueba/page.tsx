'use client';

import React, { useState, useEffect } from 'react';
import { Users, ShieldAlert, Clock, Smartphone, Globe, Loader2 } from 'lucide-react';
import { api } from '@/utils/api';

interface UEBAProfile {
  username: string;
  risk_score: number;
  severity: string;
  anomalies_count: number;
  anomalies: any[];
  login_baseline: {
    workplace: string;
    normal_hours: string;
    trusted_devices: string[];
  };
}

export default function UEBA() {
  const [profiles, setProfiles] = useState<UEBAProfile[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchUEBAProfiles();
  }, []);

  const fetchUEBAProfiles = async () => {
    try {
      setLoading(true);
      const data = await api.get('/ueba/users');
      setProfiles(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const riskBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical': return 'text-neon-red border border-neon-red/30 bg-neon-red/5';
      case 'high': return 'text-orange-500 border border-orange-500/30 bg-orange-500/5';
      case 'medium': return 'text-neon-yellow border border-neon-yellow/30 bg-neon-yellow/5';
      default: return 'text-neon-green border border-neon-green/30 bg-neon-green/5';
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold tracking-wide text-slate-100 uppercase">
          User & Entity Behavior Analytics (UEBA)
        </h2>
        <p className="text-xs text-slate-500 font-mono mt-0.5">
          ANOMALY SCORING // LOGIN BASELINES // PRIVILEGED ACCESS AUDITING
        </p>
      </div>

      {loading ? (
        <div className="h-64 flex items-center justify-center text-slate-500 font-mono text-xs">
          <Loader2 className="w-5 h-5 animate-spin mr-2" /> LOADING ACCESS PROFILE BASELINES...
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          {profiles.map((prof, index) => (
            <div 
              key={index} 
              className={`glass-panel p-6 rounded-xl border-slate-800 space-y-5 relative transition-all duration-300 ${
                prof.risk_score > 50 ? 'shadow-[0_0_20px_rgba(255,0,85,0.05)] border-neon-red/20' : ''
              }`}
            >
              
              {/* Header profile info */}
              <div className="flex justify-between items-start">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center font-bold text-neon-cyan text-sm">
                    {prof.username.slice(0, 2).toUpperCase()}
                  </div>
                  <div>
                    <h3 className="text-sm font-extrabold text-slate-200 font-mono">@{prof.username}</h3>
                    <span className="text-[10px] text-slate-500 font-mono">ENTITY TRUSTED PROFILE</span>
                  </div>
                </div>

                <div className="flex flex-col items-end gap-1.5 font-mono">
                  <span className={`text-[9px] px-2 py-0.5 rounded font-bold uppercase ${riskBadge(prof.severity)}`}>
                    {prof.severity} RISK ({prof.risk_score}/100)
                  </span>
                </div>
              </div>

              {/* Baseline stats grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 border-t border-b border-slate-850 py-4 font-mono text-[10px] text-slate-400">
                <div className="space-y-1">
                  <span className="text-slate-500 uppercase font-bold flex items-center gap-1">
                    <Globe className="w-3.5 h-3.5" /> Working Scope
                  </span>
                  <p className="text-slate-350">{prof.login_baseline.workplace}</p>
                </div>
                <div className="space-y-1">
                  <span className="text-slate-500 uppercase font-bold flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" /> Normal Login Hours
                  </span>
                  <p className="text-slate-350">{prof.login_baseline.normal_hours}</p>
                </div>
                <div className="space-y-1">
                  <span className="text-slate-500 uppercase font-bold flex items-center gap-1">
                    <Smartphone className="w-3.5 h-3.5" /> Trusted Assets
                  </span>
                  <p className="text-slate-350">{prof.login_baseline.trusted_devices.join(', ')}</p>
                </div>
              </div>

              {/* Anomalies listed logs */}
              <div className="space-y-2">
                <h4 className="text-xs uppercase text-slate-400 font-mono tracking-widest font-bold flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4 text-neon-red" /> Flagged Anomalous Activity Logs ({prof.anomalies_count})
                </h4>

                <div className="space-y-2">
                  {prof.anomalies.map((anom, idx) => (
                    <div key={idx} className="p-3 bg-[#11050a]/40 border border-neon-red/10 rounded flex justify-between items-center text-[10px] font-mono">
                      <div className="space-y-0.5">
                        <span className="text-slate-200 block font-bold">{anom.title}</span>
                        <span className="text-slate-500">CATEGORY: {anom.category}</span>
                      </div>
                      <span className="text-slate-500">{new Date(anom.timestamp).toLocaleTimeString()}</span>
                    </div>
                  ))}
                  {prof.anomalies_count === 0 && (
                    <div className="p-4 border border-slate-900 rounded text-center text-[10px] text-slate-600 font-mono">
                      NO DEVIATIVE ACTIVITIES DETECTED. USER OPERATING WITHIN BASELINE PREFERENCES.
                    </div>
                  )}
                </div>
              </div>

            </div>
          ))}
        </div>
      )}

    </div>
  );
}
