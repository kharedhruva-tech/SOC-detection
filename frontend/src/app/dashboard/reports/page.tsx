'use client';

import React, { useState, useEffect } from 'react';
import { TrendingUp, FileText, Download, CheckSquare, Layers, Award, Loader2 } from 'lucide-react';
import { api, API_BASE_URL } from '@/utils/api';

interface ReportData {
  report_generated_at: string;
  total_incidents: number;
  open_incidents: number;
  closed_incidents: number;
  total_alerts: number;
  new_alerts: number;
  unpatched_vulns: number;
  critical_vulns: number;
  average_response_time: string;
  average_resolution_time: string;
  compliance_score: number;
  analyst_performance: any[];
}

export default function Reports() {
  const [data, setData] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchReport();
  }, []);

  const fetchReport = async () => {
    try {
      setLoading(true);
      const res = await api.get('/reports/summary');
      setData(res);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadCSV = () => {
    const token = localStorage.getItem('soc_token');
    const url = `${API_BASE_URL}/reports/export/csv`;
    
    // Create a temporary link and trigger download with auth token parameter or standard window location.
    // For standard window download of secure endpoints:
    const a = document.createElement('a');
    a.href = url;
    // Standard window download can use cookie or link triggers. For simplicity in prototype, we route directly:
    window.open(`${url}?token=${token}`, '_blank');
  };

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold tracking-wide text-slate-100 uppercase">
            Executive & Compliance Reporting
          </h2>
          <p className="text-xs text-slate-500 font-mono mt-0.5">
            KPI SCORECARDS // SLAS // COMPLIANCE TRACKING LOGS
          </p>
        </div>

        <button
          onClick={handleDownloadCSV}
          className="px-4 py-2 rounded bg-neon-cyan text-black font-extrabold text-[11px] uppercase tracking-wider flex items-center gap-1.5 transition-all duration-300 hover:bg-neon-cyan/80 cursor-pointer shadow-[0_0_15px_rgba(0,240,255,0.15)]"
        >
          <Download className="w-4 h-4" />
          <span>Export Incidents CSV</span>
        </button>
      </div>

      {loading ? (
        <div className="h-64 flex items-center justify-center text-slate-500 font-mono text-xs">
          <Loader2 className="w-5 h-5 animate-spin mr-2" /> COMPILES SOC AUDIT SCORECARDS...
        </div>
      ) : data ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          
          {/* Box 1: KPI scorecard */}
          <div className="glass-panel p-5 rounded-xl border-slate-800 space-y-4 font-mono text-xs md:col-span-2">
            <h3 className="text-xs uppercase text-slate-400 font-mono tracking-widest font-bold border-b border-slate-850 pb-2 flex items-center gap-1.5">
              <TrendingUp className="w-4 h-4 text-neon-green" /> SOC Operations Performance Metrics
            </h3>

            <div className="grid grid-cols-2 gap-6 py-2">
              <div className="space-y-1">
                <span className="text-slate-500 uppercase font-bold block">Incident Load</span>
                <p className="text-slate-200 text-sm">
                  {data.open_incidents} Active / {data.total_incidents} Total Cases
                </p>
              </div>
              <div className="space-y-1">
                <span className="text-slate-500 uppercase font-bold block">Average Resolution SLA</span>
                <p className="text-slate-200 text-sm">{data.average_resolution_time}</p>
              </div>
              <div className="space-y-1">
                <span className="text-slate-500 uppercase font-bold block">Telemetry Alert Ingests</span>
                <p className="text-slate-200 text-sm">{data.total_alerts} Normalized Events</p>
              </div>
              <div className="space-y-1">
                <span className="text-slate-500 uppercase font-bold block">Mitre TTP Coverage</span>
                <p className="text-slate-200 text-sm">{data.compliance_score}% Coverage score</p>
              </div>
            </div>
          </div>

          {/* Box 2: Compliance scorecard */}
          <div className="glass-panel p-5 rounded-xl border-slate-800 space-y-4 font-mono text-xs flex flex-col justify-between">
            <h3 className="text-xs uppercase text-slate-400 font-mono tracking-widest font-bold border-b border-slate-850 pb-2 flex items-center gap-1.5">
              <Award className="w-4 h-4 text-neon-purple animate-pulse" /> Compliance Alignment
            </h3>

            <div className="space-y-3 flex-1 flex flex-col justify-center">
              <div className="flex justify-between items-center text-[10px]">
                <span className="text-slate-300">SOC 2 TYPE II Standard</span>
                <span className="text-neon-green font-bold">COMPLIANT (98%)</span>
              </div>
              <div className="flex justify-between items-center text-[10px]">
                <span className="text-slate-300">ISO/IEC 27001 Checklist</span>
                <span className="text-neon-green font-bold">COMPLIANT (95%)</span>
              </div>
              <div className="flex justify-between items-center text-[10px]">
                <span className="text-slate-300">NIST 800-53 Framework</span>
                <span className="text-neon-cyan font-bold">IN REVIEW (92%)</span>
              </div>
            </div>
          </div>

          {/* Row 2 Box 3: Analyst SLAs */}
          <div className="glass-panel rounded-xl border-slate-800 p-5 md:col-span-3 font-mono text-xs space-y-4">
            <h3 className="text-xs uppercase text-slate-400 font-mono tracking-widest font-bold border-b border-slate-850 pb-2 flex items-center gap-1.5">
              <FileText className="w-4 h-4 text-neon-cyan" /> Analyst Closure SLAs
            </h3>

            <table className="w-full text-left text-xs mt-3">
              <thead className="bg-[#090b1c]/80 text-slate-500 uppercase tracking-widest text-[9px]">
                <tr>
                  <th className="p-3">Analyst Node</th>
                  <th className="p-3">Resolved Incident Count</th>
                  <th className="p-3">SLA Target met</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {data.analyst_performance.map((analyst, index) => (
                  <tr key={index} className="text-slate-300">
                    <td className="p-3 font-bold text-slate-200">{analyst.name}</td>
                    <td className="p-3 text-neon-cyan">{analyst.closed} cases</td>
                    <td className="p-3 text-neon-green font-semibold">{analyst.sla} SLA</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

        </div>
      ) : (
        <div className="p-10 border border-slate-800 rounded-xl text-center text-xs text-slate-600 font-mono">
          FAILED COMPILES FROM SERVER REPORT SERVICE.
        </div>
      )}

    </div>
  );
}
