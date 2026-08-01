'use client';

import React, { useState, useEffect } from 'react';
import { FileSearch, Lock, Database, Clock, HardDrive, Globe, Usb, ShieldCheck, Loader2 } from 'lucide-react';
import { api } from '@/utils/api';

interface Evidence {
  id: number;
  incident_id: number;
  file_name: string;
  file_hash: string;
  file_size: number;
  chain_of_custody: string;
  uploaded_by: string;
  uploaded_at: string;
}

export default function ForensicsWorkspace() {
  const [evidenceList, setEvidenceList] = useState<Evidence[]>([]);
  const [activeSubTab, setActiveSubTab] = useState<'evidence' | 'prefetch' | 'usb' | 'browser'>('evidence');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchEvidence();
  }, []);

  const fetchEvidence = async () => {
    try {
      setLoading(true);
      const data = await api.get('/forensics/evidence');
      setEvidenceList(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const mockPrefetch = [
    { name: 'RANSOMWARE.EXE', count: 1, path: '\\USERS\\JDOE\\DOWNLOADS\\', lastRun: '15 mins ago' },
    { name: 'CERTUTIL.EXE', count: 3, path: '\\WINDOWS\\SYSTEM32\\', lastRun: '25 mins ago' },
    { name: 'WMIC.EXE', count: 12, path: '\\WINDOWS\\SYSTEM32\\WBEM\\', lastRun: '1 hour ago' },
    { name: 'POWERSHELL.EXE', count: 48, path: '\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\', lastRun: '4 mins ago' }
  ];

  const mockUsb = [
    { serial: 'USB-SN-455294', vendor: 'Kingston DataTraveler', drive: 'E:', connectedAt: '2 hours ago' },
    { serial: 'USB-SN-125049', vendor: 'SanDisk Cruzer', drive: 'F:', connectedAt: '3 days ago' }
  ];

  const mockBrowser = [
    { url: 'http://evil-c2-server.net/payload.exe', title: 'Payload Dropper download link', visits: 1, timestamp: '20 mins ago' },
    { url: 'https://github.com/danielmiessler/SecLists', title: 'danielmiessler/SecLists GitHub repository', visits: 14, timestamp: '1 day ago' },
    { url: 'https://stackoverflow.com/questions', title: 'Stack Overflow coding questions', visits: 45, timestamp: '2 hours ago' }
  ];

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold tracking-wide text-slate-100 uppercase">
          Digital Forensics & Incident Response
        </h2>
        <p className="text-xs text-slate-500 font-mono mt-0.5">
          TELEMETRY ANALYSIS // TIMELINES // EVIDENCE CHAIN OF CUSTODY
        </p>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 bg-[#070919]/60 px-6 rounded-t-xl">
        {[
          { id: 'evidence', name: 'Evidence Lockbox', icon: Lock },
          { id: 'prefetch', name: 'Prefetch Executor', icon: HardDrive },
          { id: 'usb', name: 'USB Device History', icon: Usb },
          { id: 'browser', name: 'Browser Artifacts', icon: Globe }
        ].map((tab) => {
          const Icon = tab.icon;
          const isCurrent = activeSubTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveSubTab(tab.id as any)}
              className={`py-3 px-4 border-b-2 font-mono text-xs flex items-center gap-2 transition-all duration-300 ${
                isCurrent
                  ? 'border-neon-cyan text-neon-cyan font-bold bg-neon-cyan/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.name}</span>
            </button>
          );
        })}
      </div>

      {/* Tab 1: Evidence Locker */}
      {activeSubTab === 'evidence' && (
        <div className="space-y-4">
          <span className="text-xs uppercase text-slate-500 font-mono">
            Chain of Custody Sealing Locker
          </span>

          {loading ? (
            <div className="h-44 flex items-center justify-center text-slate-500 font-mono text-xs">
              <Loader2 className="w-5 h-5 animate-spin mr-2" /> SCANNING FOR SEALED INCIDENT EVIDENCE FILES...
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {evidenceList.map((ev) => (
                <div key={ev.id} className="glass-panel p-5 rounded-xl border-slate-800 space-y-4 font-mono text-xs">
                  <div className="flex justify-between items-start">
                    <div className="space-y-1">
                      <span className="text-[10px] text-slate-500">INCIDENT ID: #{ev.incident_id}</span>
                      <h4 className="text-xs font-bold text-slate-200">{ev.file_name}</h4>
                    </div>
                    <span className="text-[10px] text-slate-500">{(ev.file_size / 1024).toFixed(1)} KB</span>
                  </div>

                  <div className="bg-slate-950 p-3 rounded border border-slate-850 space-y-2 text-[10px] text-slate-400">
                    <div>
                      <span className="text-slate-500">SHA-256 HASH:</span>
                      <span className="text-neon-cyan block truncate">{ev.file_hash}</span>
                    </div>
                    <div className="flex justify-between items-center text-[9px] text-slate-500">
                      <span>UPLOADER: {ev.uploaded_by}</span>
                      <span>DATE: {new Date(ev.uploaded_at).toLocaleString()}</span>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[9px] text-slate-400 font-bold">CHAIN OF CUSTODY LOG trail:</span>
                    <pre className="text-[8px] bg-black/40 p-2.5 rounded text-slate-500 whitespace-pre-wrap leading-relaxed max-h-24 overflow-auto">
                      {ev.chain_of_custody}
                    </pre>
                  </div>
                </div>
              ))}
              {evidenceList.length === 0 && (
                <div className="md:col-span-2 p-10 border border-dashed border-slate-800 rounded-xl text-center text-xs text-slate-650 font-mono">
                  NO FORENSIC ARTIFACTS OR SECURED EVIDENCE HAS BEEN REGISTERED. UPLOAD EVIDENCE IN THE INCIDENTS TAB.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Prefetch Analyzer */}
      {activeSubTab === 'prefetch' && (
        <div className="space-y-4">
          <span className="text-xs uppercase text-slate-500 font-mono">
            Endpoint Execution Logs (Prefetch)
          </span>

          <div className="glass-panel rounded-xl border-slate-800 overflow-hidden">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#090b1c]/80 text-slate-400 uppercase tracking-widest text-[9px] border-b border-slate-850">
                <tr>
                  <th className="p-4">Executable Name</th>
                  <th className="p-4">Execution Counts</th>
                  <th className="p-4">Binary Location</th>
                  <th className="p-4">Last Execution Interval</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {mockPrefetch.map((pref, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/20 text-slate-350">
                    <td className="p-4 font-bold text-slate-200">{pref.name}</td>
                    <td className="p-4 text-neon-cyan">{pref.count} times</td>
                    <td className="p-4 text-slate-400">{pref.path}</td>
                    <td className="p-4 text-slate-500">{pref.lastRun}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 3: USB History */}
      {activeSubTab === 'usb' && (
        <div className="space-y-4">
          <span className="text-xs uppercase text-slate-500 font-mono">
            USB Storage Connective History logs
          </span>

          <div className="glass-panel rounded-xl border-slate-800 overflow-hidden">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#090b1c]/80 text-slate-400 uppercase tracking-widest text-[9px] border-b border-slate-850">
                <tr>
                  <th className="p-4">Serial Identifier</th>
                  <th className="p-4">Hardware Vendor Description</th>
                  <th className="p-4">Mount Directory</th>
                  <th className="p-4">Plug Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {mockUsb.map((usb, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/20 text-slate-350">
                    <td className="p-4 font-bold text-neon-cyan">{usb.serial}</td>
                    <td className="p-4 text-slate-200">{usb.vendor}</td>
                    <td className="p-4 text-slate-400">{usb.drive}</td>
                    <td className="p-4 text-slate-500">{usb.connectedAt}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 4: Browser history */}
      {activeSubTab === 'browser' && (
        <div className="space-y-4">
          <span className="text-xs uppercase text-slate-500 font-mono">
            Recent Browser URL navigation audits
          </span>

          <div className="glass-panel rounded-xl border-slate-800 overflow-hidden">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#090b1c]/80 text-slate-400 uppercase tracking-widest text-[9px] border-b border-slate-850">
                <tr>
                  <th className="p-4">Destination Host URL</th>
                  <th className="p-4">Window Title</th>
                  <th className="p-4">Navigation Count</th>
                  <th className="p-4">Audited Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {mockBrowser.map((brow, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/20 text-slate-350">
                    <td className="p-4 max-w-[280px] truncate font-bold text-neon-cyan hover:underline cursor-pointer">{brow.url}</td>
                    <td className="p-4 text-slate-200">{brow.title}</td>
                    <td className="p-4 text-slate-400">{brow.visits} times</td>
                    <td className="p-4 text-slate-500">{brow.timestamp}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

    </div>
  );
}
