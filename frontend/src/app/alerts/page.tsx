'use client';
import { useState } from 'react';
import { Shield, Filter, Search } from 'lucide-react';

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([
    { id: 'ALT-101', type: 'Failed Login', source: '203.0.113.5', dest: '10.0.1.5', time: '10:15:00', severity: 'Low' },
    { id: 'ALT-102', type: 'Failed Login', source: '203.0.113.5', dest: '10.0.1.5', time: '10:15:01', severity: 'Low' },
    { id: 'ALT-103', type: 'Failed Login', source: '203.0.113.5', dest: '10.0.1.5', time: '10:15:02', severity: 'Low' },
    { id: 'ALT-104', type: 'File Write', source: '10.0.2.50', dest: 'Local', time: '10:38:12', severity: 'High' },
    { id: 'ALT-105', type: 'Malicious Payload', source: '185.12.33.44', dest: '10.0.0.1', time: '10:42:05', severity: 'Critical' }
  ]);

  return (
    <div className="p-8">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white mb-1">SIEM Alerts</h1>
          <p className="text-gray-400">Raw alert stream from detection engine</p>
        </div>
        <div className="flex space-x-3">
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-gray-500" />
            <input type="text" placeholder="Search alerts..." className="cyber-input pl-9 w-64" />
          </div>
          <button className="cyber-button flex items-center">
            <Filter className="w-4 h-4 mr-2" /> Filter
          </button>
        </div>
      </div>

      <div className="cyber-card">
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-[#232333] text-gray-400 text-sm">
                <th className="pb-4 font-medium px-4">Alert ID</th>
                <th className="pb-4 font-medium px-4">Time</th>
                <th className="pb-4 font-medium px-4">Rule Name</th>
                <th className="pb-4 font-medium px-4">Source</th>
                <th className="pb-4 font-medium px-4">Destination</th>
                <th className="pb-4 font-medium px-4">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#232333]">
              {alerts.map((alert) => (
                <tr key={alert.id} className="hover:bg-[#0a0a0f] transition-colors group">
                  <td className="py-3 px-4 font-mono text-[#00f3ff] text-sm">{alert.id}</td>
                  <td className="py-3 px-4 text-sm text-gray-400">{alert.time}</td>
                  <td className="py-3 px-4 font-medium text-white">{alert.type}</td>
                  <td className="py-3 px-4 font-mono text-xs text-gray-300">{alert.source}</td>
                  <td className="py-3 px-4 font-mono text-xs text-gray-300">{alert.dest}</td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-1 text-xs rounded border ${
                      alert.severity === 'Critical' ? 'bg-[#ff003c]/10 text-[#ff003c] border-[#ff003c]/30' :
                      alert.severity === 'High' ? 'bg-[#ff8c00]/10 text-[#ff8c00] border-[#ff8c00]/30' :
                      alert.severity === 'Low' ? 'bg-[#00f3ff]/10 text-[#00f3ff] border-[#00f3ff]/30' :
                      'bg-[#39ff14]/10 text-[#39ff14] border-[#39ff14]/30'
                    }`}>
                      {alert.severity}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
