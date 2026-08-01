'use client';
import { useState, useEffect } from 'react';
import { AlertTriangle, Filter, Plus, FileText, Activity } from 'lucide-react';

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState([
    { id: 'INC-2024-001', title: 'Ransomware Behavior Detected', severity: 'Critical', status: 'Investigating', assignee: 'AI Analyst', created: '2 hrs ago' },
    { id: 'INC-2024-002', title: 'Impossible Travel Login', severity: 'High', status: 'New', assignee: 'Unassigned', created: '5 hrs ago' },
    { id: 'INC-2024-003', title: 'Multiple Failed Logins', severity: 'Medium', status: 'Closed', assignee: 'John Doe', created: '1 day ago' }
  ]);

  return (
    <div className="p-8">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white mb-1">Incident Management</h1>
          <p className="text-gray-400">Track and respond to correlated security events</p>
        </div>
        <div className="flex space-x-3">
          <button className="cyber-button flex items-center">
            <Filter className="w-4 h-4 mr-2" /> Filter
          </button>
          <button className="cyber-button-primary flex items-center">
            <Plus className="w-4 h-4 mr-2" /> New Incident
          </button>
        </div>
      </div>

      <div className="cyber-card">
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-[#232333] text-gray-400 text-sm">
                <th className="pb-4 font-medium px-4">Incident ID</th>
                <th className="pb-4 font-medium px-4">Title</th>
                <th className="pb-4 font-medium px-4">Severity</th>
                <th className="pb-4 font-medium px-4">Status</th>
                <th className="pb-4 font-medium px-4">Assignee</th>
                <th className="pb-4 font-medium px-4">Created</th>
                <th className="pb-4 font-medium px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#232333]">
              {incidents.map((incident) => (
                <tr key={incident.id} className="hover:bg-[#0a0a0f] transition-colors group">
                  <td className="py-4 px-4 font-mono text-[#00f3ff] text-sm">{incident.id}</td>
                  <td className="py-4 px-4 font-medium text-white">{incident.title}</td>
                  <td className="py-4 px-4">
                    <span className={`px-2 py-1 text-xs rounded border ${
                      incident.severity === 'Critical' ? 'bg-[#ff003c]/10 text-[#ff003c] border-[#ff003c]/30' :
                      incident.severity === 'High' ? 'bg-[#ff8c00]/10 text-[#ff8c00] border-[#ff8c00]/30' :
                      'bg-[#39ff14]/10 text-[#39ff14] border-[#39ff14]/30'
                    }`}>
                      {incident.severity}
                    </span>
                  </td>
                  <td className="py-4 px-4 text-sm text-gray-300">{incident.status}</td>
                  <td className="py-4 px-4 text-sm text-gray-300 flex items-center">
                    {incident.assignee === 'AI Analyst' && <Activity className="w-3 h-3 mr-2 text-[#bc13fe]" />}
                    {incident.assignee}
                  </td>
                  <td className="py-4 px-4 text-sm text-gray-400">{incident.created}</td>
                  <td className="py-4 px-4 text-right">
                    <button className="text-[#00f3ff] hover:text-white transition-colors text-sm font-medium">Investigate</button>
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
