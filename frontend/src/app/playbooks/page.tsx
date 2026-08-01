'use client';
import { useState } from 'react';
import { BookOpen, Play, Edit, Trash2 } from 'lucide-react';

export default function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState([
    { id: 1, name: 'Ransomware Containment', description: 'Isolates host and disables AD account when ransomware is detected.', status: 'Active', runs: 24 },
    { id: 2, name: 'Phishing Response', description: 'Blocks sender IP and deletes malicious emails from inboxes.', status: 'Active', runs: 142 },
    { id: 3, name: 'Impossible Travel Mitigation', description: 'Forces MFA re-authentication and disables VPN access.', status: 'Inactive', runs: 0 },
  ]);

  return (
    <div className="p-8">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white mb-1">SOAR Playbooks</h1>
          <p className="text-gray-400">Automate incident response and remediation</p>
        </div>
        <button className="cyber-button-primary flex items-center">
          <BookOpen className="w-4 h-4 mr-2" /> Create Playbook
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {playbooks.map(playbook => (
          <div key={playbook.id} className="cyber-card flex flex-col">
            <div className="flex justify-between items-start mb-4">
              <h2 className="text-lg font-bold text-white">{playbook.name}</h2>
              <span className={`px-2 py-1 text-xs rounded border ${
                playbook.status === 'Active' ? 'bg-[#39ff14]/10 text-[#39ff14] border-[#39ff14]/30' : 'bg-gray-800 text-gray-400 border-gray-600'
              }`}>
                {playbook.status}
              </span>
            </div>
            <p className="text-gray-400 text-sm mb-6 flex-1">{playbook.description}</p>
            <div className="flex items-center justify-between pt-4 border-t border-[#232333]">
              <span className="text-xs text-gray-500">Total Runs: <span className="text-[#00f3ff] font-mono">{playbook.runs}</span></span>
              <div className="flex space-x-2">
                <button className="p-2 hover:text-[#00f3ff] text-gray-400 transition-colors"><Play className="w-4 h-4" /></button>
                <button className="p-2 hover:text-[#bc13fe] text-gray-400 transition-colors"><Edit className="w-4 h-4" /></button>
                <button className="p-2 hover:text-[#ff003c] text-gray-400 transition-colors"><Trash2 className="w-4 h-4" /></button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
