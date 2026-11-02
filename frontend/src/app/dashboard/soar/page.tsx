'use client';

import React, { useState, useEffect } from 'react';
import ReactFlow, { 
  MiniMap, 
  Controls, 
  Background, 
  useNodesState, 
  useEdgesState,
  Edge,
  Node,
  MarkerType
} from 'reactflow';
import 'reactflow/dist/style.css';
import { 
  GitBranch, 
  Play, 
  Save, 
  Plus, 
  Loader2, 
  RefreshCw, 
  CheckCircle2, 
  Clock, 
  AlertTriangle, 
  ShieldCheck, 
  Terminal,
  Activity,
  Layers
} from 'lucide-react';
import { api } from '@/utils/api';

// Pre-seeded playbook blueprints
const PRESETS = {
  ransomware: {
    name: "Automated Ransomware Containment",
    nodes: [
      { id: '1', type: 'input', data: { label: '🚨 Trigger: Ransomware Indicator' }, position: { x: 250, y: 20 }, style: { background: '#1c0b14', color: '#ff0055', border: '1px solid #ff0055', fontFamily: 'monospace', fontSize: 11, borderRadius: 6, padding: '8px 12px' } },
      { id: '2', data: { label: '🔍 Enrich Host IOCs via Threat Intel' }, position: { x: 250, y: 120 }, style: { background: '#0a0f24', color: '#00f0ff', border: '1px solid #00f0ff', fontFamily: 'monospace', fontSize: 11, borderRadius: 6, padding: '8px 12px' } },
      { id: '3', data: { label: '🚫 Isolate Endpoint (EDR Policy)' }, position: { x: 250, y: 220 }, style: { background: '#141c28', color: '#ffcc00', border: '1px solid #ffcc00', fontFamily: 'monospace', fontSize: 11, borderRadius: 6, padding: '8px 12px' } },
      { id: '4', data: { label: '🔒 Revoke Active Tokens & Disable User' }, position: { x: 250, y: 320 }, style: { background: '#180c2a', color: '#c084fc', border: '1px solid #c084fc', fontFamily: 'monospace', fontSize: 11, borderRadius: 6, padding: '8px 12px' } },
      { id: '5', type: 'output', data: { label: '📢 Notify War Room (Slack / Teams)' }, position: { x: 250, y: 420 }, style: { background: '#091c14', color: '#34d399', border: '1px solid #34d399', fontFamily: 'monospace', fontSize: 11, borderRadius: 6, padding: '8px 12px' } }
    ],
    edges: [
      { id: 'e1-2', source: '1', target: '2', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#00f0ff' } },
      { id: 'e2-3', source: '2', target: '3', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#ffcc00' } },
      { id: 'e3-4', source: '3', target: '4', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#c084fc' } },
      { id: 'e4-5', source: '4', target: '5', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#34d399' } }
    ]
  },
  bruteforce: {
    name: "Malicious IP Connection Blocking",
    nodes: [
      { id: '1', type: 'input', data: { label: '🚨 Trigger: Brute Force / Port Scan' }, position: { x: 250, y: 20 }, style: { background: '#1c0b14', color: '#ff0055', border: '1px solid #ff0055', fontFamily: 'monospace', fontSize: 11, borderRadius: 6, padding: '8px 12px' } },
      { id: '2', data: { label: '🚦 Check AbuseIPDB & Threat Intel' }, position: { x: 250, y: 120 }, style: { background: '#0a0f24', color: '#00f0ff', border: '1px solid #00f0ff', fontFamily: 'monospace', fontSize: 11, borderRadius: 6, padding: '8px 12px' } },
      { id: '3', data: { label: '👤 SOC Commander Approval Gate' }, position: { x: 250, y: 220 }, style: { background: '#241a08', color: '#fb923c', border: '1px solid #fb923c', fontFamily: 'monospace', fontSize: 11, borderRadius: 6, padding: '8px 12px' } },
      { id: '4', data: { label: '🛡️ Block IP on Perimeter Firewall' }, position: { x: 120, y: 320 }, style: { background: '#1c0b14', color: '#ff0055', border: '1px solid #ff0055', fontFamily: 'monospace', fontSize: 11, borderRadius: 6, padding: '8px 12px' } },
      { id: '5', type: 'output', data: { label: '📝 Audit Log in SIEM Event Trail' }, position: { x: 380, y: 320 }, style: { background: '#091c14', color: '#34d399', border: '1px solid #34d399', fontFamily: 'monospace', fontSize: 11, borderRadius: 6, padding: '8px 12px' } }
    ],
    edges: [
      { id: 'e1-2', source: '1', target: '2', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#00f0ff' } },
      { id: 'e2-3', source: '2', target: '3', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#fb923c' } },
      { id: 'e3-4', source: '3', target: '4', label: 'Approved', markerEnd: { type: MarkerType.ArrowClosed, color: '#ff0055' } },
      { id: 'e3-5', source: '3', target: '5', label: 'Audit Only', markerEnd: { type: MarkerType.ArrowClosed, color: '#34d399' } }
    ]
  }
};

interface ExecutionHistoryItem {
  id: string;
  playbookName: string;
  trigger: string;
  status: 'Completed' | 'Pending Approval' | 'Executing';
  timestamp: string;
  duration: string;
  analyst: string;
}

export default function SOARCanvas() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  
  const [playbooks, setPlaybooks] = useState<any[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState<any>(null);
  const [saving, setSaving] = useState(false);
  const [mounted, setMounted] = useState(false);
  const [activeSubTab, setActiveSubTab] = useState<'canvas' | 'history'>('canvas');
  const [isExecuting, setIsExecuting] = useState(false);
  const [approvalGateStatus, setApprovalGateStatus] = useState<'idle' | 'waiting' | 'approved' | 'rejected'>('idle');

  const [history, setHistory] = useState<ExecutionHistoryItem[]>([
    {
      id: 'EXEC-9821',
      playbookName: 'Malicious IP Connection Blocking',
      trigger: 'ALT-BR-001 (Brute Force detected on 185.220.101.4)',
      status: 'Completed',
      timestamp: '10 min ago',
      duration: '1.2s',
      analyst: 'Tier 3 SecOps'
    },
    {
      id: 'EXEC-9820',
      playbookName: 'Automated Ransomware Containment',
      trigger: 'ALT-MD-007 (WannaCry signature match on WKSTN-09)',
      status: 'Completed',
      timestamp: '32 min ago',
      duration: '4.8s',
      analyst: 'Automated Copilot'
    },
    {
      id: 'EXEC-9819',
      playbookName: 'Malicious IP Connection Blocking',
      trigger: 'ALT-PS-008 (High-speed port scan from 45.142.122.9)',
      status: 'Pending Approval',
      timestamp: '1 hr ago',
      duration: 'Waiting',
      analyst: 'Tier 2 Analyst'
    }
  ]);

  useEffect(() => {
    setMounted(true);
    fetchPlaybooks();
  }, []);

  const fetchPlaybooks = async () => {
    try {
      const data = await api.get('/playbooks/');
      setPlaybooks(data);
      if (data.length > 0) {
        loadPlaybookPreset(data[0]);
      }
    } catch (err) {
      console.error(err);
      // Fallback to local blueprints if API playbooks table is empty
      const localPresets = [
        { id: 1, name: 'Automated Ransomware Containment', description: 'Isolate host EDR and notify SOC war room', version: '2.1' },
        { id: 2, name: 'Malicious IP Connection Blocking', description: 'Enrich threat intel and block malicious inbound traffic', version: '1.4' }
      ];
      setPlaybooks(localPresets);
      loadPlaybookPreset(localPresets[0]);
    }
  };

  const loadPlaybookPreset = (pb: any) => {
    setSelectedPlaybook(pb);
    if (pb.nodes && pb.nodes.length > 0) {
      setNodes(pb.nodes);
      setEdges(pb.edges);
    } else {
      const preset = pb.name?.includes("Ransomware") ? PRESETS.ransomware : PRESETS.bruteforce;
      setNodes(preset.nodes);
      setEdges(preset.edges);
    }
  };

  const handleSavePlaybook = async () => {
    if (!selectedPlaybook) return;
    setSaving(true);
    try {
      await api.put(`/playbooks/${selectedPlaybook.id}`, {
        nodes: nodes,
        edges: edges
      });
      alert('Playbook blueprint successfully saved!');
    } catch (err) {
      console.error(err);
    } finally {
      setSaving(false);
    }
  };

  const handleAddActionNode = () => {
    const id = (nodes.length + 1).toString();
    const newNode: Node = {
      id,
      data: { label: `⚡ Custom Automated Action ${id}` },
      position: { x: 120 + Math.random() * 200, y: 140 + Math.random() * 200 },
      style: { background: '#0a0f24', color: '#00f0ff', border: '1px solid #00f0ff', fontFamily: 'monospace', fontSize: 11, borderRadius: 6, padding: '8px 12px' }
    };
    setNodes(prev => [...prev, newNode]);
  };

  const handleSimulateExecution = () => {
    setIsExecuting(true);
    setTimeout(() => {
      setIsExecuting(false);
      const newExec: ExecutionHistoryItem = {
        id: `EXEC-${Math.floor(1000 + Math.random() * 9000)}`,
        playbookName: selectedPlaybook?.name || 'Automated Playbook',
        trigger: 'Manual SOC Operator Simulation',
        status: 'Completed',
        timestamp: 'Just now',
        duration: '0.8s',
        analyst: 'Tier 3 SecOps'
      };
      setHistory(prev => [newExec, ...prev]);
    }, 1500);
  };

  if (!mounted) return null;

  return (
    <div className="space-y-5 flex flex-col h-[calc(100vh-140px)]">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center text-cyan-400">
              <GitBranch className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-xl font-bold tracking-wider text-white">
                SOAR Automation Orchestrator
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                SECURITY ORCHESTRATION, AUTOMATION & RESPONSE • WORKFLOW BLUEPRINTS
              </p>
            </div>
          </div>
        </div>

        {/* Action Buttons & Subtab Switch */}
        <div className="flex items-center gap-2">
          <div className="flex p-0.5 rounded-lg bg-slate-900 border border-slate-800 font-mono text-xs mr-2">
            <button
              onClick={() => setActiveSubTab('canvas')}
              className={`px-3 py-1 rounded transition ${
                activeSubTab === 'canvas' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-white'
              }`}
            >
              Workflow Visualizer
            </button>
            <button
              onClick={() => setActiveSubTab('history')}
              className={`px-3 py-1 rounded transition ${
                activeSubTab === 'history' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-white'
              }`}
            >
              Execution History ({history.length})
            </button>
          </div>

          <button
            onClick={handleAddActionNode}
            className="px-3 py-1.5 rounded bg-slate-900 border border-slate-700 text-xs font-mono font-bold text-slate-300 hover:border-cyan-400 flex items-center gap-1.5 transition"
          >
            <Plus className="w-3.5 h-3.5 text-cyan-400" />
            <span>Add Node</span>
          </button>

          <button
            onClick={handleSimulateExecution}
            disabled={isExecuting}
            className="px-3.5 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-mono font-bold text-xs flex items-center gap-1.5 transition disabled:opacity-50"
          >
            {isExecuting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            <span>Test Run</span>
          </button>
          
          <button
            onClick={handleSavePlaybook}
            disabled={saving}
            className="px-4 py-1.5 rounded bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-mono font-bold text-xs flex items-center gap-1.5 shadow-[0_0_12px_rgba(56,189,248,0.25)] transition disabled:opacity-50"
          >
            {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
            <span>Save Blueprint</span>
          </button>
        </div>
      </div>

      {activeSubTab === 'canvas' ? (
        /* Visual Workflow Layout */
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-4 gap-5 min-h-0">
          
          {/* Left Column: Playbook Blueprints */}
          <div className="cyber-card p-4 flex flex-col gap-3">
            <h3 className="text-xs uppercase text-slate-300 font-mono tracking-wider font-bold border-b border-slate-800 pb-2 flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Active Playbooks
            </h3>

            <div className="flex-1 overflow-y-auto space-y-2 pr-1 font-mono">
              {playbooks.map((pb, idx) => (
                <div
                  key={`${pb.id || 'pb'}-${idx}`}
                  onClick={() => loadPlaybookPreset(pb)}
                  className={`p-3 rounded-lg border transition cursor-pointer ${
                    selectedPlaybook?.id === pb.id
                      ? 'bg-cyan-950/40 border-cyan-500 text-cyan-300'
                      : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                  }`}
                >
                  <div className="flex justify-between items-start gap-1">
                    <h4 className="text-xs font-bold truncate">{pb.name}</h4>
                    <span className="text-[9px] px-1 py-0.5 rounded bg-slate-800 text-slate-400 shrink-0">
                      v{pb.version || '1.0'}
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                    {pb.description}
                  </p>
                </div>
              ))}
            </div>

            {/* Approval Gate Control Panel */}
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 font-mono text-[11px] space-y-2">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-bold flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5 text-amber-400" /> Approval Authorization
              </span>
              <p className="text-[10px] text-slate-300">
                Action requires Tier 3 SOC Commander confirmation before perimeter block.
              </p>
              <div className="flex gap-2 pt-1">
                <button
                  onClick={() => setApprovalGateStatus('approved')}
                  className={`flex-1 py-1 rounded text-[10px] font-bold border transition ${
                    approvalGateStatus === 'approved' ? 'bg-emerald-950 border-emerald-500 text-emerald-300' : 'bg-slate-800 border-slate-700 text-slate-300 hover:border-emerald-500'
                  }`}
                >
                  Authorize
                </button>
                <button
                  onClick={() => setApprovalGateStatus('rejected')}
                  className={`flex-1 py-1 rounded text-[10px] font-bold border transition ${
                    approvalGateStatus === 'rejected' ? 'bg-rose-950 border-rose-500 text-rose-300' : 'bg-slate-800 border-slate-700 text-slate-300 hover:border-rose-500'
                  }`}
                >
                  Reject
                </button>
              </div>
            </div>
          </div>

          {/* Right Column: React Flow Canvas */}
          <div className="lg:col-span-3 cyber-card overflow-hidden h-full relative">
            <div className="absolute top-4 left-6 z-10 font-mono">
              <span className="text-[10px] text-cyan-400 uppercase tracking-widest font-bold block">
                Visual Flow Blueprint
              </span>
              <h4 className="text-sm font-bold text-white">
                {selectedPlaybook?.name || 'Loading flow blueprint...'}
              </h4>
            </div>
            
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              fitView
              style={{ width: '100%', height: '100%', background: '#070913' }}
            >
              <Controls className="bg-slate-900 border-slate-800 text-white rounded [&>button]:border-slate-800 [&>button]:bg-slate-900 [&>svg]:fill-white" />
              <Background color="#1a233a" gap={18} />
              <MiniMap 
                nodeStrokeColor={() => '#00f0ff'}
                nodeColor={() => '#0d172e'}
                maskColor="rgba(7, 9, 19, 0.7)"
                style={{ background: '#0a0e1c', border: '1px solid #1e293b' }}
              />
            </ReactFlow>
          </div>

        </div>
      ) : (
        /* Execution History Subtab */
        <div className="cyber-card p-5 space-y-4">
          <div className="flex justify-between items-center border-b border-slate-800 pb-3">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Automated SOAR Execution Audit Log
            </h3>
            <span className="text-xs font-mono text-slate-400">
              All trigger events logged with full execution traces
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="text-[10px] uppercase text-slate-400 border-b border-slate-800 bg-slate-900/40">
                <tr>
                  <th className="p-3">Execution ID</th>
                  <th className="p-3">Playbook Name</th>
                  <th className="p-3">Trigger Event Source</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Duration</th>
                  <th className="p-3">Authorized By</th>
                  <th className="p-3">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {history.map((item, idx) => (
                  <tr key={`${item.id}-${idx}`} className="hover:bg-slate-850/40">
                    <td className="p-3 text-cyan-400 font-bold">{item.id}</td>
                    <td className="p-3 text-slate-200 font-semibold">{item.playbookName}</td>
                    <td className="p-3 text-slate-400 text-[11px]">{item.trigger}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        item.status === 'Completed' ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/40' :
                        item.status === 'Pending Approval' ? 'bg-amber-950/60 text-amber-300 border border-amber-500/40' :
                        'bg-cyan-950/60 text-cyan-300 border border-cyan-500/40'
                      }`}>
                        {item.status}
                      </span>
                    </td>
                    <td className="p-3 text-slate-400">{item.duration}</td>
                    <td className="p-3 text-purple-300">{item.analyst}</td>
                    <td className="p-3 text-slate-500">{item.timestamp}</td>
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
