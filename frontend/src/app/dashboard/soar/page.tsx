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
import { GitBranch, Play, Save, Plus, Loader2, RefreshCw } from 'lucide-react';
import { api } from '@/utils/api';

// Pre-seeded playbook details
const PRESETS = {
  ransomware: {
    name: "Automated Ransomware Containment",
    nodes: [
      { id: '1', type: 'input', data: { label: '🔴 Trigger: Ransomware Alert' }, position: { x: 250, y: 20 }, style: { background: '#11050e', color: '#ff0055', border: '1px solid #ff0055', fontFamily: 'monospace', fontSize: 11, borderRadius: 5 } },
      { id: '2', data: { label: '🔍 Enrich Host IOCs via TI' }, position: { x: 250, y: 120 }, style: { background: '#0a0d20', color: '#00f0ff', border: '1px solid #00f0ff', fontFamily: 'monospace', fontSize: 11, borderRadius: 5 } },
      { id: '3', data: { label: '🚫 Isolate Endpoint (EDR)' }, position: { x: 250, y: 220 }, style: { background: '#0d142d', color: '#ffcc00', border: '1px solid #ffcc00', fontFamily: 'monospace', fontSize: 11, borderRadius: 5 } },
      { id: '4', data: { label: '🔒 Disable compromised User' }, position: { x: 250, y: 320 }, style: { background: '#0d142d', color: '#bd00ff', border: '1px solid #bd00ff', fontFamily: 'monospace', fontSize: 11, borderRadius: 5 } },
      { id: '5', type: 'output', data: { label: '💬 Post Slack Incident Alert' }, position: { x: 250, y: 420 }, style: { background: '#05140e', color: '#00ff66', border: '1px solid #00ff66', fontFamily: 'monospace', fontSize: 11, borderRadius: 5 } }
    ],
    edges: [
      { id: 'e1-2', source: '1', target: '2', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#00f0ff' } },
      { id: 'e2-3', source: '2', target: '3', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#ffcc00' } },
      { id: 'e3-4', source: '3', target: '4', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#bd00ff' } },
      { id: 'e4-5', source: '4', target: '5', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#00ff66' } }
    ]
  },
  bruteforce: {
    name: "Malicious IP Connection Blocking",
    nodes: [
      { id: '1', type: 'input', data: { label: '🔴 Trigger: Malicious IP Alert' }, position: { x: 250, y: 20 }, style: { background: '#11050e', color: '#ff0055', border: '1px solid #ff0055', fontFamily: 'monospace', fontSize: 11, borderRadius: 5 } },
      { id: '2', data: { label: '🚦 Check IP Reputation' }, position: { x: 250, y: 120 }, style: { background: '#0a0d20', color: '#00f0ff', border: '1px solid #00f0ff', fontFamily: 'monospace', fontSize: 11, borderRadius: 5 } },
      { id: '3', data: { label: '👤 SOC Manager Approval Gate' }, position: { x: 250, y: 220 }, style: { background: '#150f05', color: '#ff7700', border: '1px solid #ff7700', fontFamily: 'monospace', fontSize: 11, borderRadius: 5 } },
      { id: '4', data: { label: '🛑 Block IP at Perimeter FW' }, position: { x: 100, y: 320 }, style: { background: '#0d142d', color: '#ff0055', border: '1px solid #ff0055', fontFamily: 'monospace', fontSize: 11, borderRadius: 5 } },
      { id: '5', type: 'output', data: { label: '💬 Post Teams Notification' }, position: { x: 400, y: 320 }, style: { background: '#05140e', color: '#00ff66', border: '1px solid #00ff66', fontFamily: 'monospace', fontSize: 11, borderRadius: 5 } }
    ],
    edges: [
      { id: 'e1-2', source: '1', target: '2', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#00f0ff' } },
      { id: 'e2-3', source: '2', target: '3', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#ff7700' } },
      { id: 'e3-4', source: '3', target: '4', label: 'Approved', markerEnd: { type: MarkerType.ArrowClosed, color: '#ff0055' } },
      { id: 'e3-5', source: '3', target: '5', label: 'Rejected', markerEnd: { type: MarkerType.ArrowClosed, color: '#00ff66' } }
    ]
  }
};

export default function SOARCanvas() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  
  const [playbooks, setPlaybooks] = useState<any[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState<any>(null);
  const [saving, setSaving] = useState(false);
  const [mounted, setMounted] = useState(false);

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
    }
  };

  const loadPlaybookPreset = (pb: any) => {
    setSelectedPlaybook(pb);
    // Parse nodes and edges from db or fallback to preset
    if (pb.nodes && pb.nodes.length > 0) {
      setNodes(pb.nodes);
      setEdges(pb.edges);
    } else {
      // Fallback
      const preset = pb.name.includes("Ransomware") ? PRESETS.ransomware : PRESETS.bruteforce;
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
      alert('Playbook layout saved successfully!');
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
      data: { label: `🛠️ New Action Step ${id}` },
      position: { x: 100 + Math.random() * 200, y: 150 + Math.random() * 200 },
      style: { background: '#0a0d20', color: '#00f0ff', border: '1px solid #00f0ff', fontFamily: 'monospace', fontSize: 11, borderRadius: 5 }
    };
    setNodes(prev => [...prev, newNode]);
  };

  if (!mounted) return null;

  return (
    <div className="space-y-6 flex flex-col h-[calc(100vh-140px)]">
      
      {/* Top Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold tracking-wide text-slate-100 uppercase">
            SOAR Automation Workspace
          </h2>
          <p className="text-xs text-slate-500 font-mono mt-0.5">
            PLAYBOOK ENGINEER // VISUAL WORKFLOW NODE CANVAS
          </p>
        </div>

        <div className="flex gap-2">
          <button
            onClick={handleAddActionNode}
            className="px-3.5 py-2 rounded bg-slate-900 border border-slate-800 text-[11px] font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5 transition-all duration-300 hover:border-slate-700 cursor-pointer"
          >
            <Plus className="w-4 h-4 text-neon-cyan" /> Add Action Node
          </button>
          
          <button
            onClick={handleSavePlaybook}
            disabled={saving}
            className="px-4 py-2 rounded bg-neon-cyan text-black font-extrabold text-[11px] uppercase tracking-wider flex items-center gap-1.5 transition-all duration-300 disabled:opacity-50 cursor-pointer shadow-[0_0_15px_rgba(0,240,255,0.15)]"
          >
            {saving ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            <span>Save Playbook Blueprint</span>
          </button>
        </div>
      </div>

      {/* Main Builder layout */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-4 gap-6 min-h-0">
        
        {/* Left Side: Playbooks list */}
        <div className="glass-panel rounded-xl border-slate-800 p-5 flex flex-col gap-4">
          <h3 className="text-xs uppercase text-slate-400 font-mono tracking-widest font-bold border-b border-slate-850 pb-2 flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-neon-purple" /> Active Automation Flowsheets
          </h3>

          <div className="flex-1 overflow-y-auto space-y-2.5 pr-1">
            {playbooks.map((pb) => (
              <div
                key={pb.id}
                onClick={() => loadPlaybookPreset(pb)}
                className={`p-3.5 rounded-lg border font-mono transition-all duration-300 cursor-pointer ${
                  selectedPlaybook?.id === pb.id
                    ? 'bg-neon-cyan/5 border-neon-cyan text-neon-cyan'
                    : 'bg-slate-900/40 border-slate-900 text-slate-400 hover:border-slate-800'
                }`}
              >
                <h4 className="text-xs font-bold">{pb.name}</h4>
                <p className="text-[10px] text-slate-500 mt-1 leading-relaxed truncate">{pb.description}</p>
                <div className="text-[8px] text-slate-500 mt-2">VERSION {pb.version}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Side: Visual Flow Canvas */}
        <div className="lg:col-span-3 glass-panel rounded-xl border-slate-800 overflow-hidden h-full relative">
          <div className="absolute top-4 left-6 z-10">
            <span className="text-[9px] text-neon-cyan font-mono uppercase tracking-widest font-bold">
              Canvas Sandbox
            </span>
            <h4 className="text-xs font-bold text-slate-300 font-mono">
              {selectedPlaybook?.name || 'Loading flow...'}
            </h4>
          </div>
          
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            fitView
            style={{ width: '100%', height: '100%', background: '#05060f' }}
          >
            <Controls className="bg-slate-900 border-slate-800 text-white rounded [&>button]:border-slate-800 [&>button]:bg-slate-900 [&>svg]:fill-white" />
            <Background color="#1e293b" gap={16} />
            <MiniMap 
              nodeStrokeColor={(n) => '#00f0ff'}
              nodeColor={(n) => '#0d172e'}
              maskColor="rgba(5, 6, 15, 0.6)"
              style={{ background: '#05060f', border: '1px solid #1e293b' }}
            />
          </ReactFlow>
        </div>

      </div>

    </div>
  );
}
