'use client';

import React, { useState, useEffect, useRef } from 'react';
import { 
  ShieldAlert, 
  User, 
  Calendar, 
  CheckSquare, 
  FileText, 
  MessageSquare, 
  Clock, 
  Upload, 
  Play, 
  Cpu, 
  ArrowRight,
  Plus,
  Loader2,
  Lock,
  Tag
} from 'lucide-react';
import { api } from '@/utils/api';

interface Incident {
  id: number;
  title: string;
  description: string;
  severity: string;
  status: string;
  risk_score: number;
  mitre_tactics: string[];
  mitre_techniques: string[];
  assigned_to: string | null;
  creator: string;
  ai_summary: string | null;
  created_at: string;
  alerts: any[];
  timeline: any[];
  evidence: any[];
  tasks: any[];
  comments: any[];
}

export default function IncidentsQueue() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'playbooks' | 'timeline' | 'tasks' | 'evidence' | 'comments'>('overview');
  
  // Forms & Loading states
  const [loadingList, setLoadingList] = useState(true);
  const [loadingSummary, setLoadingSummary] = useState(false);
  const [commentText, setCommentText] = useState('');
  const [newTaskText, setNewTaskText] = useState('');
  const [playbooks, setPlaybooks] = useState<any[]>([]);
  const [playbookLogs, setPlaybookLogs] = useState<string>('');
  const [runningPlaybookId, setRunningPlaybookId] = useState<number | null>(null);
  
  // File Upload Form
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [cocNotes, setCocNotes] = useState('');
  const [uploadingEvidence, setUploadingEvidence] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetchIncidents();
    fetchPlaybooks();
  }, []);

  const fetchIncidents = async () => {
    try {
      setLoadingList(true);
      const data = await api.get('/incidents/');
      setIncidents(data);
      if (data.length > 0 && !selectedIncident) {
        setSelectedIncident(data[0]);
      } else if (selectedIncident) {
        // Refresh selected incident details
        const updated = data.find((i: Incident) => i.id === selectedIncident.id);
        if (updated) setSelectedIncident(updated);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingList(false);
    }
  };

  const fetchPlaybooks = async () => {
    try {
      const data = await api.get('/playbooks/');
      setPlaybooks(data);
    } catch (err) {
      console.error(err);
    }
  };

  const handleSelectIncident = (incident: Incident) => {
    setSelectedIncident(incident);
    setPlaybookLogs('');
    setRunningPlaybookId(null);
  };

  const handleStatusChange = async (newStatus: string) => {
    if (!selectedIncident) return;
    try {
      const updated = await api.put(`/incidents/${selectedIncident.id}`, { status: newStatus });
      fetchIncidents();
    } catch (err) {
      console.error(err);
    }
  };

  const handleAssigneeChange = async (assignee: string) => {
    if (!selectedIncident) return;
    try {
      const updated = await api.put(`/incidents/${selectedIncident.id}`, { assigned_to: assignee });
      fetchIncidents();
    } catch (err) {
      console.error(err);
    }
  };

  const handleSummarizeAI = async () => {
    if (!selectedIncident) return;
    try {
      setLoadingSummary(true);
      const res = await api.post(`/incidents/${selectedIncident.id}/summarize`);
      fetchIncidents();
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingSummary(false);
    }
  };

  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident || !commentText.trim()) return;
    try {
      await api.post(`/incidents/${selectedIncident.id}/comments`, { comment_text: commentText });
      setCommentText('');
      fetchIncidents();
    } catch (err) {
      console.error(err);
    }
  };

  const handleAddTask = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident || !newTaskText.trim()) return;
    try {
      await api.post(`/incidents/${selectedIncident.id}/tasks`, { description: newTaskText });
      setNewTaskText('');
      fetchIncidents();
    } catch (err) {
      console.error(err);
    }
  };

  const handleToggleTask = async (taskId: number) => {
    if (!selectedIncident) return;
    try {
      await api.put(`/incidents/${selectedIncident.id}/tasks/${taskId}`, {});
      fetchIncidents();
    } catch (err) {
      console.error(err);
    }
  };

  const handleRunPlaybook = async (pbId: number) => {
    if (!selectedIncident) return;
    setRunningPlaybookId(pbId);
    setPlaybookLogs(`[${new Date().toISOString()}] INITIALIZING PLAYBOOK RUN EXECUTION...\n`);
    try {
      const run = await api.post(`/playbooks/run?playbook_id=${pbId}&incident_id=${selectedIncident.id}`);
      setPlaybookLogs(run.log);
      fetchIncidents();
    } catch (err: any) {
      setPlaybookLogs(prev => prev + `[ERROR] Playbook run failed: ${err.message}\n`);
    } finally {
      setRunningPlaybookId(null);
    }
  };

  const handleEvidenceUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident || !uploadFile) return;

    setUploadingEvidence(true);
    const formData = new FormData();
    formData.append('file', uploadFile);
    if (cocNotes) {
      formData.append('chain_of_custody_notes', cocNotes);
    }

    try {
      await api.postFormData(`/incidents/${selectedIncident.id}/evidence`, formData);
      setUploadFile(null);
      setCocNotes('');
      if (fileInputRef.current) fileInputRef.current.value = '';
      fetchIncidents();
    } catch (err) {
      console.error(err);
    } finally {
      setUploadingEvidence(false);
    }
  };

  // Severity display badges
  const severityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical': return 'bg-red-950/40 border border-red-500/50 text-neon-red';
      case 'high': return 'bg-orange-950/40 border border-orange-500/50 text-orange-400';
      case 'medium': return 'bg-yellow-950/40 border border-yellow-500/50 text-neon-yellow';
      default: return 'bg-cyan-950/40 border border-cyan-500/50 text-neon-cyan';
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[calc(100vh-140px)]">
      
      {/* Column 1: Incident List Queue */}
      <div className="glass-panel rounded-xl border-slate-800 flex flex-col h-full overflow-hidden">
        <div className="p-4 border-b border-slate-800 bg-[#090b1c]/80 flex justify-between items-center">
          <div>
            <h3 className="text-sm font-bold tracking-wide uppercase text-slate-200 font-mono">
              Incident Response Queue
            </h3>
            <span className="text-[9px] font-mono text-slate-500">
              {incidents.length} TICKETS REGISTERED
            </span>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60">
          {loadingList ? (
            <div className="h-full flex items-center justify-center text-slate-500 font-mono text-xs">
              <Loader2 className="w-5 h-5 animate-spin mr-2" /> LOADING TICKETS...
            </div>
          ) : incidents.map((inc) => (
            <div
              key={inc.id}
              onClick={() => handleSelectIncident(inc)}
              className={`p-4 transition-all duration-300 cursor-pointer flex flex-col gap-2 ${
                selectedIncident?.id === inc.id
                  ? 'bg-neon-cyan/5 border-l-2 border-neon-cyan'
                  : 'hover:bg-slate-800/20'
              }`}
            >
              <div className="flex justify-between items-start">
                <span className="text-xs font-bold text-slate-200 truncate max-w-[180px]">{inc.title}</span>
                <span className={`text-[8px] font-mono px-2 py-0.5 rounded font-semibold uppercase ${severityBadge(inc.severity)}`}>
                  {inc.severity}
                </span>
              </div>
              <div className="flex justify-between items-center text-[10px] font-mono text-slate-400">
                <span className={inc.status === 'Closed' ? 'text-slate-600' : 'text-neon-cyan'}>
                  {inc.status}
                </span>
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {new Date(inc.created_at).toLocaleDateString()}
                </span>
              </div>
            </div>
          ))}
          {incidents.length === 0 && !loadingList && (
            <div className="p-6 text-center text-xs text-slate-600 font-mono">
              NO INCIDENTS REGISTERED IN DATABASE.
            </div>
          )}
        </div>
      </div>

      {/* Column 2 & 3: Detailed Workspace */}
      <div className="lg:col-span-2 flex flex-col h-full overflow-hidden">
        {selectedIncident ? (
          <div className="glass-panel rounded-xl border-slate-800 flex flex-col h-full overflow-hidden">
            
            {/* Header Detail Info */}
            <div className="p-6 border-b border-slate-800 bg-[#090b1c]/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest font-bold">
                    Incident #{selectedIncident.id}
                  </span>
                  <span className={`text-[8px] font-mono px-2 py-0.5 rounded font-semibold uppercase ${severityBadge(selectedIncident.severity)}`}>
                    {selectedIncident.severity}
                  </span>
                </div>
                <h2 className="text-lg font-bold text-slate-100">{selectedIncident.title}</h2>
                <p className="text-[10px] text-slate-400 font-mono">
                  CREATED BY: <span className="text-slate-300 font-semibold">{selectedIncident.creator}</span> | {new Date(selectedIncident.created_at).toLocaleString()}
                </p>
              </div>

              {/* Action Dropdowns */}
              <div className="flex flex-wrap gap-2">
                
                {/* Status Dropdown */}
                <div className="flex flex-col gap-0.5">
                  <span className="text-[8px] font-mono text-slate-500 uppercase">Status</span>
                  <select
                    value={selectedIncident.status}
                    onChange={(e) => handleStatusChange(e.target.value)}
                    className="bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-300 font-mono focus:outline-none focus:border-neon-cyan cursor-pointer"
                  >
                    <option value="Open">Open</option>
                    <option value="Investigating">Investigating</option>
                    <option value="Contained">Contained</option>
                    <option value="Resolved">Resolved</option>
                    <option value="Closed">Closed</option>
                  </select>
                </div>

                {/* Assignee Dropdown */}
                <div className="flex flex-col gap-0.5">
                  <span className="text-[8px] font-mono text-slate-500 uppercase">Assigned Analyst</span>
                  <select
                    value={selectedIncident.assigned_to || ''}
                    onChange={(e) => handleAssigneeChange(e.target.value)}
                    className="bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-300 font-mono focus:outline-none focus:border-neon-cyan cursor-pointer"
                  >
                    <option value="">Unassigned</option>
                    <option value="admin">Super Admin</option>
                    <option value="manager">SOC Manager</option>
                    <option value="analyst">Tier 1 Analyst</option>
                    <option value="hunter">Threat Hunter</option>
                  </select>
                </div>

              </div>
            </div>

            {/* Navigation Tabs */}
            <div className="flex border-b border-slate-800 bg-[#070919]/60 px-6 overflow-x-auto">
              {[
                { id: 'overview', name: 'Overview', icon: FileText },
                { id: 'playbooks', name: 'SOAR Playbooks', icon: Play },
                { id: 'timeline', name: 'Timeline', icon: Clock },
                { id: 'tasks', name: 'Response Tasks', icon: CheckSquare },
                { id: 'evidence', name: 'Forensics Lockbox', icon: Lock },
                { id: 'comments', name: 'Analyst Chat', icon: MessageSquare },
              ].map((tab) => {
                const Icon = tab.icon;
                const isCurrent = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as any)}
                    className={`py-3 px-4 border-b-2 font-mono text-xs flex items-center gap-2 transition-all duration-300 cursor-pointer select-none ${
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

            {/* Tab Body Contents */}
            <div className="flex-1 overflow-y-auto p-6 bg-[#04050d]">
              
              {/* Tab 1: Overview & AI Summary */}
              {activeTab === 'overview' && (
                <div className="space-y-6">
                  {/* Raw Description */}
                  <div className="space-y-2">
                    <h4 className="text-xs uppercase text-slate-400 font-mono tracking-widest font-bold">
                      Telemetry Alert Description
                    </h4>
                    <p className="text-sm text-slate-300 leading-relaxed bg-slate-900/40 p-4 rounded-lg border border-slate-800/80">
                      {selectedIncident.description}
                    </p>
                  </div>

                  {/* MITRE Mapping */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 bg-slate-900/40 rounded-lg border border-slate-800/80 space-y-2">
                      <div className="flex items-center gap-2 text-neon-purple">
                        <Tag className="w-4 h-4" />
                        <h5 className="text-xs font-mono font-bold uppercase">MITRE Tactics</h5>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedIncident.mitre_tactics && selectedIncident.mitre_tactics.length > 0 ? (
                          selectedIncident.mitre_tactics.map((t, idx) => (
                            <span key={idx} className="text-[10px] font-mono px-2 py-0.5 bg-neon-purple/10 border border-neon-purple/30 text-neon-purple rounded">
                              {t}
                            </span>
                          ))
                        ) : (
                          <span className="text-[10px] text-slate-500 font-mono">None registered.</span>
                        )}
                      </div>
                    </div>

                    <div className="p-4 bg-slate-900/40 rounded-lg border border-slate-800/80 space-y-2">
                      <div className="flex items-center gap-2 text-neon-cyan">
                        <Tag className="w-4 h-4" />
                        <h5 className="text-xs font-mono font-bold uppercase">MITRE Techniques</h5>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedIncident.mitre_techniques && selectedIncident.mitre_techniques.length > 0 ? (
                          selectedIncident.mitre_techniques.map((tech, idx) => (
                            <span key={idx} className="text-[10px] font-mono px-2 py-0.5 bg-neon-cyan/10 border border-neon-cyan/30 text-neon-cyan rounded">
                              {tech}
                            </span>
                          ))
                        ) : (
                          <span className="text-[10px] text-slate-500 font-mono">None registered.</span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* AI Summary Section */}
                  <div className="space-y-4 pt-4 border-t border-slate-900">
                    <div className="flex justify-between items-center">
                      <div className="flex items-center gap-2">
                        <Cpu className="w-4 h-4 text-neon-green" />
                        <h4 className="text-xs uppercase text-slate-400 font-mono tracking-widest font-bold">
                          AI Security Analyst Synthesis
                        </h4>
                      </div>
                      <button
                        onClick={handleSummarizeAI}
                        disabled={loadingSummary}
                        className="px-3 py-1.5 rounded bg-neon-green hover:bg-neon-green/80 text-black font-extrabold text-[11px] uppercase tracking-wider flex items-center gap-1.5 transition-all duration-300 disabled:opacity-50 cursor-pointer shadow-[0_0_10px_rgba(0,255,102,0.15)]"
                      >
                        {loadingSummary ? (
                          <>
                            <Loader2 className="w-3 h-3 animate-spin" />
                            <span>Synthesizing...</span>
                          </>
                        ) : (
                          <>
                            <Cpu className="w-3.5 h-3.5" />
                            <span>Ask AI Copilot</span>
                          </>
                        )}
                      </button>
                    </div>

                    {selectedIncident.ai_summary ? (
                      <div className="p-5 rounded-lg border border-neon-green/30 bg-neon-green/5 text-slate-200 text-sm leading-relaxed whitespace-pre-wrap font-mono prose prose-invert prose-xs max-w-none">
                        {selectedIncident.ai_summary}
                      </div>
                    ) : (
                      <div className="p-6 border border-slate-800 rounded-lg text-center text-xs text-slate-500 font-mono">
                        NO DRAFTED AI SUMMARY AVAILABLE. CLICK 'ASK AI COPILOT' TO SYNTHESIZE TELEMETRY DATA.
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Tab 2: SOAR Response Playbooks */}
              {activeTab === 'playbooks' && (
                <div className="space-y-6">
                  <div className="space-y-1">
                    <h4 className="text-xs uppercase text-slate-400 font-mono tracking-widest font-bold">
                      Available Automation Playbooks
                    </h4>
                    <p className="text-[10px] text-slate-500 font-mono">
                      TRIGGER CONTROLS AND RESPONSE SEQUENCE SCHEMAS FOR CONSOLIDATED CONTAINMENT.
                    </p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {playbooks.map((pb) => (
                      <div key={pb.id} className="p-4 bg-slate-900/40 rounded-lg border border-slate-800/80 flex flex-col justify-between gap-4">
                        <div className="space-y-1">
                          <h5 className="text-xs font-bold text-slate-200 font-mono">{pb.name}</h5>
                          <p className="text-[11px] text-slate-400">{pb.description}</p>
                          <div className="pt-2 text-[9px] font-mono text-slate-500">
                            TRIGGERS ON: <span className="text-neon-cyan">{JSON.stringify(pb.trigger_condition)}</span>
                          </div>
                        </div>
                        <button
                          onClick={() => handleRunPlaybook(pb.id)}
                          disabled={runningPlaybookId !== null}
                          className="w-full py-2 rounded bg-neon-cyan hover:bg-neon-cyan/80 text-black font-extrabold text-[11px] uppercase tracking-wider flex items-center justify-center gap-1.5 transition-all duration-300 disabled:opacity-50 cursor-pointer"
                        >
                          <Play className="w-3.5 h-3.5 fill-black" />
                          <span>Execute Automation Flow</span>
                        </button>
                      </div>
                    ))}
                  </div>

                  {/* Playbook Log Output Console */}
                  {playbookLogs && (
                    <div className="space-y-2 pt-4 border-t border-slate-900">
                      <span className="text-[10px] font-mono uppercase text-slate-400 font-bold block">
                        Playbook Action Run Console
                      </span>
                      <pre className="p-4 bg-black/90 rounded border border-slate-800 text-[10px] font-mono text-neon-green overflow-auto max-h-56 leading-relaxed">
                        {playbookLogs}
                      </pre>
                    </div>
                  )}
                </div>
              )}

              {/* Tab 3: Timeline */}
              {activeTab === 'timeline' && (
                <div className="space-y-6">
                  <div className="relative border-l border-slate-850 pl-6 ml-3 space-y-6">
                    {selectedIncident.timeline && selectedIncident.timeline.map((event) => (
                      <div key={event.id} className="relative">
                        {/* Event Dot */}
                        <span className="absolute -left-[30px] top-1.5 w-2 h-2 rounded-full bg-neon-cyan shadow-[0_0_8px_rgba(0,240,255,0.8)]" />
                        
                        <div className="space-y-1">
                          <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500">
                            <span className="text-slate-400 font-semibold">{event.actor}</span>
                            <span>•</span>
                            <span>{new Date(event.timestamp).toLocaleString()}</span>
                          </div>
                          <p className="text-xs text-slate-300 font-mono bg-slate-900/20 p-2.5 rounded border border-slate-900/60 max-w-xl">
                            {event.message}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Tab 4: Response Tasks Checklist */}
              {activeTab === 'tasks' && (
                <div className="space-y-6">
                  
                  {/* Task Addition Form */}
                  <form onSubmit={handleAddTask} className="flex gap-2">
                    <input
                      type="text"
                      value={newTaskText}
                      onChange={(e) => setNewTaskText(e.target.value)}
                      required
                      placeholder="e.g. Conduct registry persistence checks at host..."
                      className="flex-1 bg-slate-900/80 border border-slate-800 rounded px-3.5 py-2 text-xs text-slate-200 focus:outline-none focus:border-neon-cyan font-mono"
                    />
                    <button
                      type="submit"
                      className="px-4 rounded bg-neon-cyan text-black hover:bg-neon-cyan/80 text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all duration-300 cursor-pointer"
                    >
                      <Plus className="w-3.5 h-3.5" /> Add Task
                    </button>
                  </form>

                  {/* Tasks List */}
                  <div className="space-y-2">
                    {selectedIncident.tasks && selectedIncident.tasks.map((task) => (
                      <div 
                        key={task.id}
                        onClick={() => handleToggleTask(task.id)}
                        className={`p-3.5 rounded-lg border flex items-center gap-3 transition-all duration-300 cursor-pointer select-none ${
                          task.status === 'Completed'
                            ? 'bg-slate-900/20 border-slate-900 text-slate-500'
                            : 'bg-slate-900/60 border-slate-800 text-slate-200 hover:border-slate-700'
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={task.status === 'Completed'}
                          readOnly
                          className="w-4 h-4 border-slate-800 rounded accent-neon-cyan cursor-pointer"
                        />
                        <span className={`text-xs font-mono ${task.status === 'Completed' ? 'line-through' : ''}`}>
                          {task.description}
                        </span>
                      </div>
                    ))}
                    {selectedIncident.tasks?.length === 0 && (
                      <div className="p-6 text-center text-xs text-slate-500 font-mono border border-slate-800 rounded-lg">
                        NO ASSIGNED TASKS IN REMEDIATION PLAN.
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Tab 5: Evidence Locker */}
              {activeTab === 'evidence' && (
                <div className="space-y-6">
                  
                  {/* Upload Evidence Form */}
                  <div className="p-5 bg-slate-900/40 border border-slate-800 rounded-lg space-y-4">
                    <h4 className="text-xs uppercase text-slate-400 font-mono tracking-widest font-bold flex items-center gap-2">
                      <Lock className="w-3.5 h-3.5 text-neon-yellow" /> Forensics Integrity Upload
                    </h4>
                    
                    <form onSubmit={handleEvidenceUpload} className="space-y-3">
                      <div className="flex flex-col gap-1">
                        <label className="text-[10px] font-mono text-slate-500 uppercase">Select Evidence File</label>
                        <input
                          type="file"
                          ref={fileInputRef}
                          onChange={(e) => setUploadFile(e.target.files ? e.target.files[0] : null)}
                          required
                          className="bg-slate-950 border border-slate-850 rounded p-1.5 text-xs font-mono focus:outline-none cursor-pointer"
                        />
                      </div>
                      
                      <div className="flex flex-col gap-1">
                        <label className="text-[10px] font-mono text-slate-500 uppercase">Chain of Custody Notes</label>
                        <textarea
                          value={cocNotes}
                          onChange={(e) => setCocNotes(e.target.value)}
                          placeholder="Log notes detailing acquisition method, parameters, and acquisition officer..."
                          className="bg-slate-950 border border-slate-850 rounded p-2.5 text-xs font-mono focus:outline-none h-16"
                        />
                      </div>

                      <button
                        type="submit"
                        disabled={uploadingEvidence || !uploadFile}
                        className="py-2 px-4 rounded bg-neon-yellow text-black font-extrabold text-[11px] uppercase tracking-wider flex items-center gap-1.5 transition-all duration-300 disabled:opacity-50 cursor-pointer shadow-[0_0_10px_rgba(255,204,0,0.15)]"
                      >
                        {uploadingEvidence ? (
                          <>
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            <span>Locking file...</span>
                          </>
                        ) : (
                          <>
                            <Upload className="w-3.5 h-3.5" />
                            <span>Seal Evidence Lockbox</span>
                          </>
                        )}
                      </button>
                    </form>
                  </div>

                  {/* Evidence Files List */}
                  <div className="space-y-3">
                    <h5 className="text-xs uppercase text-slate-400 font-mono tracking-widest font-bold">
                      Ingested Forensic Artifacts
                    </h5>
                    
                    {selectedIncident.evidence && selectedIncident.evidence.map((ev) => (
                      <div key={ev.id} className="p-4 bg-slate-900/60 border border-slate-850 rounded-lg flex flex-col gap-2 font-mono">
                        <div className="flex justify-between items-start">
                          <span className="text-xs font-semibold text-slate-200">{ev.file_name}</span>
                          <span className="text-[9px] text-slate-500">{(ev.file_size / 1024).toFixed(1)} KB</span>
                        </div>
                        <div className="text-[10px] bg-slate-950 p-2 rounded border border-slate-800/60 space-y-1 text-slate-400">
                          <div>
                            <span className="text-slate-500">SHA-256 INTEGRITY HASH:</span>
                            <span className="text-neon-yellow block truncate">{ev.file_hash}</span>
                          </div>
                          <div>
                            <span className="text-slate-500">ACQUIRED BY:</span>
                            <span className="text-slate-300"> {ev.uploaded_by}</span>
                          </div>
                        </div>
                        <div className="text-[10px] text-slate-500">
                          <span className="font-bold text-slate-400">Chain of Custody Logs:</span>
                          <pre className="mt-1 whitespace-pre-wrap leading-relaxed text-[9px] bg-black/40 p-2 rounded max-h-32 overflow-auto">
                            {ev.chain_of_custody}
                          </pre>
                        </div>
                      </div>
                    ))}
                    {selectedIncident.evidence?.length === 0 && (
                      <div className="p-6 text-center text-xs text-slate-500 font-mono border border-slate-800 rounded-lg">
                        LOCKBOX EMPTY. NO FORENSIC ARTIFACTS LINKED.
                      </div>
                    )}
                  </div>

                </div>
              )}

              {/* Tab 6: Comments/Chat */}
              {activeTab === 'comments' && (
                <div className="space-y-6 flex flex-col h-full">
                  
                  {/* Add Comment Form */}
                  <form onSubmit={handleAddComment} className="flex gap-2">
                    <input
                      type="text"
                      value={commentText}
                      onChange={(e) => setCommentText(e.target.value)}
                      required
                      placeholder="Type investigation update notes..."
                      className="flex-1 bg-slate-900/80 border border-slate-800 rounded px-3.5 py-2 text-xs text-slate-200 focus:outline-none focus:border-neon-cyan font-mono"
                    />
                    <button
                      type="submit"
                      className="px-4 rounded bg-neon-cyan text-black hover:bg-neon-cyan/80 text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all duration-300 cursor-pointer"
                    >
                      <ArrowRight className="w-3.5 h-3.5" /> Send
                    </button>
                  </form>

                  {/* Comment Feed */}
                  <div className="space-y-4 max-h-[300px] overflow-y-auto pr-1">
                    {selectedIncident.comments && selectedIncident.comments.map((com) => (
                      <div key={com.id} className="p-3 bg-slate-900/40 rounded-lg border border-slate-950 flex flex-col gap-1.5 font-mono">
                        <div className="flex justify-between items-center text-[10px]">
                          <span className="font-bold text-neon-cyan">{com.author}</span>
                          <span className="text-slate-500">{new Date(com.timestamp).toLocaleString()}</span>
                        </div>
                        <p className="text-xs text-slate-300 leading-relaxed">
                          {com.comment_text}
                        </p>
                      </div>
                    ))}
                    {selectedIncident.comments?.length === 0 && (
                      <div className="p-6 text-center text-xs text-slate-500 font-mono border border-slate-800 rounded-lg">
                        NO LOGGED COMMENTS ON THIS INVESTIGATION TICKET.
                      </div>
                    )}
                  </div>
                </div>
              )}

            </div>

          </div>
        ) : (
          <div className="glass-panel rounded-xl border-slate-800 h-full flex items-center justify-center text-xs text-slate-500 font-mono">
            SELECT AN INCIDENT FROM THE LEFT QUEUE TO BEGIN INVESTIGATION.
          </div>
        )}
      </div>

    </div>
  );
}
