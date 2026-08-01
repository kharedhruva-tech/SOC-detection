'use client';

import React, { useState, useEffect } from 'react';
import { Database, Search, Cpu, Copy, Check, FileCode, Play, Plus, Activity, Loader2 } from 'lucide-react';
import { api } from '@/utils/api';

export default function SIEMLogs() {
  const [logs, setLogs] = useState<any[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState<'logs' | 'correlation' | 'ai-generator'>('logs');
  
  // Rule Generator Form States
  const [ruleType, setRuleType] = useState<'sigma' | 'yara'>('sigma');
  const [title, setTitle] = useState('Detect Suspicious Curl Download');
  const [description, setDescription] = useState('Detects execution of curl pulling payloads from external domains.');
  const [targetImage, setTargetImage] = useState('curl.exe');
  const [targetCmd, setTargetCmd] = useState('-O http://');
  const [generatedRule, setGeneratedRule] = useState('');
  const [loadingRule, setLoadingRule] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    fetchLogs();
  }, []);

  const fetchLogs = async () => {
    try {
      const data = await api.get('/alerts/');
      setLogs(data);
    } catch (err) {
      console.error(err);
    }
  };

  const handleGenerateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoadingRule(true);
    setGeneratedRule('');
    try {
      // Direct templates matching the prompt
      if (ruleType === 'sigma') {
        const rule = (
          `title: ${title}\n` +
          `id: ${Math.floor(Math.random() * 10000000).toString(16)}-abcd-ef12-3456-7890abcdef12\n` +
          `status: experimental\n` +
          `description: ${description}\n` +
          `author: Aegis AI Analyst\n` +
          `date: 2026/07/30\n` +
          `references:\n` +
          `    - Internal SOC Detection Library\n` +
          `tags:\n` +
          `    - attack.execution\n` +
          `    - attack.t1059\n` +
          `logsource:\n` +
          `    product: windows\n` +
          `    service: sysmon\n` +
          `detection:\n` +
          `    selection:\n` +
          `        Image|endswith: '\\${targetImage}'\n` +
          (targetCmd ? `        CommandLine|contains: '${targetCmd}'\n` : '') +
          `    condition: selection\n` +
          `falsepositives:\n` +
          `    - Legitimate administrative downloads\n` +
          `level: medium`
        );
        setGeneratedRule(rule);
      } else {
        const indicators = targetCmd ? [targetCmd, targetImage] : [targetImage];
        const cleanName = title.replace(/\s+/g, '_').replace(/[^a-zA-Z0-5_]/g, '');
        const rule = (
          `rule AI_Detect_${cleanName} {\n` +
          `    meta:\n` +
          `        description = "${description}"\n` +
          `        author = "Aegis AI Analyst"\n` +
          `        date = "2026-07-30"\n` +
          `        severity = "medium"\n\n` +
          `    strings:\n` +
          indicators.map((ind, i) => `        $string_${i} = "${ind}" ascii wide nocase`).join('\n') + '\n' +
          `\n    condition:\n` +
          `        all of them\n` +
          `}`
        );
        setGeneratedRule(rule);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingRule(false);
    }
  };

  const handleCopyRule = () => {
    if (!generatedRule) return;
    navigator.clipboard.writeText(generatedRule);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Filter logs based on search query
  const filteredLogs = logs.filter(log => {
    const q = searchQuery.toLowerCase();
    return (
      log.title.toLowerCase().includes(q) ||
      log.category.toLowerCase().includes(q) ||
      log.severity.toLowerCase().includes(q) ||
      (log.description && log.description.toLowerCase().includes(q))
    );
  });

  const correlationRules = [
    { id: 'RULE_001', name: 'Brute Force Attack Detected', severity: 'High', category: 'Credential Abuse', enabled: true },
    { id: 'RULE_002', name: 'Ransomware Behavior - Rapid File Modification', severity: 'Critical', category: 'Ransomware', enabled: true },
    { id: 'RULE_003', name: 'Lateral Movement - WMI Command Execution', severity: 'High', category: 'Lateral Movement', enabled: true },
    { id: 'RULE_004', name: 'Data Exfiltration to Suspicious Domain', severity: 'High', category: 'Data Exfiltration', enabled: true },
    { id: 'RULE_005', name: 'Living off the Land - Suspicious Certutil Download', severity: 'Medium', category: 'Defense Evasion', enabled: true },
    { id: 'RULE_006', name: 'Impossible Travel Connection', severity: 'Medium', category: 'UEBA Anomaly', enabled: true }
  ];

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold tracking-wide text-slate-100 uppercase">
          SIEM Engine & Detection Rules
        </h2>
        <p className="text-xs text-slate-500 font-mono mt-0.5">
          LOG STORAGE // PARSING PIPELINES // SIGMA & YARA DEPLOYMENTS
        </p>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 bg-[#070919]/60 px-6 rounded-t-xl">
        {[
          { id: 'logs', name: 'Normalized Log Ingests', icon: Database },
          { id: 'correlation', name: 'Correlation Rules', icon: Activity },
          { id: 'ai-generator', name: 'AI Rule Generator', icon: Cpu }
        ].map((tab) => {
          const Icon = tab.icon;
          const isCurrent = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
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

      {/* Tab 1: Log Search Viewer */}
      {activeTab === 'logs' && (
        <div className="space-y-4">
          {/* Search bar */}
          <div className="relative">
            <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-500">
              <Search className="w-4 h-4" />
            </span>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search normalized events by category, title, severity, or description parameters..."
              className="w-full bg-[#0a0d20]/70 border border-slate-800 rounded-lg py-2.5 pl-10 pr-4 text-xs text-slate-300 focus:outline-none focus:border-neon-cyan font-mono"
            />
          </div>

          {/* Log Table */}
          <div className="glass-panel rounded-xl border-slate-800 overflow-hidden">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#090b1c]/80 text-slate-400 uppercase tracking-widest text-[9px] border-b border-slate-850">
                <tr>
                  <th className="p-4">Timestamp</th>
                  <th className="p-4">Alert Event</th>
                  <th className="p-4">Category</th>
                  <th className="p-4">Severity</th>
                  <th className="p-4">Integrity Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-900/20 text-slate-300">
                    <td className="p-4 whitespace-nowrap text-slate-500">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="p-4 font-semibold text-slate-200">{log.title}</td>
                    <td className="p-4 text-neon-cyan">{log.category}</td>
                    <td className="p-4">
                      <span className={`px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${
                        log.severity === 'Critical' ? 'text-neon-red border-neon-red/20 bg-neon-red/5' :
                        log.severity === 'High' ? 'text-orange-400 border-orange-400/20 bg-orange-400/5' :
                        log.severity === 'Medium' ? 'text-neon-yellow border-neon-yellow/20 bg-neon-yellow/5' :
                        'text-neon-cyan border-neon-cyan/20 bg-neon-cyan/5'
                      }`}>
                        {log.severity}
                      </span>
                    </td>
                    <td className="p-4 text-neon-green">NORMALIZED</td>
                  </tr>
                ))}
                {filteredLogs.length === 0 && (
                  <tr>
                    <td colSpan={5} className="p-6 text-center text-slate-600">
                      NO LOG ENTRYS DETECTED MATCHING QUERY.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 2: Correlation Engine Rules */}
      {activeTab === 'correlation' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <span className="text-xs uppercase text-slate-500 font-mono">
              Ingestion Correlation Rules Registry
            </span>
            <button className="px-3 py-1.5 rounded bg-neon-cyan text-black hover:bg-neon-cyan/80 text-[11px] font-bold uppercase tracking-wider flex items-center gap-1 cursor-pointer">
              <Plus className="w-3.5 h-3.5" /> Deploy Custom Rule
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {correlationRules.map((rule) => (
              <div key={rule.id} className="p-4 bg-slate-900/40 rounded-lg border border-slate-800/80 flex items-center justify-between">
                <div className="space-y-1 font-mono">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-slate-500">{rule.id}</span>
                    <span className={`text-[8px] font-mono px-1 rounded uppercase ${
                      rule.severity === 'Critical' ? 'text-neon-red border border-neon-red/20 bg-neon-red/5' :
                      rule.severity === 'High' ? 'text-orange-400 border border-orange-400/20 bg-orange-400/5' :
                      'text-neon-yellow border border-neon-yellow/20 bg-neon-yellow/5'
                    }`}>
                      {rule.severity}
                    </span>
                  </div>
                  <h5 className="text-xs font-semibold text-slate-200">{rule.name}</h5>
                  <p className="text-[10px] text-slate-500">CATEGORY: {rule.category}</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-neon-green" />
                  <span className="text-[10px] font-mono text-slate-400 uppercase font-semibold">ACTIVE</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: AI Sigma / YARA Rule Creator */}
      {activeTab === 'ai-generator' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-start">
          {/* Controls Input Form */}
          <div className="p-5 bg-slate-900/40 border border-slate-800 rounded-xl space-y-4">
            <h4 className="text-xs uppercase text-slate-400 font-mono tracking-widest font-bold flex items-center gap-1.5">
              <Cpu className="w-4 h-4 text-neon-green" /> AI Rule Blueprint
            </h4>
            
            <form onSubmit={handleGenerateRule} className="space-y-4 font-mono text-xs">
              <div className="flex flex-col gap-1">
                <label className="text-[10px] text-slate-500 uppercase">Rule Target Output</label>
                <div className="flex gap-2">
                  {['sigma', 'yara'].map((type) => (
                    <button
                      key={type}
                      type="button"
                      onClick={() => setRuleType(type as any)}
                      className={`flex-1 py-1.5 rounded uppercase font-bold border transition-all duration-300 cursor-pointer ${
                        ruleType === type
                          ? 'bg-neon-cyan/15 border-neon-cyan text-neon-cyan'
                          : 'bg-slate-950 border-slate-850 text-slate-500'
                      }`}
                    >
                      {type} Rule Format
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex flex-col gap-1">
                <label className="text-[10px] text-slate-500 uppercase">Rule Title</label>
                <input
                  type="text"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  required
                  className="bg-slate-950 border border-slate-850 rounded p-2 text-xs text-slate-300 focus:outline-none focus:border-neon-cyan"
                />
              </div>

              <div className="flex flex-col gap-1">
                <label className="text-[10px] text-slate-500 uppercase">Description</label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  required
                  className="bg-slate-950 border border-slate-850 rounded p-2 text-xs text-slate-300 focus:outline-none focus:border-neon-cyan h-16"
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div className="flex flex-col gap-1">
                  <label className="text-[10px] text-slate-500 uppercase">Process Image Match</label>
                  <input
                    type="text"
                    value={targetImage}
                    onChange={(e) => setTargetImage(e.target.value)}
                    required
                    className="bg-slate-950 border border-slate-850 rounded p-2 text-xs text-slate-300 focus:outline-none focus:border-neon-cyan"
                  />
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-[10px] text-slate-500 uppercase">Command Line substring</label>
                  <input
                    type="text"
                    value={targetCmd}
                    onChange={(e) => setTargetCmd(e.target.value)}
                    className="bg-slate-950 border border-slate-850 rounded p-2 text-xs text-slate-300 focus:outline-none focus:border-neon-cyan"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loadingRule}
                className="w-full py-2.5 rounded bg-neon-green hover:bg-neon-green/80 text-black font-extrabold uppercase tracking-wider flex items-center justify-center gap-1.5 transition-all duration-300 disabled:opacity-50 cursor-pointer shadow-[0_0_15px_rgba(0,255,102,0.15)]"
              >
                {loadingRule ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Compiling...</span>
                  </>
                ) : (
                  <>
                    <FileCode className="w-4 h-4" />
                    <span>Compile AI Detection Rule</span>
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Code Viewer Output */}
          <div className="flex flex-col gap-2 h-full">
            <div className="flex justify-between items-center">
              <span className="text-xs uppercase text-slate-400 font-mono">Rule Definition Output</span>
              {generatedRule && (
                <button
                  onClick={handleCopyRule}
                  className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  {copied ? (
                    <>
                      <Check className="w-3 h-3 text-neon-green" />
                      <span className="text-neon-green">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copy Code</span>
                    </>
                  )}
                </button>
              )}
            </div>
            
            {generatedRule ? (
              <pre className="p-5 bg-black/80 rounded-xl border border-slate-800 text-[10px] font-mono text-slate-200 overflow-auto max-h-[350px] leading-relaxed shadow-inner">
                {generatedRule}
              </pre>
            ) : (
              <div className="h-[300px] border border-dashed border-slate-800 rounded-xl flex items-center justify-center text-xs text-slate-600 font-mono text-center px-6">
                AWAITING RULE BLUEPRINT GENERATION PARAMS. FILL DETAILS AND CLICK COMPILE.
              </div>
            )}
          </div>
        </div>
      )}

    </div>
  );
}
