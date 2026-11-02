'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { 
  Bot, 
  Send, 
  Terminal, 
  User, 
  Sparkles, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  Cpu, 
  ArrowRight, 
  RotateCcw,
  Sliders,
  ShieldCheck,
  Flame,
  Activity,
  Layers,
  ArrowLeft
} from 'lucide-react';
import { api } from '@/utils/api';

interface Message {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  verifiedEvidence?: Record<string, any>;
  recommendations?: string[];
  timestamp: string;
}

export default function AIAnalystPage() {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'init-1',
      role: 'system',
      content: 'Aegis CyberCopilot v2.4 initialized. Connected to real-time SIEM Detection Rules Engine and correlation memory.',
      timestamp: new Date().toLocaleTimeString()
    },
    {
      id: 'init-2',
      role: 'assistant',
      content: 'Hello Analyst. I continuously monitor the 10 active SIEM detection rules. You can ask me to analyze recent security alerts, explain detection evidence, or recommend incident response containment steps.',
      recommendations: [
        'Review recent brute force authentication alerts',
        'Verify potential credential theft from foreign IP addresses',
        'Run Automated Isolation Playbook on compromised endpoints'
      ],
      timestamp: new Date().toLocaleTimeString()
    }
  ]);
  const [input, setInput] = useState<string>('');
  const [analyzing, setAnalyzing] = useState<boolean>(false);
  const [alerts, setAlerts] = useState<any[]>([]);

  useEffect(() => {
    // Load recent alerts for quick context
    api.get('/alerts/').then((res) => {
      if (Array.isArray(res)) setAlerts(res.slice(0, 5));
    }).catch(() => {});
  }, []);

  const handleSend = async (customQuery?: string) => {
    const textToSend = (customQuery || input).trim();
    if (!textToSend || analyzing) return;

    const userMsg: Message = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: textToSend,
      timestamp: new Date().toLocaleTimeString()
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!customQuery) setInput('');
    setAnalyzing(true);

    try {
      // Send to backend AI analysis endpoint
      const response = await api.post('/ai/analyze', { query: textToSend });
      
      const assistantMsg: Message = {
        id: `ai-${Date.now()}`,
        role: 'assistant',
        content: response.ai_explanation || 'Analysis completed based on available telemetry.',
        verifiedEvidence: response.verified_evidence && Object.keys(response.verified_evidence).length > 0
          ? response.verified_evidence
          : undefined,
        recommendations: [
          'Verify source host network boundaries and perimeter firewall drop rules',
          'Audit user account session tokens and force password revocation if compromised',
          'Deploy Host Isolation playbook via SOAR engine'
        ],
        timestamp: new Date().toLocaleTimeString()
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      const errorMsg: Message = {
        id: `err-${Date.now()}`,
        role: 'assistant',
        content: `Analysis Error: ${err.message || 'Unable to contact AI inference gateway.'}`,
        timestamp: new Date().toLocaleTimeString()
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setAnalyzing(false);
    }
  };

  const quickPrompts = [
    'Analyze latest high-priority alert and extract indicators',
    'Explain Rule BR-001 Brute Force detection logic and threshold evidence',
    'Recommend containment steps for ransomware file modification signal',
    'Investigate suspicious outbound data transfer exceeding 10MB'
  ];

  return (
    <div className="min-h-screen bg-[#070913] text-slate-200 flex flex-col font-sans">
      {/* Top Navigation Bar */}
      <header className="h-16 border-b border-slate-800 bg-[#0a0e1c]/90 backdrop-blur-md px-6 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <Link
            href="/dashboard"
            className="flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-white transition px-2.5 py-1.5 rounded bg-slate-900 border border-slate-800"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>SOC Dashboard</span>
          </Link>
          <div className="h-4 w-[1px] bg-slate-800" />
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
              <Bot className="w-4 h-4" />
            </div>
            <div>
              <h1 className="text-sm font-bold text-white tracking-wide">
                AI Security Analyst Copilot
              </h1>
              <span className="text-[10px] text-purple-400 font-mono">
                EVIDENCE-GROUNDED REASONING ENGINE
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/dashboard/rules"
            className="text-xs font-mono text-cyan-400 hover:text-white flex items-center gap-1.5"
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>Detection Rules</span>
          </Link>
        </div>
      </header>

      {/* Main Chat & Evidence Split Screen */}
      <div className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 grid grid-cols-1 lg:grid-cols-4 gap-6 overflow-hidden">
        {/* Left Side: Chat Conversation (3 cols) */}
        <div className="lg:col-span-3 cyber-card flex flex-col h-[calc(100vh-130px)] bg-[#0a0e1c] p-0 overflow-hidden">
          {/* Messages Feed */}
          <div className="flex-1 overflow-y-auto p-5 space-y-4 font-sans text-sm">
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                {msg.role !== 'user' && (
                  <div className="w-8 h-8 rounded-full bg-purple-500/15 border border-purple-500/30 flex items-center justify-center text-purple-400 shrink-0 mt-0.5">
                    <Bot className="w-4 h-4" />
                  </div>
                )}

                <div
                  className={`max-w-[85%] rounded-xl p-4 space-y-3 ${
                    msg.role === 'user'
                      ? 'bg-cyan-600/15 border border-cyan-500/30 text-white rounded-tr-none'
                      : msg.role === 'system'
                      ? 'bg-slate-900/80 border border-slate-800 text-slate-400 text-xs font-mono'
                      : 'bg-[#0f152a] border border-slate-800 text-slate-200 rounded-tl-none shadow-[0_4px_20px_rgba(0,0,0,0.3)]'
                  }`}
                >
                  {/* Message Label Tag */}
                  {msg.role === 'assistant' && (
                    <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                      <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-purple-400 flex items-center gap-1">
                        <Sparkles className="w-3 h-3" /> AI Copilot Analysis
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono">{msg.timestamp}</span>
                    </div>
                  )}

                  {/* Message Body */}
                  <div className="prose prose-invert prose-xs max-w-none whitespace-pre-line leading-relaxed text-slate-300">
                    {msg.content}
                  </div>

                  {/* Verified Forensic Evidence Callout */}
                  {msg.verifiedEvidence && (
                    <div className="p-3 rounded-lg bg-[#070b18] border border-cyan-500/30 space-y-2 font-mono text-xs">
                      <div className="flex items-center justify-between text-cyan-400 font-bold uppercase text-[10px] tracking-wider border-b border-slate-800 pb-1.5">
                        <span className="flex items-center gap-1.5">
                          <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                          [VERIFIED SYSTEM EVIDENCE]
                        </span>
                        <span>{msg.verifiedEvidence.alert_id}</span>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-300">
                        <div>
                          <span className="text-slate-500 block">Triggering Rule:</span>
                          <strong>{msg.verifiedEvidence.rule_id} · {msg.verifiedEvidence.title}</strong>
                        </div>
                        <div>
                          <span className="text-slate-500 block">Source IP / User:</span>
                          <strong>{msg.verifiedEvidence.source_ip || 'N/A'} ({msg.verifiedEvidence.username || 'System'})</strong>
                        </div>
                      </div>
                      {msg.verifiedEvidence.evidence_payload && (
                        <div className="mt-1 pt-1.5 border-t border-slate-800/80 text-[10px] text-slate-400">
                          <span>Condition: {msg.verifiedEvidence.evidence_payload.trigger_condition || 'Detection threshold satisfied'}</span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Recommendations */}
                  {msg.recommendations && msg.recommendations.length > 0 && (
                    <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/30 space-y-1.5 font-mono text-xs">
                      <span className="text-[10px] text-emerald-400 font-bold uppercase tracking-wider block">
                        Recommended SOC Actions:
                      </span>
                      <ul className="list-disc pl-4 space-y-1 text-slate-300 text-[11px]">
                        {msg.recommendations.map((rec, i) => (
                          <li key={i}>{rec}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {msg.role === 'user' && (
                  <div className="w-8 h-8 rounded-full bg-cyan-500/20 border border-cyan-400/40 flex items-center justify-center text-cyan-300 shrink-0 mt-0.5">
                    <User className="w-4 h-4" />
                  </div>
                )}
              </div>
            ))}

            {analyzing && (
              <div className="flex gap-3 items-center text-purple-400 font-mono text-xs">
                <div className="w-8 h-8 rounded-full bg-purple-500/10 border border-purple-500/30 flex items-center justify-center animate-spin">
                  <Bot className="w-4 h-4" />
                </div>
                <span>Extracting telemetry facts and querying CyberCopilot...</span>
              </div>
            )}
          </div>

          {/* Prompt Suggestions */}
          <div className="p-2.5 border-t border-slate-800 bg-[#080c1a] flex flex-wrap gap-1.5">
            {quickPrompts.map((qp, idx) => (
              <button
                key={idx}
                disabled={analyzing}
                onClick={() => handleSend(qp)}
                className="text-[11px] font-mono px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-cyan-300 hover:border-cyan-500/30 transition cursor-pointer"
              >
                {qp}
              </button>
            ))}
          </div>

          {/* Input Box */}
          <div className="p-3.5 border-t border-slate-800 bg-[#0a0e1c] flex items-center gap-2">
            <input
              type="text"
              value={input}
              disabled={analyzing}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSend()}
              placeholder="Ask the AI Analyst to investigate an incident, audit suspicious IPs, or recommend playbooks..."
              className="flex-1 bg-slate-900 border border-slate-800 rounded-lg px-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono transition"
            />
            <button
              onClick={() => handleSend()}
              disabled={analyzing || !input.trim()}
              className="cyber-button-primary px-4 py-2.5 font-mono text-xs"
            >
              <Send className="w-4 h-4" />
              <span className="hidden sm:inline">Analyze</span>
            </button>
          </div>
        </div>

        {/* Right Side: Active Alert Context & Forensic Feeds (1 col) */}
        <div className="space-y-4">
          <div className="cyber-card p-4">
            <h3 className="text-xs font-mono uppercase tracking-wider text-white font-bold mb-3 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              Recent Alerts for Analysis
            </h3>

            <div className="space-y-2 font-mono text-xs">
              {alerts.length === 0 ? (
                <p className="text-slate-500 text-xs">No alerts currently loaded.</p>
              ) : (
                alerts.map((alt, idx) => (
                  <button
                    key={`${alt.alert_id || alt.id || 'alt'}-${idx}`}
                    onClick={() => handleSend(`Investigate alert ${alt.alert_id || alt.id}: "${alt.title}"`)}
                    className="w-full text-left p-2.5 rounded bg-slate-900/70 border border-slate-800 hover:border-purple-500/40 hover:bg-slate-850 transition block"
                  >
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-[10px] text-cyan-400 font-bold">{alt.rule_id || 'SIEM'}</span>
                      <span className="text-[9px] text-rose-400 uppercase">{alt.severity}</span>
                    </div>
                    <p className="text-slate-200 font-semibold truncate text-[11px]">{alt.title}</p>
                  </button>
                ))
              )}
            </div>
          </div>

          <div className="cyber-card p-4 space-y-2 font-mono text-xs text-slate-400">
            <h4 className="text-slate-300 font-bold uppercase text-[10px] tracking-wider">
              Verification Protocol
            </h4>
            <p className="text-[11px] leading-relaxed">
              System facts and rule matches are derived from database logs. Analysis outputs are synthesized using cyber security domain reasoning.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
