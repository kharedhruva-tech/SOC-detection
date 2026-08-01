'use client';
import { useState } from 'react';
import { Terminal, Send, Bot, User } from 'lucide-react';

export default function AIAnalystPage() {
  const [messages, setMessages] = useState([
    { role: 'system', content: 'AURA AI Copilot initialized. Ready to assist with threat analysis and incident response.' },
    { role: 'user', content: 'Can you summarize the recent ransomware incident (INC-2024-001)?' },
    { role: 'assistant', content: 'Certainly. Incident INC-2024-001 involves a suspected ransomware infection on Host 10.0.1.5 (Local). The attack vector appears to be a malicious payload dropped via a phishing email. Over 25 files were encrypted in the C:\\Users\\jsmith\\Documents directory. I recommend immediately isolating the host and running the "Ransomware Containment" playbook.' }
  ]);
  const [input, setInput] = useState('');

  const handleSend = () => {
    if (!input.trim()) return;
    
    // Add user message
    setMessages(prev => [...prev, { role: 'user', content: input }]);
    setInput('');
    
    // Simulate AI response
    setTimeout(() => {
      setMessages(prev => [...prev, { role: 'assistant', content: 'I am analyzing your request. As a simulation, I cannot perform live queries at this moment, but in a production environment, I would query the SIEM database and return actionable intelligence here.' }]);
    }, 1000);
  };

  return (
    <div className="p-8 h-screen flex flex-col">
      <div className="mb-6 flex-shrink-0">
        <h1 className="text-3xl font-bold text-white mb-1 flex items-center">
          <Terminal className="w-8 h-8 mr-3 text-[#bc13fe]" /> AI Analyst Copilot
        </h1>
        <p className="text-gray-400">Natural language threat intelligence and incident investigation</p>
      </div>

      <div className="flex-1 cyber-card flex flex-col overflow-hidden">
        <div className="flex-1 overflow-y-auto p-4 space-y-6">
          {messages.map((msg, idx) => (
            <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`flex items-start max-w-[80%] ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
                <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${
                  msg.role === 'user' ? 'bg-[#00f3ff]/20 text-[#00f3ff] ml-3' : 
                  msg.role === 'system' ? 'bg-[#39ff14]/20 text-[#39ff14] mr-3' : 
                  'bg-[#bc13fe]/20 text-[#bc13fe] mr-3'
                }`}>
                  {msg.role === 'user' ? <User className="w-4 h-4" /> : msg.role === 'system' ? <Terminal className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
                </div>
                <div className={`p-4 rounded-lg ${
                  msg.role === 'user' ? 'bg-[#00f3ff]/10 border border-[#00f3ff]/30 text-[#e0e0e0]' : 
                  msg.role === 'system' ? 'bg-[#39ff14]/10 border border-[#39ff14]/30 text-[#39ff14] font-mono text-sm' : 
                  'bg-[#232333]/50 border border-[#232333] text-gray-300'
                }`}>
                  {msg.content}
                </div>
              </div>
            </div>
          ))}
        </div>
        
        <div className="p-4 border-t border-[#232333] bg-[#0a0a0f] flex-shrink-0">
          <div className="relative">
            <input 
              type="text" 
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSend()}
              placeholder="Ask the AI Analyst to investigate an IP, summarize an incident, or write a YARA rule..." 
              className="w-full bg-[#12121a] border border-[#232333] text-white px-4 py-3 rounded-lg focus:outline-none focus:border-[#bc13fe] transition-colors pr-12"
            />
            <button 
              onClick={handleSend}
              className="absolute right-2 top-2 p-1.5 text-gray-400 hover:text-[#bc13fe] transition-colors bg-[#0a0a0f] rounded"
            >
              <Send className="w-5 h-5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
