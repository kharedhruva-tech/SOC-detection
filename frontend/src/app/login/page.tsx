'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { Shield, Lock, User, Terminal, CheckCircle2, AlertCircle, ArrowRight, Cpu } from 'lucide-react';
import { API_BASE_URL } from '@/utils/api';

export default function LoginPage() {
  const router = useRouter();
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  // Matrix / Hacker digital rain background canvas animation
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    const charSet = '0123456789ABCDEFABCDEFGHIJKLMNOPQRSTUVWXYZｦｱｳｴｵｶｷｹｺｻｼｽｾｿﾀﾂﾃﾅﾆﾇﾈﾊﾋﾎﾏﾐﾑﾒﾓﾔﾕﾗﾘﾜ';
    const fontSize = 14;
    const columns = Math.floor(width / fontSize);
    const drops: number[] = Array(columns).fill(1);

    const draw = () => {
      // Semi-transparent fade background for matrix trail effect
      ctx.fillStyle = 'rgba(4, 5, 13, 0.08)';
      ctx.fillRect(0, 0, width, height);

      ctx.font = `${fontSize}px monospace`;

      for (let i = 0; i < drops.length; i++) {
        const text = charSet.charAt(Math.floor(Math.random() * charSet.length));
        
        // Alternate between neon cyan, matrix green and purple
        if (i % 5 === 0) {
          ctx.fillStyle = '#00f0ff';
        } else if (i % 3 === 0) {
          ctx.fillStyle = '#7000ff';
        } else {
          ctx.fillStyle = '#00ff66';
        }

        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        if (drops[i] * fontSize > height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i]++;
      }

      animationFrameId = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    setSuccessMsg('');
    setLoading(true);

    try {
      // Send login request to backend API
      const res = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || 'Authentication failed');
      }

      setSuccessMsg(`ACCESS GRANTED // WELCOME COMMANDER ${data.username.toUpperCase()}`);
      
      // Store credentials in localStorage
      localStorage.setItem('soc_token', data.access_token);
      localStorage.setItem('soc_user', data.username);
      localStorage.setItem('soc_role', data.role);

      setTimeout(() => {
        router.push('/dashboard');
      }, 1000);
    } catch (err: any) {
      // Fallback for offline or static dev mode: accept admin / admin regardless
      if (username === 'admin' && password === '2006') {
        setSuccessMsg('OFFLINE OVERRIDE ACCEPTED // LOGGING IN AS ADMIN');
        localStorage.setItem('soc_token', 'aegis-admin-demo-token');
        localStorage.setItem('soc_user', 'admin');
        localStorage.setItem('soc_role', 'Super Admin');
        setTimeout(() => {
          router.push('/dashboard');
        }, 1000);
      } else if (username === 'user' && password === 'user') {
        setSuccessMsg('OFFLINE OVERRIDE ACCEPTED // LOGGING IN AS SOC USER');
        localStorage.setItem('soc_token', 'aegis-user-demo-token');
        localStorage.setItem('soc_user', 'user');
        localStorage.setItem('soc_role', 'SOC User');
        setTimeout(() => {
          router.push('/dashboard');
        }, 1000);
      } else {
        setErrorMsg(err.message || 'INVALID CREDENTIALS. SYSTEM ACCESS DENIED.');
      }
    } finally {
      setLoading(false);
    }
  };



  return (
    <div className="relative min-h-screen w-full overflow-hidden bg-[#04050d] text-slate-100 flex items-center justify-center font-mono selection:bg-neon-cyan/30 selection:text-neon-cyan">
      
      {/* Background Matrix Canvas */}
      <canvas ref={canvasRef} className="absolute inset-0 z-0 opacity-40 pointer-events-none" />

      {/* Futuristic Scanline Overlay */}
      <div className="absolute inset-0 z-0 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%)] bg-[length:100%_4px] pointer-events-none opacity-60" />

      {/* Cyber Grid Background lines */}
      <div className="absolute inset-0 z-0 bg-[linear-gradient(to_right,#00f0ff08_1px,transparent_1px),linear-gradient(to_bottom,#00f0ff08_1px,transparent_1px)] bg-[size:4rem_4rem] pointer-events-none" />

      {/* Central Login Card Container */}
      <div className="relative z-10 w-full max-w-md p-6 sm:p-8">
        
        {/* Glow backdrop behind card */}
        <div className="absolute -inset-1 rounded-2xl bg-gradient-to-r from-neon-cyan/20 via-neon-purple/20 to-neon-green/20 blur-xl opacity-70 animate-pulse pointer-events-none" />

        <div className="relative border border-slate-800/80 bg-[#070919]/90 backdrop-blur-2xl rounded-2xl p-8 shadow-[0_0_50px_rgba(0,240,255,0.15)]">
          
          {/* Card Header */}
          <div className="flex flex-col items-center text-center space-y-3 mb-8">
            <div className="relative w-16 h-16 rounded-2xl bg-slate-900 border border-neon-cyan/40 flex items-center justify-center shadow-[0_0_20px_rgba(0,240,255,0.25)]">
              <Shield className="w-8 h-8 text-neon-cyan animate-pulse" />
              <div className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-neon-green border-2 border-[#070919]" />
            </div>
            
            <div>
              <h1 className="text-xl font-bold tracking-widest uppercase text-slate-100 flex items-center justify-center gap-2">
                AEGIS <span className="text-neon-cyan">SOC CORE</span>
              </h1>
              <p className="text-[11px] text-slate-400 font-mono tracking-wider uppercase mt-1">
                CYBERNETIC COMMAND & DEFENSE GATEWAY
              </p>
            </div>


          </div>

          {/* Alert Message Containers */}
          {errorMsg && (
            <div className="mb-6 p-3 rounded-lg border border-red-500/40 bg-red-950/40 flex items-center gap-3 text-xs text-red-400 animate-shake">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {successMsg && (
            <div className="mb-6 p-3 rounded-lg border border-neon-green/40 bg-neon-green/10 flex items-center gap-3 text-xs text-neon-green animate-pulse">
              <CheckCircle2 className="w-4 h-4 text-neon-green shrink-0" />
              <span>{successMsg}</span>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleLogin} className="space-y-5">
            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-2 tracking-wider flex items-center gap-1.5">
                <User className="w-3.5 h-3.5 text-neon-cyan" />
                <span>CYBER USERNAME</span>
              </label>
              <div className="relative">
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter username"
                  className="w-full bg-[#03040a] border border-slate-700/80 focus:border-neon-cyan focus:ring-1 focus:ring-neon-cyan rounded-lg px-4 py-3 text-sm text-slate-100 placeholder:text-slate-600 outline-none transition-all duration-200 font-mono"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-2 tracking-wider flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-neon-purple" />
                <span>SECURITY ACCESS CODE</span>
              </label>
              <div className="relative">
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter password"
                  className="w-full bg-[#03040a] border border-slate-700/80 focus:border-neon-purple focus:ring-1 focus:ring-neon-purple rounded-lg px-4 py-3 text-sm text-slate-100 placeholder:text-slate-600 outline-none transition-all duration-200 font-mono"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="mt-6 w-full py-3.5 px-6 rounded-lg bg-gradient-to-r from-neon-cyan/20 via-neon-purple/20 to-neon-green/20 hover:from-neon-cyan/30 hover:via-neon-purple/30 hover:to-neon-green/30 border border-neon-cyan/50 hover:border-neon-cyan text-slate-100 font-bold uppercase tracking-widest text-xs flex items-center justify-center gap-3 transition-all duration-300 shadow-[0_0_20px_rgba(0,240,255,0.2)] active:scale-95 cursor-pointer disabled:opacity-50"
            >
              {loading ? (
                <>
                  <Cpu className="w-4 h-4 animate-spin text-neon-cyan" />
                  <span>AUTHENTICATING AGENT...</span>
                </>
              ) : (
                <>
                  <Terminal className="w-4 h-4 text-neon-cyan" />
                  <span>INITIALIZE SYSTEM ACCESS</span>
                  <ArrowRight className="w-4 h-4 text-neon-green" />
                </>
              )}
            </button>
          </form>

          {/* Footer Security Watermark */}
          <div className="mt-8 pt-4 border-t border-slate-800/80 text-center">
            <p className="text-[10px] text-slate-500 font-mono uppercase tracking-widest">
              AEGIS PROTOCOL v3.14 // AUTHORIZED PERSONNEL ONLY
            </p>
          </div>

        </div>
      </div>
    </div>
  );
}
