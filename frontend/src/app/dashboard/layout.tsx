'use client';

import React, { useEffect, useState } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import Link from 'next/link';
import { 
  ShieldAlert, 
  Terminal, 
  Settings, 
  LogOut, 
  Wifi, 
  WifiOff, 
  Activity, 
  GitBranch, 
  Crosshair, 
  Users, 
  Layers, 
  FileSearch, 
  Database,
  Briefcase,
  TrendingUp
} from 'lucide-react';
import { WS_BASE_URL } from '@/utils/api';

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const [user, setUser] = useState<string>('');
  const [role, setRole] = useState<string>('');
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [mounted, setMounted] = useState<boolean>(false);

  useEffect(() => {
    setMounted(true);
    let token = localStorage.getItem('soc_token');
    let storedUser = localStorage.getItem('soc_user');
    let storedRole = localStorage.getItem('soc_role');

    if (!token || !storedUser || !storedRole) {
      token = 'demo-session-token';
      storedUser = 'SecOps Commander';
      storedRole = 'Tier 3 Analyst';
      localStorage.setItem('soc_token', token);
      localStorage.setItem('soc_user', storedUser);
      localStorage.setItem('soc_role', storedRole);
    }

    setUser(storedUser);
    setRole(storedRole);

    // Setup Websocket for live alerts indicator
    let ws: WebSocket;
    let reconnectTimeout: NodeJS.Timeout;
    let active = true;

    const connect = () => {
      if (!active) return;
      ws = new WebSocket(WS_BASE_URL);
      ws.onopen = () => {
        setWsConnected(true);
      };
      ws.onclose = () => {
        setWsConnected(false);
        if (active) {
          reconnectTimeout = setTimeout(connect, 3000);
        }
      };
      ws.onerror = () => {
        setWsConnected(false);
      };
    };

    connect();

    return () => {
      active = false;
      if (ws) ws.close();
      clearTimeout(reconnectTimeout);
    };
  }, []);

  useEffect(() => {
    if (mounted && role === 'SOC User') {
      const allowedPaths = [
        '/dashboard',
        '/dashboard/reports',
        '/dashboard/vulnerability',
        '/dashboard/soar'
      ];
      if (!allowedPaths.includes(pathname)) {
        router.replace('/dashboard');
      }
    }
  }, [pathname, role, mounted, router]);

  const handleLogout = () => {
    localStorage.removeItem('soc_token');
    localStorage.removeItem('soc_user');
    localStorage.removeItem('soc_role');
    router.push('/');
  };

  const navItems = [
    { name: 'SOC Operations', path: '/dashboard', icon: Activity },
    { name: 'Incidents Queue', path: '/dashboard/incidents', icon: ShieldAlert },
    { name: 'SIEM Log Engine', path: '/dashboard/siem', icon: Database },
    { name: 'SOAR Automation', path: '/dashboard/soar', icon: GitBranch },
    { name: 'Threat Hunting', path: '/dashboard/hunting', icon: Crosshair },
    { name: 'UEBA Baselines', path: '/dashboard/ueba', icon: Users },
    { name: 'Vulnerability Mgmt', path: '/dashboard/vulnerability', icon: Layers },
    { name: 'Digital Forensics', path: '/dashboard/forensics', icon: FileSearch },
    { name: 'Threat Intelligence', path: '/dashboard/intel', icon: Briefcase },
    { name: 'Executive Reports', path: '/dashboard/reports', icon: TrendingUp },
  ];

  if (!mounted) return null;

  return (
    <div className="flex h-screen bg-cyber-bg text-slate-200 overflow-hidden scanlines">
      {/* Sidebar */}
      <aside className="w-64 bg-[#070919]/90 border-r border-slate-800 flex flex-col z-20">
        {/* Brand Header */}
        <div className="h-16 flex items-center px-6 border-b border-slate-800 gap-3">
          <div className="w-8 h-8 rounded bg-gradient-to-tr from-neon-purple to-neon-cyan flex items-center justify-center">
            <Terminal className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="font-bold tracking-wider bg-gradient-to-r from-neon-cyan to-white bg-clip-text text-transparent">
              AEGIS SOC
            </h1>
            <span className="text-[10px] uppercase text-neon-green tracking-widest block font-bold">
              AI INTEGRATED
            </span>
          </div>
        </div>

        {/* Navigation List */}
        <nav className="flex-1 py-6 px-4 space-y-1 overflow-y-auto">
          {navItems
            .filter((item) => {
              if (role === 'SOC User') {
                return [
                  '/dashboard',
                  '/dashboard/reports',
                  '/dashboard/vulnerability',
                  '/dashboard/soar'
                ].includes(item.path);
              }
              return true;
            })
            .map((item) => {
            const Icon = item.icon;
            const isActive = pathname === item.path;
            return (
              <Link
                key={item.path}
                href={item.path}
                className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm transition-all duration-300 group ${
                  isActive 
                    ? 'bg-neon-cyan/10 border-l-2 border-neon-cyan text-neon-cyan font-semibold shadow-[0_0_15px_rgba(0,240,255,0.05)]' 
                    : 'text-slate-400 hover:bg-slate-800/40 hover:text-slate-100'
                }`}
              >
                <Icon className={`w-5 h-5 transition-transform duration-300 group-hover:scale-110 ${isActive ? 'text-neon-cyan' : 'text-slate-500 group-hover:text-neon-cyan'}`} />
                <span>{item.name}</span>
              </Link>
            );
          })}
        </nav>

        {/* User Card */}
        <div className="p-4 border-t border-slate-800 bg-[#090b1c]/80 flex flex-col gap-2">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-neon-cyan">
              {user.slice(0, 2).toUpperCase()}
            </div>
            <div className="overflow-hidden">
              <p className="text-sm font-semibold truncate text-slate-200">{user}</p>
              <p className="text-[10px] text-neon-purple font-mono uppercase truncate">{role}</p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="mt-2 w-full flex items-center justify-center gap-2 py-2 px-3 rounded bg-red-950/30 hover:bg-red-900/40 border border-red-900/50 hover:border-red-700 text-xs text-red-400 transition-all duration-300 font-semibold cursor-pointer"
          >
            <LogOut className="w-4 h-4" />
            <span>Terminate Session</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Header */}
        <header className="h-16 border-b border-slate-800 bg-[#070919]/60 backdrop-blur-md flex items-center justify-between px-8 z-10">
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-neon-green animate-ping' : 'bg-red-500'}`} />
            <span className="text-xs font-mono text-slate-400">
              SOCKET SYSTEM STATUS:
            </span>
            <span className={`text-xs font-mono font-bold ${wsConnected ? 'text-neon-green' : 'text-red-500'}`}>
              {wsConnected ? 'ONLINE (STREAMING)' : 'OFFLINE'}
            </span>
          </div>

          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2 bg-slate-800/40 px-3 py-1.5 rounded-full border border-slate-700/50">
              {wsConnected ? (
                <Wifi className="w-4 h-4 text-neon-green" />
              ) : (
                <WifiOff className="w-4 h-4 text-red-500" />
              )}
              <span className="text-xs font-mono text-slate-300">AEGIS Core API v1</span>
            </div>
            
            <div className="text-xs font-mono text-slate-400 border-l border-slate-800 pl-6">
              SYSTEM TIME: <span className="text-slate-200">{new Date().toLocaleDateString()}</span>
            </div>
          </div>
        </header>

        {/* Child Router Content */}
        <main className="flex-1 overflow-y-auto bg-[#04050d] p-8">
          {children}
        </main>
      </div>
    </div>
  );
}
