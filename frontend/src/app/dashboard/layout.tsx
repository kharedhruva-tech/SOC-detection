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
  TrendingUp,
  Sliders,
  AlertOctagon,
  Bot,
  Menu,
  X,
  Globe
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
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

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
        '/dashboard/asm',
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
    { name: 'Live SIEM Alerts', path: '/alerts', icon: AlertOctagon },
    { name: 'Detection Rules', path: '/dashboard/rules', icon: Sliders },
    { name: 'Incidents Queue', path: '/dashboard/incidents', icon: ShieldAlert },
    { name: 'SIEM Log Engine', path: '/dashboard/siem', icon: Database },
    { name: 'AI Analyst Copilot', path: '/ai-analyst', icon: Bot },
    { name: 'SOAR Automation', path: '/dashboard/soar', icon: GitBranch },
    { name: 'Threat Hunting', path: '/dashboard/hunting', icon: Crosshair },
    { name: 'UEBA Baselines', path: '/dashboard/ueba', icon: Users },
    { name: 'Vulnerability Mgmt', path: '/dashboard/vulnerability', icon: Layers },
    { name: 'Attack Surface (ASM)', path: '/dashboard/asm', icon: Globe },
    { name: 'Digital Forensics', path: '/dashboard/forensics', icon: FileSearch },
    { name: 'Threat Intelligence', path: '/dashboard/intel', icon: Briefcase },
    { name: 'Executive Reports', path: '/dashboard/reports', icon: TrendingUp },
  ];

  if (!mounted) return null;

  return (
    <div className="flex h-screen bg-[#070913] text-slate-200 overflow-hidden">
      {/* Mobile Backdrop */}
      {mobileMenuOpen && (
        <div
          onClick={() => setMobileMenuOpen(false)}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-40 lg:hidden"
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed lg:static top-0 bottom-0 left-0 w-64 bg-[#0a0e1c] border-r border-slate-800/80 flex flex-col z-50 transition-transform duration-200 ${
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Brand Header */}
        <div className="h-16 flex items-center justify-between px-6 border-b border-slate-800/80">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center shadow-[0_0_12px_rgba(56,189,248,0.3)]">
              <Terminal className="w-4 h-4 text-white" />
            </div>
            <div>
              <h1 className="font-bold text-sm tracking-wider text-white">
                AEGIS <span className="text-cyan-400">SOC</span>
              </h1>
              <span className="text-[9px] uppercase text-cyan-400/80 tracking-widest block font-mono font-semibold">
                Enterprise Defense
              </span>
            </div>
          </div>
          <button
            onClick={() => setMobileMenuOpen(false)}
            className="lg:hidden text-slate-400 hover:text-white p-1"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation List */}
        <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto font-mono text-xs">
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
                  onClick={() => setMobileMenuOpen(false)}
                  className={`flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-150 group font-medium ${
                    isActive 
                      ? 'bg-cyan-500/15 border-l-2 border-cyan-400 text-cyan-300 shadow-[inset_0_0_12px_rgba(56,189,248,0.1)]' 
                      : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
                  }`}
                >
                  <Icon className={`w-4 h-4 transition-colors ${isActive ? 'text-cyan-400' : 'text-slate-500 group-hover:text-cyan-400'}`} />
                  <span>{item.name}</span>
                </Link>
              );
            })}
        </nav>

        {/* User Card */}
        <div className="p-4 border-t border-slate-800/80 bg-[#070914] flex flex-col gap-2">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-cyan-400 text-xs">
              {user.slice(0, 2).toUpperCase()}
            </div>
            <div className="overflow-hidden">
              <p className="text-xs font-semibold truncate text-slate-200">{user}</p>
              <p className="text-[10px] text-cyan-400/80 font-mono uppercase truncate">{role}</p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="mt-1 w-full flex items-center justify-center gap-2 py-1.5 px-3 rounded bg-rose-950/30 hover:bg-rose-900/40 border border-rose-900/50 hover:border-rose-700 text-xs text-rose-300 transition-all font-mono cursor-pointer"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>End Session</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden min-w-0">
        {/* Top Header */}
        <header className="h-16 border-b border-slate-800/80 bg-[#0a0e1c]/90 backdrop-blur-md flex items-center justify-between px-6 z-10 shrink-0">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden text-slate-400 hover:text-white p-1"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
              <span className="text-xs font-mono text-slate-400 hidden sm:inline">
                TELEMETRY:
              </span>
              <span className={`text-xs font-mono font-bold ${wsConnected ? 'text-emerald-400' : 'text-rose-400'}`}>
                {wsConnected ? 'LIVE STREAM' : 'OFFLINE'}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 bg-slate-900/80 px-3 py-1 rounded-full border border-slate-800 text-xs font-mono text-slate-300">
              {wsConnected ? (
                <Wifi className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <WifiOff className="w-3.5 h-3.5 text-rose-400" />
              )}
              <span className="hidden sm:inline">SOC Gateway 8000</span>
            </div>
            
            <div className="text-xs font-mono text-slate-400 hidden md:block border-l border-slate-800 pl-4">
              UTC: <span className="text-slate-200">{new Date().toLocaleTimeString()}</span>
            </div>
          </div>
        </header>

        {/* Child Router Content */}
        <main className="flex-1 overflow-y-auto bg-[#070913] p-6 lg:p-8">
          {children}
        </main>
      </div>
    </div>
  );
}
