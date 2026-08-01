import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { 
  Activity, 
  ShieldAlert, 
  Database, 
  GitBranch, 
  Crosshair, 
  Users, 
  Layers, 
  FileSearch, 
  Briefcase, 
  TrendingUp 
} from 'lucide-react';

const navItems = [
  { name: 'SOC Operations', href: '/dashboard', icon: Activity },
  { name: 'Incidents Queue', href: '/dashboard/incidents', icon: ShieldAlert },
  { name: 'SIEM Log Engine', href: '/dashboard/siem', icon: Database },
  { name: 'SOAR Automation', href: '/dashboard/soar', icon: GitBranch },
  { name: 'Threat Hunting', href: '/dashboard/hunting', icon: Crosshair },
  { name: 'UEBA Baselines', href: '/dashboard/ueba', icon: Users },
  { name: 'Vulnerability Mgmt', href: '/dashboard/vulnerability', icon: Layers },
  { name: 'Digital Forensics', href: '/dashboard/forensics', icon: FileSearch },
  { name: 'Threat Intelligence', href: '/dashboard/intel', icon: Briefcase },
  { name: 'Executive Reports', href: '/dashboard/reports', icon: TrendingUp },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 bg-[#070919]/95 border-r border-slate-800 flex flex-col h-screen fixed left-0 top-0 z-50">
      <div className="p-6 border-b border-slate-800 flex items-center space-x-3">
        <div className="w-8 h-8 rounded bg-gradient-to-tr from-purple-600 to-cyan-400 flex items-center justify-center font-bold text-white text-xs">
          AEGIS
        </div>
        <div>
          <h1 className="text-cyan-400 font-bold text-base tracking-wider">AURA SOC</h1>
          <p className="text-[10px] text-purple-400 font-mono tracking-widest uppercase">AI Defense</p>
        </div>
      </div>
      
      <div className="flex-1 overflow-y-auto py-4">
        <nav className="space-y-1 px-3">
          {navItems.map((item) => {
            const isActive = pathname === item.href;
            const Icon = item.icon;
            return (
              <Link
                key={item.name}
                href={item.href}
                className={`flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-200 group ${
                  isActive
                    ? 'bg-cyan-500/10 border-l-2 border-cyan-400 text-cyan-400 font-semibold'
                    : 'text-slate-400 hover:text-cyan-300 hover:bg-slate-800/50'
                }`}
              >
                <Icon className={`w-5 h-5 transition-colors ${isActive ? 'text-cyan-400' : 'text-slate-500 group-hover:text-cyan-400'}`} />
                <span className="font-medium">{item.name}</span>
              </Link>
            );
          })}
        </nav>
      </div>
      
      <div className="p-4 border-t border-slate-800 bg-[#090b1c]">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-full bg-slate-800 border border-cyan-500/50 flex items-center justify-center font-bold text-cyan-400 text-xs">
            SC
          </div>
          <div className="overflow-hidden">
            <p className="text-xs text-white font-medium truncate">SecOps Commander</p>
            <p className="text-[10px] text-slate-400 font-mono truncate">Tier 3 Analyst</p>
          </div>
        </div>
      </div>
    </aside>
  );
}
