'use client';

import React, { useState, useEffect, useMemo } from 'react';
import {
  Globe,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Server,
  Layers,
  Search,
  Filter,
  Plus,
  RotateCw,
  ExternalLink,
  ChevronRight,
  X,
  Sparkles,
  Lock,
  Unlock,
  Radio,
  FileCode,
  Activity,
  CheckCircle2,
  Clock,
  AlertOctagon,
  Eye,
  Check,
  Copy,
  Sliders,
  Calendar,
  Network,
  Cpu,
  RefreshCw,
  Terminal,
  Zap,
  Tag,
  Play
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip
} from 'recharts';
import { api } from '@/utils/api';

// ──────────────────────────────────────────────
// Type Definitions
// ──────────────────────────────────────────────
interface ASMAsset {
  id: number;
  asset_id: string;
  name: string;
  asset_type: string;
  domain_name?: string;
  ip_address?: string;
  environment: string;
  owner: string;
  business_unit: string;
  criticality: string;
  authorization_status: string;
  discovery_source: string;
  exposure_level: string;
  risk_score: number;
  status: string;
  first_seen: string;
  last_seen: string;
  metadata_info?: Record<string, any>;
}

interface ASMDomain {
  id: number;
  domain_id: string;
  root_domain: string;
  subdomain: string;
  ip_addresses: string[];
  cname_target?: string;
  dns_status: string;
  is_apex: boolean;
  is_active: boolean;
  discovered_via: string;
  first_seen: string;
  last_seen: string;
  flagged_review: boolean;
}

interface ASMCertificate {
  id: number;
  cert_id: string;
  domain_name: string;
  port: number;
  issuer: string;
  subject_cn: string;
  sans: string[];
  valid_from: string;
  valid_to: string;
  days_remaining: number;
  status: string;
  tls_version: string;
  cipher_suite?: string;
  chain_status: string;
  last_checked: string;
}

interface ASMService {
  id: number;
  service_id: string;
  asset_id?: string;
  hostname: string;
  ip_address: string;
  port: number;
  protocol: string;
  service_name: string;
  version?: string;
  is_approved_baseline: boolean;
  exposure_status: string;
  risk_level: string;
  last_assessed: string;
}

interface ASMChangeLog {
  id: number;
  change_id: string;
  asset_id?: string;
  asset_name: string;
  change_type: string;
  previous_value?: string;
  current_value?: string;
  severity: string;
  description: string;
  timestamp: string;
  reviewed: boolean;
  reviewed_by?: string;
}

interface ASMDashboardStats {
  total_assets: number;
  total_domains: number;
  total_certificates: number;
  expiring_certificates_count: number;
  total_services: number;
  unexpected_services_count: number;
  active_change_events: number;
  average_attack_surface_risk: number;
  asset_types_distribution: Record<string, number>;
  exposure_distribution: Record<string, number>;
  environment_distribution: Record<string, number>;
  critical_perimeter_assets: ASMAsset[];
  recent_changes: ASMChangeLog[];
  expiring_certificates: ASMCertificate[];
  unexpected_services: ASMService[];
}

const CRITICALITY_COLORS: Record<string, string> = {
  Critical: '#f43f5e',
  High: '#f97316',
  Medium: '#f59e0b',
  Low: '#06b6d4',
  Info: '#38bdf8',
};

const CHART_COLORS = ['#06b6d4', '#8b5cf6', '#3b82f6', '#ec4899', '#10b981', '#f59e0b'];

export default function AttackSurfacePage() {
  const [activeTab, setActiveTab] = useState<'overview' | 'assets' | 'domains' | 'certs' | 'services' | 'changes'>('overview');
  const [stats, setStats] = useState<ASMDashboardStats | null>(null);
  const [assets, setAssets] = useState<ASMAsset[]>([]);
  const [domains, setDomains] = useState<ASMDomain[]>([]);
  const [certificates, setCertificates] = useState<ASMCertificate[]>([]);
  const [services, setServices] = useState<ASMService[]>([]);
  const [changes, setChanges] = useState<ASMChangeLog[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Asset Filters & Search
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedType, setSelectedType] = useState<string>('All');
  const [selectedEnv, setSelectedEnv] = useState<string>('All');
  const [selectedCriticality, setSelectedCriticality] = useState<string>('All');
  const [selectedExposure, setSelectedExposure] = useState<string>('All');

  // Modals & Drawers
  const [isAddAssetModalOpen, setIsAddAssetModalOpen] = useState<boolean>(false);
  const [isDnsModalOpen, setIsDnsModalOpen] = useState<boolean>(false);
  const [selectedAssetForDetails, setSelectedAssetForDetails] = useState<ASMAsset | null>(null);
  const [assetFullDetails, setAssetFullDetails] = useState<any>(null);
  const [detailsLoading, setDetailsLoading] = useState<boolean>(false);

  // DNS Inspector state
  const [dnsTargetDomain, setDnsTargetDomain] = useState<string>('api.enterprise-defense.org');
  const [dnsDkimSelector, setDnsDkimSelector] = useState<string>('default');
  const [dnsAssessing, setDnsAssessing] = useState<boolean>(false);
  const [dnsResult, setDnsResult] = useState<any>(null);

  // AI Explain State
  const [aiLoading, setAiLoading] = useState<boolean>(false);
  const [aiReport, setAiReport] = useState<any>(null);

  // Form State for Asset Registration
  const [newAsset, setNewAsset] = useState({
    name: '',
    asset_type: 'Web Application',
    domain_name: '',
    ip_address: '',
    environment: 'Production',
    owner: 'Security Operations',
    business_unit: 'Core Systems',
    criticality: 'High',
    exposure_level: 'Public Internet',
    discovery_source: 'Manual Registration',
  });

  // ──────────────────────────────────────────────
  // Fetch Functions
  // ──────────────────────────────────────────────
  const loadDashboardData = async () => {
    try {
      setRefreshing(true);
      setError(null);

      const [dashRes, assetsRes, domainsRes, certsRes, servicesRes, changesRes] = await Promise.all([
        api.get('/asm/dashboard'),
        api.get('/asm/assets'),
        api.get('/asm/domains'),
        api.get('/asm/certificates'),
        api.get('/asm/services'),
        api.get('/asm/changes'),
      ]);

      setStats(dashRes);
      setAssets(assetsRes);
      setDomains(domainsRes);
      setCertificates(certsRes);
      setServices(servicesRes);
      setChanges(changesRes);
    } catch (err: any) {
      console.error('ASM load failed:', err);
      setError(err?.message || 'Failed to load Attack Surface telemetry.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, []);

  // Filtered Assets
  const filteredAssets = useMemo(() => {
    return assets.filter((a) => {
      const matchSearch =
        searchQuery === '' ||
        a.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (a.domain_name && a.domain_name.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (a.ip_address && a.ip_address.includes(searchQuery)) ||
        a.owner.toLowerCase().includes(searchQuery.toLowerCase()) ||
        a.asset_id.toLowerCase().includes(searchQuery.toLowerCase());

      const matchType = selectedType === 'All' || a.asset_type === selectedType;
      const matchEnv = selectedEnv === 'All' || a.environment === selectedEnv;
      const matchCrit = selectedCriticality === 'All' || a.criticality === selectedCriticality;
      const matchExpo = selectedExposure === 'All' || a.exposure_level === selectedExposure;

      return matchSearch && matchType && matchEnv && matchCrit && matchExpo;
    });
  }, [assets, searchQuery, selectedType, selectedEnv, selectedCriticality, selectedExposure]);

  // Open Asset Slide-over
  const handleOpenAssetDetails = async (asset: ASMAsset) => {
    setSelectedAssetForDetails(asset);
    setDetailsLoading(true);
    setAiReport(null);
    try {
      const res = await api.get(`/asm/assets/${asset.id}`);
      setAssetFullDetails(res);
    } catch (err) {
      console.error('Error fetching asset details:', err);
    } finally {
      setDetailsLoading(false);
    }
  };

  // Close Asset Slide-over
  const handleCloseAssetDetails = () => {
    setSelectedAssetForDetails(null);
    setAssetFullDetails(null);
    setAiReport(null);
  };

  // Run Live DNS Check
  const handleRunDnsAssessment = async (domainToTest?: string) => {
    const target = domainToTest || dnsTargetDomain;
    if (!target) return;
    setDnsAssessing(true);
    try {
      const res = await api.post('/asm/dns/check', {
        domain: target.trim(),
        dkim_selector: dnsDkimSelector.trim() || 'default',
      });
      setDnsResult(res);
      setIsDnsModalOpen(true);
    } catch (err: any) {
      alert(`DNS Assessment failed: ${err?.message || 'Error occurred'}`);
    } finally {
      setDnsAssessing(false);
    }
  };

  // Refresh Certificate Check
  const handleRefreshCert = async (host: string, port: number = 443) => {
    try {
      const res = await api.post('/asm/certificates/check', { host, port });
      if (res.success) {
        alert(`Certificate inspection completed for ${host}: ${res.status} (${res.days_remaining} days remaining)`);
        loadDashboardData();
      } else {
        alert(`Failed to refresh certificate for ${host}: ${res.error || 'Unknown error'}`);
      }
    } catch (err: any) {
      alert(`Error refreshing certificate: ${err?.message}`);
    }
  };

  // Toggle Service Baseline
  const handleToggleServiceBaseline = async (serviceId: number, currentApproved: boolean) => {
    try {
      await api.patch(`/asm/services/${serviceId}`, {
        is_approved_baseline: !currentApproved,
        exposure_status: !currentApproved ? 'Approved Baseline' : 'Unexpected Exposure',
      });
      loadDashboardData();
    } catch (err: any) {
      alert(`Failed to update service baseline: ${err?.message}`);
    }
  };

  // Mark Change Log Reviewed
  const handleReviewChange = async (changeId: number) => {
    try {
      await api.patch(`/asm/changes/${changeId}/review`, { reviewer: 'SecOps Commander' });
      loadDashboardData();
    } catch (err: any) {
      alert(`Failed to review change log: ${err?.message}`);
    }
  };

  // Submit New Asset
  const handleCreateAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newAsset.name) return;
    try {
      await api.post('/asm/assets', newAsset);
      setIsAddAssetModalOpen(false);
      setNewAsset({
        name: '',
        asset_type: 'Web Application',
        domain_name: '',
        ip_address: '',
        environment: 'Production',
        owner: 'Security Operations',
        business_unit: 'Core Systems',
        criticality: 'High',
        exposure_level: 'Public Internet',
        discovery_source: 'Manual Registration',
      });
      loadDashboardData();
    } catch (err: any) {
      alert(`Failed to register asset: ${err?.message}`);
    }
  };

  // AI Explanation
  const handleGenerateAiExplanation = async (title: string, detail: string, type: string = 'exposure') => {
    setAiLoading(true);
    try {
      const res = await api.post('/asm/ai/explain', {
        type,
        title,
        detail,
      });
      setAiReport(res);
    } catch (err: any) {
      alert(`AI Analyst query failed: ${err?.message}`);
    } finally {
      setAiLoading(false);
    }
  };

  // Seed / Sync Demo Telemetry
  const handleSyncDemoTelemetry = async () => {
    try {
      setRefreshing(true);
      await api.post('/asm/demo/generate');
      await loadDashboardData();
    } catch (err: any) {
      alert(`Sync failed: ${err?.message}`);
    } finally {
      setRefreshing(false);
    }
  };

  // Prepare Chart Data
  const typeChartData = useMemo(() => {
    if (!stats?.asset_types_distribution) return [];
    return Object.entries(stats.asset_types_distribution).map(([name, value]) => ({ name, value }));
  }, [stats]);

  const exposureChartData = useMemo(() => {
    if (!stats?.exposure_distribution) return [];
    return Object.entries(stats.exposure_distribution).map(([name, value]) => ({ name, value }));
  }, [stats]);

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-[#070913]">
        <div className="flex flex-col items-center space-y-4">
          <div className="relative">
            <Globe className="w-12 h-12 text-cyan-400 animate-spin" />
            <div className="absolute inset-0 blur-lg bg-cyan-500/30 -z-10" />
          </div>
          <p className="text-sm font-mono text-cyan-400 tracking-wider">SYNCING AEGIS ATTACK SURFACE TELEMETRY...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#070913] text-slate-200 pb-20">
      {/* ──────────────────────────────────────────────
          Top Header Bar
      ────────────────────────────────────────────── */}
      <div className="border-b border-slate-800/80 bg-[#0a0e1c]/80 backdrop-blur-md sticky top-0 z-30 px-6 py-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <Globe className="w-6 h-6 animate-pulse" />
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <h1 className="text-xl font-bold tracking-tight text-white font-mono">
                    ATTACK SURFACE MANAGEMENT (ASM)
                  </h1>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-widest bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                    PERIMETER RADAR ACTIVE
                  </span>
                </div>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Authorized asset catalog, DNS hygiene (SPF/DKIM/DMARC), SSL/TLS drift & exposure auditing
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center flex-wrap gap-2.5">
            <button
              onClick={() => handleRunDnsAssessment('enterprise-defense.org')}
              className="flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-mono bg-purple-500/10 border border-purple-500/30 text-purple-300 hover:bg-purple-500/20 transition-all shadow-sm"
            >
              <Radio className="w-3.5 h-3.5" />
              <span>DNS Hygiene Scanner</span>
            </button>

            <button
              onClick={() => setIsAddAssetModalOpen(true)}
              className="flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-mono bg-cyan-500/20 border border-cyan-400/50 text-cyan-300 hover:bg-cyan-500/30 transition-all shadow-sm"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Register Asset</span>
            </button>

            <button
              onClick={handleSyncDemoTelemetry}
              disabled={refreshing}
              className="flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-mono bg-slate-800/80 border border-slate-700 text-slate-300 hover:bg-slate-700/80 transition-all"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-cyan-400' : ''}`} />
              <span>Sync Telemetry</span>
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex space-x-2 border-t border-slate-800/60 mt-4 pt-3 overflow-x-auto text-xs font-mono scrollbar-none">
          {[
            { id: 'overview', label: 'Posture Overview', count: undefined },
            { id: 'assets', label: 'Authorized Assets', count: stats?.total_assets },
            { id: 'domains', label: 'Domains & DNS', count: stats?.total_domains },
            { id: 'certs', label: 'SSL/TLS Certificates', count: stats?.total_certificates, alert: (stats?.expiring_certificates_count || 0) > 0 },
            { id: 'services', label: 'Exposed Services', count: stats?.total_services, alert: (stats?.unexpected_services_count || 0) > 0 },
            { id: 'changes', label: 'Perimeter Drift Log', count: stats?.active_change_events, alert: (stats?.active_change_events || 0) > 0 },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center space-x-2 px-3.5 py-2 rounded-md transition-all whitespace-nowrap ${
                activeTab === tab.id
                  ? 'bg-cyan-500/15 border-b-2 border-cyan-400 text-cyan-400 font-semibold shadow-inner'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <span>{tab.label}</span>
              {tab.count !== undefined && (
                <span
                  className={`px-1.5 py-0.2 rounded text-[10px] ${
                    tab.alert
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30 animate-pulse'
                      : 'bg-slate-800 text-slate-400 border border-slate-700'
                  }`}
                >
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">
        {/* Urgent Exposure Banner */}
        {((stats?.expiring_certificates_count || 0) > 0 || (stats?.unexpected_services_count || 0) > 0) && (
          <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-950/20 backdrop-blur flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg bg-rose-500/20 text-rose-400 border border-rose-500/40">
                <AlertOctagon className="w-5 h-5 animate-pulse" />
              </div>
              <div>
                <h4 className="text-sm font-semibold text-rose-300 font-mono">
                  ATTENTION: Perimeter Exposure Deviations Detected
                </h4>
                <p className="text-xs text-rose-200/70 mt-0.5">
                  {stats?.expiring_certificates_count} certificate(s) enter critical expiration windows &{' '}
                  {stats?.unexpected_services_count} port(s) exposed outside approved baseline configuration.
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              {(stats?.expiring_certificates_count || 0) > 0 && (
                <button
                  onClick={() => setActiveTab('certs')}
                  className="px-3 py-1.5 rounded-lg text-xs font-mono bg-rose-500/30 border border-rose-400/50 text-rose-200 hover:bg-rose-500/40 transition-all"
                >
                  Inspect Certificates ({stats?.expiring_certificates_count})
                </button>
              )}
              {(stats?.unexpected_services_count || 0) > 0 && (
                <button
                  onClick={() => setActiveTab('services')}
                  className="px-3 py-1.5 rounded-lg text-xs font-mono bg-amber-500/20 border border-amber-400/40 text-amber-200 hover:bg-amber-500/30 transition-all"
                >
                  Triage Services ({stats?.unexpected_services_count})
                </button>
              )}
            </div>
          </div>
        )}

        {/* ──────────────────────────────────────────────
            Top 6 KPI Summary Cards
        ────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
          {/* Card 1: Assets */}
          <div className="p-4 rounded-xl bg-[#0d1224] border border-slate-800 shadow-lg relative overflow-hidden group hover:border-cyan-500/40 transition-all">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Total Assets</span>
              <Server className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white font-mono">{stats?.total_assets || 0}</div>
            <p className="text-[10px] text-slate-400 mt-1 font-mono">
              {stats?.asset_types_distribution ? Object.keys(stats.asset_types_distribution).length : 0} distinct asset types
            </p>
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-500 to-transparent opacity-50" />
          </div>

          {/* Card 2: Domains */}
          <div className="p-4 rounded-xl bg-[#0d1224] border border-slate-800 shadow-lg relative overflow-hidden group hover:border-purple-500/40 transition-all">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Domains & Sub</span>
              <Globe className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-white font-mono">{stats?.total_domains || 0}</div>
            <p className="text-[10px] text-purple-400 mt-1 font-mono">100% Authorized</p>
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-purple-500 to-transparent opacity-50" />
          </div>

          {/* Card 3: Expiring Certs */}
          <div className="p-4 rounded-xl bg-[#0d1224] border border-slate-800 shadow-lg relative overflow-hidden group hover:border-rose-500/40 transition-all">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Expiring Certs</span>
              <Lock className="w-4 h-4 text-rose-400" />
            </div>
            <div className="text-2xl font-bold text-rose-400 font-mono">
              {stats?.expiring_certificates_count || 0}
            </div>
            <p className="text-[10px] text-slate-400 mt-1 font-mono">
              of {stats?.total_certificates || 0} monitored TLS certs
            </p>
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-rose-500 to-transparent opacity-50" />
          </div>

          {/* Card 4: Unexpected Services */}
          <div className="p-4 rounded-xl bg-[#0d1224] border border-slate-800 shadow-lg relative overflow-hidden group hover:border-amber-500/40 transition-all">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Exposed Services</span>
              <Activity className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold text-amber-400 font-mono">
              {stats?.unexpected_services_count || 0}
            </div>
            <p className="text-[10px] text-slate-400 mt-1 font-mono">
              deviations from baseline ({stats?.total_services || 0} total)
            </p>
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-amber-500 to-transparent opacity-50" />
          </div>

          {/* Card 5: Change Events */}
          <div className="p-4 rounded-xl bg-[#0d1224] border border-slate-800 shadow-lg relative overflow-hidden group hover:border-blue-500/40 transition-all">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Perimeter Drifts</span>
              <Zap className="w-4 h-4 text-blue-400" />
            </div>
            <div className="text-2xl font-bold text-blue-400 font-mono">
              {stats?.active_change_events || 0}
            </div>
            <p className="text-[10px] text-slate-400 mt-1 font-mono">pending review</p>
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-blue-500 to-transparent opacity-50" />
          </div>

          {/* Card 6: Mean Risk */}
          <div className="p-4 rounded-xl bg-[#0d1224] border border-slate-800 shadow-lg relative overflow-hidden group hover:border-emerald-500/40 transition-all">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">ASM Risk Score</span>
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-cyan-400">
              {stats?.average_attack_surface_risk || 0}
              <span className="text-xs text-slate-500 font-normal"> / 100</span>
            </div>
            <p className="text-[10px] text-slate-400 mt-1 font-mono">Weighted Perimeter Index</p>
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-emerald-500 to-transparent opacity-50" />
          </div>
        </div>

        {/* ──────────────────────────────────────────────
            TAB 1: POSTURE OVERVIEW
        ────────────────────────────────────────────── */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Visual Charts Row */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Asset Types Distribution */}
              <div className="p-5 rounded-xl bg-[#0d1224] border border-slate-800 shadow-lg">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-semibold text-white font-mono flex items-center space-x-2">
                    <Server className="w-4 h-4 text-cyan-400" />
                    <span>ASSET TYPE COMPOSITION</span>
                  </h3>
                  <span className="text-[10px] font-mono text-slate-400">Approved Inventory</span>
                </div>
                <div className="h-56">
                  {typeChartData.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={typeChartData}
                          dataKey="value"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          outerRadius={70}
                          innerRadius={40}
                          paddingAngle={4}
                          label={({ name, percent }: any) => `${(name || '').split(' ')[0]} ${((percent || 0) * 100).toFixed(0)}%`}
                        >
                          {typeChartData.map((entry, index) => (
                            <Cell key={`type-cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: '#070913', borderColor: '#1e293b', borderRadius: '8px', fontSize: '12px' }} />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex h-full items-center justify-center text-xs text-slate-500 font-mono">No data</div>
                  )}
                </div>
                <div className="flex flex-wrap gap-2 mt-2 justify-center">
                  {typeChartData.map((item, idx) => (
                    <span key={item.name} className="flex items-center space-x-1.5 text-[10px] font-mono text-slate-400">
                      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: CHART_COLORS[idx % CHART_COLORS.length] }} />
                      <span>{item.name}: {item.value}</span>
                    </span>
                  ))}
                </div>
              </div>

              {/* Exposure Level Breakdown */}
              <div className="p-5 rounded-xl bg-[#0d1224] border border-slate-800 shadow-lg">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-semibold text-white font-mono flex items-center space-x-2">
                    <Network className="w-4 h-4 text-purple-400" />
                    <span>EXPOSURE BOUNDARIES</span>
                  </h3>
                  <span className="text-[10px] font-mono text-slate-400">Perimeter Ingress</span>
                </div>
                <div className="h-56">
                  {exposureChartData.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={exposureChartData} layout="vertical" margin={{ left: 20, right: 20, top: 10, bottom: 10 }}>
                        <XAxis type="number" stroke="#475569" fontSize={10} />
                        <YAxis type="category" dataKey="name" stroke="#94a3b8" fontSize={11} width={90} />
                        <Tooltip contentStyle={{ backgroundColor: '#070913', borderColor: '#1e293b', borderRadius: '8px', fontSize: '12px' }} />
                        <Bar dataKey="value" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex h-full items-center justify-center text-xs text-slate-500 font-mono">No data</div>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 font-mono text-center mt-2">
                  Public Internet assets require mandatory TLS 1.3 & SPF/DMARC policies.
                </p>
              </div>

              {/* Certificate Expiration Urgency */}
              <div className="p-5 rounded-xl bg-[#0d1224] border border-slate-800 shadow-lg flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-sm font-semibold text-white font-mono flex items-center space-x-2">
                      <Lock className="w-4 h-4 text-rose-400" />
                      <span>EXPIRATION WINDOWS</span>
                    </h3>
                    <span className="text-[10px] font-mono text-rose-400">Action Required</span>
                  </div>
                  <div className="space-y-3">
                    {stats?.expiring_certificates && stats.expiring_certificates.length > 0 ? (
                      stats.expiring_certificates.slice(0, 3).map((c) => (
                        <div key={c.cert_id} className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                          <div>
                            <div className="text-xs font-mono font-semibold text-white truncate max-w-[170px]">
                              {c.domain_name}
                            </div>
                            <div className="text-[10px] font-mono text-slate-400">
                              Issuer: {c.issuer.split(' ')[0]}
                            </div>
                          </div>
                          <div className="text-right">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                                c.days_remaining <= 7
                                  ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse'
                                  : c.days_remaining <= 15
                                  ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                                  : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                              }`}
                            >
                              {c.days_remaining}d left
                            </span>
                            <div className="text-[9px] font-mono text-slate-500 mt-1">{c.tls_version}</div>
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-xs font-mono text-slate-400 text-center py-6">
                        No critical certificate expirations detected.
                      </div>
                    )}
                  </div>
                </div>

                <button
                  onClick={() => setActiveTab('certs')}
                  className="mt-4 w-full py-2 rounded-lg text-xs font-mono bg-slate-800/80 hover:bg-slate-700/80 text-cyan-300 border border-slate-700 flex items-center justify-center space-x-1.5 transition-all"
                >
                  <span>View All {stats?.total_certificates || 0} Certificates</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Critical Perimeter Assets & Recent Change Activity */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Critical Perimeter Assets */}
              <div className="p-5 rounded-xl bg-[#0d1224] border border-slate-800 shadow-lg">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-semibold text-white font-mono flex items-center space-x-2">
                    <ShieldAlert className="w-4 h-4 text-cyan-400" />
                    <span>HIGH-RISK PUBLIC PERIMETER ASSETS</span>
                  </h3>
                  <button
                    onClick={() => setActiveTab('assets')}
                    className="text-xs font-mono text-cyan-400 hover:underline flex items-center space-x-1"
                  >
                    <span>Full Catalog</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2">Asset</th>
                        <th className="py-2">Type</th>
                        <th className="py-2">IP / Domain</th>
                        <th className="py-2 text-right">Risk Score</th>
                        <th className="py-2 text-center">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {stats?.critical_perimeter_assets && stats.critical_perimeter_assets.length > 0 ? (
                        stats.critical_perimeter_assets.map((asset) => (
                          <tr key={asset.id} className="hover:bg-slate-800/30 transition-all">
                            <td className="py-2.5">
                              <div className="font-semibold text-white">{asset.name}</div>
                              <div className="text-[10px] text-slate-500">{asset.asset_id}</div>
                            </td>
                            <td className="py-2.5 text-slate-300">{asset.asset_type}</td>
                            <td className="py-2.5">
                              <div className="text-cyan-400 truncate max-w-[140px]">{asset.domain_name || 'N/A'}</div>
                              <div className="text-[10px] text-slate-400">{asset.ip_address || 'N/A'}</div>
                            </td>
                            <td className="py-2.5 text-right font-bold text-rose-400">
                              {asset.risk_score}
                            </td>
                            <td className="py-2.5 text-center">
                              <button
                                onClick={() => handleOpenAssetDetails(asset)}
                                className="px-2 py-1 rounded bg-slate-800 hover:bg-cyan-500/20 text-cyan-300 border border-slate-700 text-[10px]"
                              >
                                Inspect
                              </button>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={5} className="py-4 text-center text-slate-500">
                            No critical assets cataloged.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Attack Surface Change Stream */}
              <div className="p-5 rounded-xl bg-[#0d1224] border border-slate-800 shadow-lg">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-semibold text-white font-mono flex items-center space-x-2">
                    <Radio className="w-4 h-4 text-amber-400" />
                    <span>LATEST PERIMETER DRIFT EVENTS</span>
                  </h3>
                  <button
                    onClick={() => setActiveTab('changes')}
                    className="text-xs font-mono text-cyan-400 hover:underline flex items-center space-x-1"
                  >
                    <span>Full Log</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="space-y-3">
                  {stats?.recent_changes && stats.recent_changes.length > 0 ? (
                    stats.recent_changes.slice(0, 4).map((chg) => (
                      <div
                        key={chg.change_id}
                        className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80 flex items-start justify-between space-x-3"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center space-x-2">
                            <span
                              className={`px-1.5 py-0.2 rounded text-[9px] font-mono uppercase font-bold ${
                                chg.severity === 'Critical'
                                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                                  : chg.severity === 'High'
                                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                                  : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                              }`}
                            >
                              {chg.severity}
                            </span>
                            <span className="text-xs font-mono font-semibold text-slate-200">
                              {chg.change_type}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-400 font-mono">{chg.description}</p>
                          <div className="text-[10px] text-slate-500 font-mono">
                            Target: {chg.asset_name} • {new Date(chg.timestamp).toLocaleString()}
                          </div>
                        </div>

                        {!chg.reviewed && (
                          <button
                            onClick={() => handleReviewChange(chg.id)}
                            className="px-2 py-1 rounded bg-slate-800 hover:bg-emerald-500/20 text-slate-300 hover:text-emerald-300 border border-slate-700 text-[10px] whitespace-nowrap font-mono"
                          >
                            Mark Reviewed
                          </button>
                        )}
                      </div>
                    ))
                  ) : (
                    <div className="text-xs font-mono text-slate-500 text-center py-6">
                      No recent perimeter changes recorded.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ──────────────────────────────────────────────
            TAB 2: AUTHORIZED ASSET INVENTORY (TOOL 1)
        ────────────────────────────────────────────── */}
        {activeTab === 'assets' && (
          <div className="space-y-4">
            {/* Filter & Search Bar */}
            <div className="p-4 rounded-xl bg-[#0d1224] border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-3 font-mono text-xs">
              <div className="relative w-full md:w-80">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Search asset, domain, IP, owner..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
                <select
                  value={selectedType}
                  onChange={(e) => setSelectedType(e.target.value)}
                  className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-2 text-slate-300 focus:outline-none focus:border-cyan-400"
                >
                  <option value="All">All Types</option>
                  <option value="Web Application">Web Application</option>
                  <option value="API">API Gateway</option>
                  <option value="Cloud Asset">Cloud Asset</option>
                  <option value="Network Device">Network Device</option>
                  <option value="Database">Database</option>
                </select>

                <select
                  value={selectedEnv}
                  onChange={(e) => setSelectedEnv(e.target.value)}
                  className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-2 text-slate-300 focus:outline-none focus:border-cyan-400"
                >
                  <option value="All">All Envs</option>
                  <option value="Production">Production</option>
                  <option value="Staging">Staging</option>
                  <option value="Development">Development</option>
                </select>

                <select
                  value={selectedCriticality}
                  onChange={(e) => setSelectedCriticality(e.target.value)}
                  className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-2 text-slate-300 focus:outline-none focus:border-cyan-400"
                >
                  <option value="All">All Criticalities</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>

                <select
                  value={selectedExposure}
                  onChange={(e) => setSelectedExposure(e.target.value)}
                  className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-2 text-slate-300 focus:outline-none focus:border-cyan-400"
                >
                  <option value="All">All Exposure</option>
                  <option value="Public Internet">Public Internet</option>
                  <option value="DMZ">DMZ</option>
                  <option value="Internal">Internal</option>
                </select>

                <button
                  onClick={() => setIsAddAssetModalOpen(true)}
                  className="px-3 py-2 rounded-lg bg-cyan-500/20 border border-cyan-400/50 text-cyan-300 hover:bg-cyan-500/30 flex items-center space-x-1.5 transition-all"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Register Asset</span>
                </button>
              </div>
            </div>

            {/* Assets Table */}
            <div className="p-5 rounded-xl bg-[#0d1224] border border-slate-800 shadow-lg overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                    <th className="py-3 px-3">Asset Name & ID</th>
                    <th className="py-3 px-3">Type</th>
                    <th className="py-3 px-3">Perimeter Ingress (Domain / IP)</th>
                    <th className="py-3 px-3">Environment</th>
                    <th className="py-3 px-3">Criticality</th>
                    <th className="py-3 px-3">Exposure</th>
                    <th className="py-3 px-3">Risk Score</th>
                    <th className="py-3 px-3">Owner & BU</th>
                    <th className="py-3 px-3 text-center">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredAssets.length > 0 ? (
                    filteredAssets.map((asset) => (
                      <tr key={asset.id} className="hover:bg-slate-800/40 transition-all">
                        <td className="py-3 px-3">
                          <div className="font-semibold text-white">{asset.name}</div>
                          <div className="text-[10px] text-cyan-400 font-mono">{asset.asset_id}</div>
                        </td>
                        <td className="py-3 px-3 text-slate-300">{asset.asset_type}</td>
                        <td className="py-3 px-3">
                          <div className="text-cyan-400 truncate max-w-[170px]">{asset.domain_name || '—'}</div>
                          <div className="text-[10px] text-slate-400">{asset.ip_address || '—'}</div>
                        </td>
                        <td className="py-3 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] ${
                              asset.environment === 'Production'
                                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                                : 'bg-slate-800 text-slate-300 border border-slate-700'
                            }`}
                          >
                            {asset.environment}
                          </span>
                        </td>
                        <td className="py-3 px-3">
                          <span
                            className="px-2 py-0.5 rounded text-[10px] font-bold"
                            style={{
                              backgroundColor: `${CRITICALITY_COLORS[asset.criticality] || '#06b6d4'}20`,
                              color: CRITICALITY_COLORS[asset.criticality] || '#06b6d4',
                              border: `1px solid ${CRITICALITY_COLORS[asset.criticality] || '#06b6d4'}40`,
                            }}
                          >
                            {asset.criticality}
                          </span>
                        </td>
                        <td className="py-3 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] ${
                              asset.exposure_level === 'Public Internet'
                                ? 'bg-rose-500/10 text-rose-300 border border-rose-500/30'
                                : 'bg-blue-500/10 text-blue-300 border border-blue-500/30'
                            }`}
                          >
                            {asset.exposure_level}
                          </span>
                        </td>
                        <td className="py-3 px-3 font-bold font-mono">
                          <span
                            className={`${
                              asset.risk_score >= 70
                                ? 'text-rose-400'
                                : asset.risk_score >= 40
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            }`}
                          >
                            {asset.risk_score}
                          </span>
                        </td>
                        <td className="py-3 px-3">
                          <div className="text-slate-200">{asset.owner}</div>
                          <div className="text-[10px] text-slate-500">{asset.business_unit}</div>
                        </td>
                        <td className="py-3 px-3 text-center">
                          <div className="flex items-center justify-center space-x-1.5">
                            <button
                              onClick={() => handleOpenAssetDetails(asset)}
                              className="px-2 py-1 rounded bg-slate-800 hover:bg-cyan-500/20 text-cyan-300 border border-slate-700 text-[10px]"
                            >
                              Inspect
                            </button>
                            {asset.domain_name && (
                              <button
                                onClick={() => handleRunDnsAssessment(asset.domain_name)}
                                title="Run DNS assessment"
                                className="p-1 rounded bg-slate-800 hover:bg-purple-500/20 text-purple-300 border border-slate-700 text-[10px]"
                              >
                                <Radio className="w-3.5 h-3.5" />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={9} className="py-6 text-center text-slate-500">
                        No assets match active filters.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ──────────────────────────────────────────────
            TAB 3: DOMAINS & DNS HYGIENE (TOOL 2 & 3)
        ────────────────────────────────────────────── */}
        {activeTab === 'domains' && (
          <div className="space-y-6">
            {/* Live DNS Hygiene Run Box */}
            <div className="p-5 rounded-xl bg-gradient-to-r from-[#0d1224] to-[#121833] border border-cyan-500/30 shadow-lg">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm font-bold text-cyan-300 font-mono flex items-center space-x-2">
                    <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
                    <span>DEFENSIVE DNS & EMAIL SECURITY AUDITOR</span>
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-1">
                    Query authoritative DNS records, validate SPF anti-spoofing policy, DMARC alignment, DKIM selector, and CAA tags.
                  </p>
                </div>

                <div className="flex items-center space-x-2">
                  <input
                    type="text"
                    value={dnsTargetDomain}
                    onChange={(e) => setDnsTargetDomain(e.target.value)}
                    placeholder="e.g. enterprise-defense.org"
                    className="px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 w-56"
                  />
                  <input
                    type="text"
                    value={dnsDkimSelector}
                    onChange={(e) => setDnsDkimSelector(e.target.value)}
                    placeholder="DKIM sel"
                    className="px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 w-24"
                  />
                  <button
                    onClick={() => handleRunDnsAssessment()}
                    disabled={dnsAssessing}
                    className="px-3 py-1.5 rounded-lg text-xs font-mono bg-cyan-500/20 border border-cyan-400/50 text-cyan-300 hover:bg-cyan-500/30 flex items-center space-x-1.5 transition-all shadow-sm"
                  >
                    {dnsAssessing ? <RotateCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                    <span>Assess DNS</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Domains Table */}
            <div className="p-5 rounded-xl bg-[#0d1224] border border-slate-800 shadow-lg overflow-x-auto">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-semibold text-white font-mono flex items-center space-x-2">
                  <Globe className="w-4 h-4 text-purple-400" />
                  <span>AUTHORIZED DOMAIN & SUBDOMAIN REGISTRY</span>
                </h3>
                <span className="text-xs font-mono text-slate-400">{domains.length} Registered FQDNs</span>
              </div>

              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                    <th className="py-3 px-3">Domain ID</th>
                    <th className="py-3 px-3">Subdomain / Apex</th>
                    <th className="py-3 px-3">Root Domain</th>
                    <th className="py-3 px-3">IP Mappings</th>
                    <th className="py-3 px-3">CNAME Target</th>
                    <th className="py-3 px-3">DNS Status</th>
                    <th className="py-3 px-3">Discovered Via</th>
                    <th className="py-3 px-3 text-center">DNS Scan</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {domains.map((dom) => (
                    <tr key={dom.id} className="hover:bg-slate-800/40 transition-all">
                      <td className="py-3 px-3 text-cyan-400 font-bold">{dom.domain_id}</td>
                      <td className="py-3 px-3">
                        <div className="font-semibold text-white flex items-center space-x-1.5">
                          <span>{dom.subdomain}</span>
                          {dom.is_apex && (
                            <span className="px-1.5 py-0.2 rounded text-[9px] bg-purple-500/20 text-purple-300 border border-purple-500/30">
                              Apex
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-3 text-slate-400">{dom.root_domain}</td>
                      <td className="py-3 px-3 text-slate-300">
                        {dom.ip_addresses && dom.ip_addresses.length > 0 ? dom.ip_addresses.join(', ') : '—'}
                      </td>
                      <td className="py-3 px-3 text-slate-400 truncate max-w-[160px]">
                        {dom.cname_target || '—'}
                      </td>
                      <td className="py-3 px-3">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                          {dom.dns_status}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-slate-400">{dom.discovered_via}</td>
                      <td className="py-3 px-3 text-center">
                        <button
                          onClick={() => handleRunDnsAssessment(dom.subdomain)}
                          className="px-2 py-1 rounded bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 text-[10px] inline-flex items-center space-x-1"
                        >
                          <Radio className="w-3 h-3" />
                          <span>Assess</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ──────────────────────────────────────────────
            TAB 4: SSL/TLS CERTIFICATE MONITOR (TOOL 4)
        ────────────────────────────────────────────── */}
        {activeTab === 'certs' && (
          <div className="space-y-4">
            <div className="p-5 rounded-xl bg-[#0d1224] border border-slate-800 shadow-lg overflow-x-auto">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-semibold text-white font-mono flex items-center space-x-2">
                    <Lock className="w-4 h-4 text-cyan-400" />
                    <span>SSL/TLS CERTIFICATE EXPIRATION & PROTOCOL AUDIT</span>
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    Real-time tracking of public ingress certificates, cipher suites, SAN coverage, and chain trust.
                  </p>
                </div>
                <span className="text-xs font-mono text-slate-400">{certificates.length} Monitored Endpoints</span>
              </div>

              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                    <th className="py-3 px-3">Cert ID</th>
                    <th className="py-3 px-3">Hostname & Port</th>
                    <th className="py-3 px-3">Issuer CA</th>
                    <th className="py-3 px-3">TLS & Cipher</th>
                    <th className="py-3 px-3">Expiration Date</th>
                    <th className="py-3 px-3">Days Remaining</th>
                    <th className="py-3 px-3">Status</th>
                    <th className="py-3 px-3">Chain Trust</th>
                    <th className="py-3 px-3 text-center">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {certificates.map((cert) => (
                    <tr key={cert.id} className="hover:bg-slate-800/40 transition-all">
                      <td className="py-3 px-3 text-cyan-400 font-bold">{cert.cert_id}</td>
                      <td className="py-3 px-3">
                        <div className="font-semibold text-white">{cert.domain_name}</div>
                        <div className="text-[10px] text-slate-400">Port {cert.port}</div>
                      </td>
                      <td className="py-3 px-3 text-slate-300 truncate max-w-[150px]">{cert.issuer}</td>
                      <td className="py-3 px-3">
                        <div className="text-slate-200">{cert.tls_version}</div>
                        <div className="text-[10px] text-slate-500 truncate max-w-[140px]">
                          {cert.cipher_suite || 'ECDHE-RSA-AES256'}
                        </div>
                      </td>
                      <td className="py-3 px-3 text-slate-400">
                        {new Date(cert.valid_to).toLocaleDateString()}
                      </td>
                      <td className="py-3 px-3 font-bold font-mono">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] ${
                            cert.days_remaining <= 7
                              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40 animate-pulse'
                              : cert.days_remaining <= 15
                              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                              : cert.days_remaining <= 30
                              ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40'
                              : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                          }`}
                        >
                          {cert.days_remaining} days
                        </span>
                      </td>
                      <td className="py-3 px-3 text-slate-300">{cert.status}</td>
                      <td className="py-3 px-3">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                          {cert.chain_status}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-center">
                        <button
                          onClick={() => handleRefreshCert(cert.domain_name, cert.port)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-500/20 text-cyan-300 border border-slate-700 text-[10px] inline-flex items-center space-x-1"
                        >
                          <RotateCw className="w-3 h-3" />
                          <span>Re-check</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ──────────────────────────────────────────────
            TAB 5: EXPOSED SERVICES & BASELINES (TOOL 5)
        ────────────────────────────────────────────── */}
        {activeTab === 'services' && (
          <div className="space-y-4">
            <div className="p-5 rounded-xl bg-[#0d1224] border border-slate-800 shadow-lg overflow-x-auto">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-semibold text-white font-mono flex items-center space-x-2">
                    <Activity className="w-4 h-4 text-amber-400" />
                    <span>PERIMETER NETWORK SERVICES & BASELINE COMPLIANCE</span>
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    Audit open ports across registered assets against approved network baselines to detect unauthorized exposure.
                  </p>
                </div>
                <span className="text-xs font-mono text-slate-400">{services.length} Monitored Ingress Ports</span>
              </div>

              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                    <th className="py-3 px-3">Service ID</th>
                    <th className="py-3 px-3">Asset & Hostname</th>
                    <th className="py-3 px-3">Port & Protocol</th>
                    <th className="py-3 px-3">Identified Service</th>
                    <th className="py-3 px-3">Software / Banner</th>
                    <th className="py-3 px-3">Baseline Compliance</th>
                    <th className="py-3 px-3">Risk Level</th>
                    <th className="py-3 px-3 text-center">Triage Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {services.map((srv) => (
                    <tr key={srv.id} className="hover:bg-slate-800/40 transition-all">
                      <td className="py-3 px-3 text-cyan-400 font-bold">{srv.service_id}</td>
                      <td className="py-3 px-3">
                        <div className="font-semibold text-white">{srv.hostname}</div>
                        <div className="text-[10px] text-slate-400">{srv.ip_address}</div>
                      </td>
                      <td className="py-3 px-3">
                        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300 font-bold">
                          {srv.port} / {srv.protocol}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-slate-200">{srv.service_name}</td>
                      <td className="py-3 px-3 text-slate-400">{srv.version || 'Unreported'}</td>
                      <td className="py-3 px-3">
                        {srv.is_approved_baseline ? (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 inline-flex items-center space-x-1">
                            <CheckCircle2 className="w-3 h-3" />
                            <span>Approved Baseline</span>
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/40 inline-flex items-center space-x-1 animate-pulse">
                            <AlertTriangle className="w-3 h-3" />
                            <span>Unexpected Exposure</span>
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-3 font-bold">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] ${
                            srv.risk_level === 'Critical'
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                              : srv.risk_level === 'High'
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                              : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                          }`}
                        >
                          {srv.risk_level}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-center">
                        <button
                          onClick={() => handleToggleServiceBaseline(srv.id, srv.is_approved_baseline)}
                          className={`px-2.5 py-1 rounded text-[10px] font-mono border transition-all ${
                            srv.is_approved_baseline
                              ? 'bg-slate-800 hover:bg-rose-500/20 text-slate-400 hover:text-rose-300 border-slate-700'
                              : 'bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border-emerald-500/40'
                          }`}
                        >
                          {srv.is_approved_baseline ? 'Flag Unexpected' : 'Approve Baseline'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ──────────────────────────────────────────────
            TAB 6: PERIMETER DRIFT & CHANGE AUDIT (TOOL 7)
        ────────────────────────────────────────────── */}
        {activeTab === 'changes' && (
          <div className="space-y-4">
            <div className="p-5 rounded-xl bg-[#0d1224] border border-slate-800 shadow-lg overflow-x-auto">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-semibold text-white font-mono flex items-center space-x-2">
                    <Zap className="w-4 h-4 text-cyan-400" />
                    <span>ATTACK SURFACE AUDIT TRAIL & PERIMETER DRIFT</span>
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    Immutable chronological audit log capturing new assets, DNS modifications, expiring certs, and unexpected port exposures.
                  </p>
                </div>
                <span className="text-xs font-mono text-slate-400">{changes.length} Recorded Events</span>
              </div>

              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                    <th className="py-3 px-3">Change ID</th>
                    <th className="py-3 px-3">Timestamp</th>
                    <th className="py-3 px-3">Target Asset</th>
                    <th className="py-3 px-3">Change Event Type</th>
                    <th className="py-3 px-3">Severity</th>
                    <th className="py-3 px-3">Description & Diff</th>
                    <th className="py-3 px-3">Status</th>
                    <th className="py-3 px-3 text-center">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {changes.map((chg) => (
                    <tr key={chg.id} className="hover:bg-slate-800/40 transition-all">
                      <td className="py-3 px-3 text-cyan-400 font-bold">{chg.change_id}</td>
                      <td className="py-3 px-3 text-slate-400">
                        {new Date(chg.timestamp).toLocaleString()}
                      </td>
                      <td className="py-3 px-3 font-semibold text-white">{chg.asset_name}</td>
                      <td className="py-3 px-3 text-slate-300 font-medium">{chg.change_type}</td>
                      <td className="py-3 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            chg.severity === 'Critical'
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                              : chg.severity === 'High'
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                              : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                          }`}
                        >
                          {chg.severity}
                        </span>
                      </td>
                      <td className="py-3 px-3 max-w-sm">
                        <div className="text-slate-300">{chg.description}</div>
                        {chg.previous_value && chg.current_value && (
                          <div className="text-[10px] text-slate-500 mt-0.5">
                            <span className="text-rose-400/80">{chg.previous_value}</span> →{' '}
                            <span className="text-emerald-400/80">{chg.current_value}</span>
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-3">
                        {chg.reviewed ? (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                            Reviewed ({chg.reviewed_by?.split(' ')[0] || 'Analyst'})
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse">
                            Pending Review
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-center">
                        {!chg.reviewed ? (
                          <button
                            onClick={() => handleReviewChange(chg.id)}
                            className="px-2 py-1 rounded bg-slate-800 hover:bg-emerald-500/20 text-emerald-300 border border-slate-700 text-[10px]"
                          >
                            Mark Reviewed
                          </button>
                        ) : (
                          <span className="text-slate-500 text-[10px]">Archived</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* ──────────────────────────────────────────────
          SLIDE-OVER ASSET DEEP INSPECTOR
      ────────────────────────────────────────────── */}
      {selectedAssetForDetails && (
        <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-2xl bg-[#090d1e] border-l border-slate-800 h-full overflow-y-auto p-6 space-y-6 shadow-2xl">
            {/* Header */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center space-x-2">
                  <h3 className="text-base font-bold text-white font-mono">{selectedAssetForDetails.name}</h3>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-mono">
                    {selectedAssetForDetails.asset_id}
                  </span>
                </div>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Deep Attack Surface Profile & Associated Telemetry
                </p>
              </div>
              <button
                onClick={handleCloseAssetDetails}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Core Specs Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase">Criticality</span>
                <p className="font-bold text-rose-400 mt-0.5">{selectedAssetForDetails.criticality}</p>
              </div>
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase">Risk Score</span>
                <p className="font-bold text-cyan-400 mt-0.5">{selectedAssetForDetails.risk_score} / 100</p>
              </div>
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase">Environment</span>
                <p className="font-bold text-purple-400 mt-0.5">{selectedAssetForDetails.environment}</p>
              </div>
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase">Exposure</span>
                <p className="font-bold text-slate-200 mt-0.5">{selectedAssetForDetails.exposure_level}</p>
              </div>
            </div>

            {/* Ingress Network Details */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2 text-xs font-mono">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                <Globe className="w-4 h-4 text-cyan-400" />
                <span>Network Coordinates</span>
              </h4>
              <div className="grid grid-cols-2 gap-2 text-slate-400">
                <div>Domain: <span className="text-white font-semibold">{selectedAssetForDetails.domain_name || 'N/A'}</span></div>
                <div>IP Address: <span className="text-white font-semibold">{selectedAssetForDetails.ip_address || 'N/A'}</span></div>
                <div>Owner: <span className="text-white font-semibold">{selectedAssetForDetails.owner}</span></div>
                <div>Business Unit: <span className="text-white font-semibold">{selectedAssetForDetails.business_unit}</span></div>
              </div>
            </div>

            {/* Associated Certificate */}
            {assetFullDetails?.certificate && (
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                    <Lock className="w-4 h-4 text-cyan-400" />
                    <span>Attached TLS Certificate</span>
                  </h4>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/40">
                    {assetFullDetails.certificate.days_remaining}d remaining
                  </span>
                </div>
                <div className="text-slate-400 space-y-1">
                  <div>Issuer: <span className="text-white">{assetFullDetails.certificate.issuer}</span></div>
                  <div>Protocol: <span className="text-white">{assetFullDetails.certificate.tls_version}</span></div>
                  <div>Cipher: <span className="text-slate-300">{assetFullDetails.certificate.cipher_suite || 'Default Strong'}</span></div>
                </div>
              </div>
            )}

            {/* Discovered Services */}
            {assetFullDetails?.services && assetFullDetails.services.length > 0 && (
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3 text-xs font-mono">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                  <Activity className="w-4 h-4 text-amber-400" />
                  <span>Open Perimeter Services ({assetFullDetails.services.length})</span>
                </h4>
                <div className="space-y-2">
                  {assetFullDetails.services.map((s: any) => (
                    <div key={s.id} className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                      <div>
                        <div className="font-bold text-white">
                          Port {s.port} ({s.service_name})
                        </div>
                        <div className="text-[10px] text-slate-500">{s.version || 'No Banner'}</div>
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] ${
                          s.is_approved_baseline
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                            : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                        }`}
                      >
                        {s.exposure_status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* AI Threat Analysis & Hardening Playbook */}
            <div className="p-5 rounded-xl bg-gradient-to-tr from-cyan-950/30 to-purple-950/20 border border-cyan-500/30 space-y-3 font-mono">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-cyan-300 uppercase tracking-wider flex items-center space-x-2">
                  <Sparkles className="w-4 h-4 text-cyan-400 animate-pulse" />
                  <span>AI Threat Analysis & Hardening Playbook</span>
                </h4>
                <button
                  onClick={() =>
                    handleGenerateAiExplanation(
                      selectedAssetForDetails.name,
                      `Asset ${selectedAssetForDetails.name} has criticality ${selectedAssetForDetails.criticality} with exposure level ${selectedAssetForDetails.exposure_level} and risk score ${selectedAssetForDetails.risk_score}.`
                    )
                  }
                  disabled={aiLoading}
                  className="px-2.5 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-400/40 text-[10px] flex items-center space-x-1"
                >
                  {aiLoading ? <RotateCw className="w-3 h-3 animate-spin" /> : <Sparkles className="w-3 h-3" />}
                  <span>Generate Brief</span>
                </button>
              </div>

              {aiReport ? (
                <div className="p-4 rounded-lg bg-slate-950/90 border border-slate-800 text-xs text-slate-300 whitespace-pre-line leading-relaxed">
                  {aiReport.analysis}
                </div>
              ) : (
                <p className="text-xs text-slate-400">
                  Click &apos;Generate Brief&apos; to invoke the Aegis AI Analyst for perimeter threat intelligence, exploitability insights, and defense playbooks.
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ──────────────────────────────────────────────
          DNS INSPECTOR MODAL
      ────────────────────────────────────────────── */}
      {isDnsModalOpen && dnsResult && (
        <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-2xl bg-[#090d1e] border border-cyan-500/40 rounded-2xl shadow-2xl p-6 space-y-5 font-mono max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Radio className="w-5 h-5 text-cyan-400 animate-pulse" />
                <h3 className="text-sm font-bold text-white">
                  DNS SECURITY & HYGIENE ASSESSMENT // {dnsResult.domain}
                </h3>
              </div>
              <button
                onClick={() => setIsDnsModalOpen(false)}
                className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Scorecard Badges */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-center">
                <span className="text-[10px] text-slate-500 uppercase">SPF Policy</span>
                <p
                  className={`font-bold mt-1 ${
                    dnsResult.spf?.status === 'PASS' ? 'text-emerald-400' : 'text-amber-400'
                  }`}
                >
                  {dnsResult.spf?.status || 'FAIL'}
                </p>
              </div>

              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-center">
                <span className="text-[10px] text-slate-500 uppercase">DMARC Policy</span>
                <p
                  className={`font-bold mt-1 ${
                    dnsResult.dmarc?.status === 'PASS' ? 'text-emerald-400' : 'text-amber-400'
                  }`}
                >
                  {dnsResult.dmarc?.policy ? `p=${dnsResult.dmarc.policy}` : 'MISSING'}
                </p>
              </div>

              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-center">
                <span className="text-[10px] text-slate-500 uppercase">CAA Records</span>
                <p
                  className={`font-bold mt-1 ${
                    (dnsResult.caa?.status === 'Configured' || dnsResult.caa?.configured) ? 'text-emerald-400' : 'text-slate-400'
                  }`}
                >
                  {(dnsResult.caa?.status === 'Configured' || dnsResult.caa?.configured) ? 'PRESENT' : 'NONE'}
                </p>
              </div>

              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-center">
                <span className="text-[10px] text-slate-500 uppercase">DKIM Selector</span>
                <p
                  className={`font-bold mt-1 ${
                    dnsResult.dkim?.status === 'PASS' ? 'text-emerald-400' : 'text-slate-400'
                  }`}
                >
                  {dnsResult.dkim?.status || 'UNKNOWN'}
                </p>
              </div>
            </div>

            {/* Raw Records */}
            <div className="space-y-3 text-xs">
              <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-[10px] text-slate-400 uppercase font-bold">A Records:</span>
                <p className="text-cyan-300">
                  {dnsResult.a_records?.join(', ') || dnsResult.records?.A?.join(', ') || 'None found'}
                </p>
              </div>

              {dnsResult.spf?.record && (
                <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-[10px] text-slate-400 uppercase font-bold">Raw SPF Record:</span>
                  <p className="text-emerald-300 break-all">{dnsResult.spf.record}</p>
                </div>
              )}

              {dnsResult.dmarc?.record && (
                <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-[10px] text-slate-400 uppercase font-bold">Raw DMARC Record:</span>
                  <p className="text-purple-300 break-all">{dnsResult.dmarc.record}</p>
                </div>
              )}

              {/* Recommendations / Concerns */}
              {(dnsResult.recommendations || dnsResult.concerns) && (dnsResult.recommendations || dnsResult.concerns).length > 0 && (
                <div className="p-3 rounded bg-amber-950/20 border border-amber-500/30 space-y-1.5">
                  <span className="text-[10px] text-amber-300 uppercase font-bold flex items-center space-x-1">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                    <span>Hardening Recommendations & Findings:</span>
                  </span>
                  <ul className="list-disc pl-4 text-slate-300 space-y-1">
                    {(dnsResult.recommendations || dnsResult.concerns).map((rec: string, i: number) => (
                      <li key={i}>{rec}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setIsDnsModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-white"
              >
                Close Report
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ──────────────────────────────────────────────
          REGISTER ASSET MODAL
      ────────────────────────────────────────────── */}
      {isAddAssetModalOpen && (
        <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-[#090d1e] border border-cyan-500/40 rounded-2xl shadow-2xl p-6 space-y-4 font-mono">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Plus className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold text-white">REGISTER AUTHORIZED ASSET</h3>
              </div>
              <button
                onClick={() => setIsAddAssetModalOpen(false)}
                className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateAsset} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Asset Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Payment Gateway ALB"
                  value={newAsset.name}
                  onChange={(e) => setNewAsset({ ...newAsset, name: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Asset Type</label>
                  <select
                    value={newAsset.asset_type}
                    onChange={(e) => setNewAsset({ ...newAsset, asset_type: e.target.value })}
                    className="w-full px-2.5 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
                  >
                    <option value="Web Application">Web Application</option>
                    <option value="API">API Gateway</option>
                    <option value="Cloud Asset">Cloud Asset</option>
                    <option value="Network Device">Network Device</option>
                    <option value="Database">Database</option>
                  </select>
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Criticality</label>
                  <select
                    value={newAsset.criticality}
                    onChange={(e) => setNewAsset({ ...newAsset, criticality: e.target.value })}
                    className="w-full px-2.5 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
                  >
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Domain Name</label>
                  <input
                    type="text"
                    placeholder="e.g. pay.enterprise-defense.org"
                    value={newAsset.domain_name}
                    onChange={(e) => setNewAsset({ ...newAsset, domain_name: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">IP Address</label>
                  <input
                    type="text"
                    placeholder="e.g. 198.51.100.55"
                    value={newAsset.ip_address}
                    onChange={(e) => setNewAsset({ ...newAsset, ip_address: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Environment</label>
                  <select
                    value={newAsset.environment}
                    onChange={(e) => setNewAsset({ ...newAsset, environment: e.target.value })}
                    className="w-full px-2.5 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
                  >
                    <option value="Production">Production</option>
                    <option value="Staging">Staging</option>
                    <option value="Development">Development</option>
                  </select>
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Exposure Level</label>
                  <select
                    value={newAsset.exposure_level}
                    onChange={(e) => setNewAsset({ ...newAsset, exposure_level: e.target.value })}
                    className="w-full px-2.5 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
                  >
                    <option value="Public Internet">Public Internet</option>
                    <option value="DMZ">DMZ</option>
                    <option value="Internal">Internal</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Owner</label>
                  <input
                    type="text"
                    value={newAsset.owner}
                    onChange={(e) => setNewAsset({ ...newAsset, owner: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Business Unit</label>
                  <input
                    type="text"
                    value={newAsset.business_unit}
                    onChange={(e) => setNewAsset({ ...newAsset, business_unit: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-cyan-400"
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-2 pt-3">
                <button
                  type="button"
                  onClick={() => setIsAddAssetModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-400/50"
                >
                  Save Asset
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
