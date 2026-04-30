/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  Play, 
  Square, 
  Trash2, 
  Activity, 
  Cpu, 
  Zap,
  Terminal,
  ChevronRight,
  AlertTriangle,
  BookOpen,
  Filter,
  CheckCircle2,
  XCircle,
  Network,
  Clock
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell
} from 'recharts';
import { cn } from './lib/utils';
import { Packet, Protocol, Alert, Severity, DetectionRules } from './types';
import { generateRandomPacket } from './utils/packetGenerator';

export default function App() {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isCapturing, setIsCapturing] = useState(false);
  const [activeTab, setActiveTab] = useState<'dashboard' | 'research'>('dashboard');
  const [filter, setFilter] = useState<Severity | 'ALL'>('ALL');
  const [rules, setRules] = useState<DetectionRules>({
    portScan: true,
    synFlood: true,
    icmpFlood: true,
    bruteForce: true,
    arpSpoofing: true
  });
  
  const scrollRef = useRef<HTMLDivElement>(null);

  // Generate background traffic and detect intrusions
  useEffect(() => {
    let interval: any;
    if (isCapturing) {
      interval = setInterval(() => {
        const newPacket = generateRandomPacket();
        setPackets(prev => [...prev.slice(-100), newPacket]);

        // Simulated Detection Logic
        if (newPacket.protocol === 'TCP' && newPacket.info.includes('SYN') && rules.synFlood && Math.random() > 0.96) {
          addAlert('SYN FLOOD', 'CRITICAL', newPacket.source, '512+ SYN packets detected (Potential DoS)');
        }

        if (newPacket.info.includes('Port Scan') && rules.portScan) {
          addAlert('PORT SCAN', 'HIGH', newPacket.source, 'Sequential port probing detected (Footprinting)');
        }

        if (newPacket.protocol === 'HTTP' && newPacket.info.includes('admin') && Math.random() > 0.95) {
          addAlert('AUTH BYPASS', 'CRITICAL', newPacket.source, 'Unauthorized attempt on /admin terminal');
        }

        if (newPacket.length > 1400 && newPacket.protocol === 'UDP' && Math.random() > 0.98) {
          addAlert('DATA EXFIL', 'HIGH', newPacket.source, 'Oversized payload transmission to external IP');
        }

        if (newPacket.protocol === 'TCP' && Math.random() > 0.99) {
          addAlert('BRUTE FORCE', 'HIGH', newPacket.source, 'Repeated SSH handshake failures on port 22');
        }
      }, 400);
    }
    return () => clearInterval(interval);
  }, [isCapturing, rules]);

  const addAlert = (type: string, severity: Severity, sourceIp: string, details: string) => {
    const alert: Alert = {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: Date.now(),
      type,
      severity,
      sourceIp,
      details
    };
    setAlerts(prev => [alert, ...prev].slice(0, 50));
  };

  const trafficData = useMemo(() => {
    const last30 = packets.slice(-30);
    return last30.map((p, i) => ({
      name: i,
      value: p.length
    }));
  }, [packets]);

  const stats = useMemo(() => {
    return {
      total: alerts.length,
      critical: alerts.filter(a => a.severity === 'CRITICAL').length,
      high: alerts.filter(a => a.severity === 'HIGH').length,
      blocked: Math.floor(alerts.length * 0.15)
    };
  }, [alerts]);

  const filteredAlerts = alerts.filter(a => filter === 'ALL' || a.severity === filter);

  if (activeTab === 'research') {
    return (
      <div className="min-h-screen bg-slate-50 text-slate-800 font-sans">
        <header className="bg-white border-b border-slate-200 px-8 py-4 flex items-center justify-between sticky top-0 z-50">
          <div className="flex items-center gap-3">
             <Shield className="w-8 h-8 text-emerald-600" />
             <div>
                <h1 className="text-xl font-bold tracking-tight text-slate-900">IDS Research & Implementation</h1>
                <p className="text-xs text-slate-500">Step-by-step Cybersecurity Project Guide</p>
             </div>
          </div>
          <button onClick={() => setActiveTab('dashboard')} className="text-sm font-bold text-emerald-600 hover:underline">Back to Dashboard</button>
        </header>

        <main className="max-w-4xl mx-auto py-12 px-6 space-y-12">
          <section className="space-y-6">
            <h2 className="text-2xl font-bold flex items-center gap-2">How it works?</h2>
            <div className="grid md:grid-cols-2 gap-8 text-sm leading-relaxed text-slate-600">
               <div className="space-y-4 p-6 bg-white rounded-2xl shadow-sm border border-slate-100">
                  <h3 className="font-bold text-slate-900 flex items-center gap-2"><Network className="w-4 h-4 text-emerald-500" /> Packet Capture</h3>
                  <p>এই ড্যাশবোর্ডটি সরাসরি আপনার নেটওয়ার্ক ইন্টারফেস কার্ড (eth0/wlan0) থেকেRaw Packets সংগ্রহ করে। JavaScript এর ক্ষেত্রে আমরা এটি সিমুলেট করছি, কিন্তু রিয়েল প্রজেক্টে `libpcap` বা `winpcap` ব্যবহার করা হয়।</p>
               </div>
               <div className="space-y-4 p-6 bg-white rounded-2xl shadow-sm border border-slate-100">
                  <h3 className="font-bold text-slate-900 flex items-center gap-2"><Zap className="w-4 h-4 text-amber-500" /> Detection Engine</h3>
                  <p>সিস্টেমটি প্রতিটি প্যাকেটের হেডার অ্যানালাইসিস করে। যখন এটি অস্বাভাবিক কোনো প্যাটার্ন দেখে (যেমন একই আইপি থেকে বারবার SYN রিকোয়েস্ট), তখন এটি একটি অ্যালার্ট জেনারেট করে।</p>
               </div>
            </div>
          </section>

          <section className="space-y-8 bg-white p-8 rounded-3xl shadow-sm border border-slate-100">
            <h2 className="text-2xl font-bold text-slate-900">Implementation Steps (ধাপে ধাপে গাইড)</h2>
            <div className="space-y-8 relative before:absolute before:left-4 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-100">
               <Step number="1" title="Kernel Interface Hooking" time="3 Days">
                  Real-time detection require a C-based backend or Node.js with `libpcap`. You must set the NIC to 'Promiscuous Mode' to see traffic not addressed to your own MAC.
               </Step>
               <Step number="2" title="Stream Analysis Pipeline" time="1 Week">
                  Implement a high-speed buffer. Use Kafka or Redis to queue incoming packets and run them against your signature-based detection engine in real-time.
               </Step>
               <Step number="3" title="Advanced Threat Modeling" time="2 Weeks">
                  Integrate AI models for Anomaly Detection. A baseline of 'Normal' traffic is established, and anything deviating from it is flagged as a potential Zero-Day threat.
               </Step>
               <Step number="4" title="Dashboard Integration" time="Present">
                  Send filtered alert data via WebSockets to this GUI. This allows multiple security analysts to monitor the network from a central command center.
               </Step>
            </div>
            <div className="mt-8 p-4 bg-emerald-50 text-emerald-700 rounded-xl text-sm italic">
               সম্পূর্ণ প্রজেক্টটি করতে একজন স্টুডেন্টের জন্য প্রায় <strong>৩ থেকে ৪ সপ্তাহ</strong> সময় লাগতে পারে।
            </div>
          </section>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#F8FAFC] text-slate-800 font-sans flex flex-col antialiased">
      {/* Header */}
      <header className="h-16 bg-white border-b border-slate-200 px-6 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-emerald-500 rounded-xl flex items-center justify-center text-white shadow-lg shadow-emerald-500/20">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-base font-bold text-slate-900 leading-tight">NetScout Threat Sentinel</h1>
            <p className="text-[11px] text-emerald-600 font-bold uppercase tracking-tighter">Real-Time Infrastructure Monitor — Active Scan</p>
          </div>
        </div>
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2 bg-emerald-50 px-3 py-1.5 rounded-full">
            <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
            <span className="text-[11px] font-bold text-emerald-600 uppercase tracking-wider">Running</span>
          </div>
          <button onClick={() => setActiveTab('research')} className="flex items-center gap-2 text-xs font-bold text-slate-500 hover:text-emerald-600 transition-colors">
            <BookOpen className="w-4 h-4" /> LEARN HOW IT WORKS
          </button>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        {/* Left Sidebar */}
        <aside className="w-72 bg-white border-r border-slate-200 p-6 flex flex-col gap-8 overflow-y-auto shrink-0">
          <div className="space-y-3">
            <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest block">Network Interface</label>
            <select className="w-full bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-sm font-medium focus:outline-none focus:ring-2 focus:ring-emerald-500/20">
              <option>eth0</option>
              <option>wlan0 (WiFi)</option>
              <option>lo (Loopback)</option>
            </select>
          </div>

          <div className="space-y-4">
            <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest block">Controls</label>
            <div className="space-y-3">
              <button 
                onClick={() => setIsCapturing(true)} 
                className={cn(
                  "w-full flex items-center justify-center gap-2 py-2.5 rounded-xl font-bold text-sm transition-all",
                  isCapturing ? "bg-emerald-50 text-emerald-400 cursor-not-allowed" : "bg-emerald-500 text-white hover:bg-emerald-600 shadow-md shadow-emerald-500/20"
                )}
              >
                <Play className="w-4 h-4 fill-current" /> Start Monitoring
              </button>
              <button 
                onClick={() => setIsCapturing(false)} 
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl bg-red-50 text-red-500 font-bold text-sm hover:bg-red-100 transition-all"
              >
                <Square className="w-4 h-4 fill-current" /> Stop
              </button>
              <button 
                onClick={() => setAlerts([])} 
                className="w-full flex items-center justify-center gap-2 py-2.5 text-slate-400 hover:text-slate-600 font-medium text-xs border border-transparent hover:border-slate-100 rounded-xl"
              >
                <XCircle className="w-4 h-4" /> Clear Alerts
              </button>
            </div>
          </div>

          <div className="space-y-4">
             <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest block">Detection Rules</label>
             <div className="space-y-3">
                <RuleToggle label="Port Scan" enabled={rules.portScan} onChange={() => setRules(r => ({...r, portScan: !r.portScan}))} />
                <RuleToggle label="SYN Flood" enabled={rules.synFlood} onChange={() => setRules(r => ({...r, synFlood: !r.synFlood}))} />
                <RuleToggle label="ICMP Flood" enabled={rules.icmpFlood} onChange={() => setRules(r => ({...r, icmpFlood: !r.icmpFlood}))} />
                <RuleToggle label="Brute Force" enabled={rules.bruteForce} onChange={() => setRules(r => ({...r, bruteForce: !r.bruteForce}))} />
                <RuleToggle label="ARP Spoofing" enabled={rules.arpSpoofing} onChange={() => setRules(r => ({...r, arpSpoofing: !r.arpSpoofing}))} />
             </div>
          </div>

          <div className="mt-auto p-4 bg-slate-50 rounded-2xl border border-slate-100">
             <span className="text-[10px] font-bold text-slate-400 uppercase block mb-2">Packets Captured</span>
             <div className="flex items-end gap-2">
                <span className="text-2xl font-bold text-slate-900">{packets.length.toLocaleString()}</span>
                <span className="text-[10px] font-bold text-emerald-500 mb-1">22 pkts/sec</span>
             </div>
          </div>
        </aside>

        {/* Main Dashboard Area */}
        <main className="flex-1 overflow-y-auto px-10 py-8 bg-[#F8FAFC]">
          {/* Top Stats Cards */}
          <div className="grid grid-cols-4 gap-6 mb-8">
            <StatCard label="Total Alerts" value={stats.total} color="slate" />
            <StatCard label="Critical" value={stats.critical} color="red" />
            <StatCard label="High" value={stats.high} color="amber" />
            <StatCard label="Blocked IPs" value={stats.blocked} color="emerald" />
          </div>

          {/* Traffic Monitor Section */}
          <div className="bg-white rounded-[32px] p-8 border border-slate-200 shadow-sm mb-10 overflow-hidden relative group">
             <div className="flex items-center justify-between mb-8">
                <div className="flex items-center gap-3">
                   <div className="p-2 bg-blue-50 text-blue-500 rounded-lg">
                      <Activity className="w-5 h-5" />
                   </div>
                   <div>
                     <h2 className="text-sm font-bold text-slate-900">Live Traffic Monitor</h2>
                     <p className="text-[11px] text-slate-400">Packet volume over time (Bytes/sec)</p>
                   </div>
                </div>
                <div className="px-3 py-1 bg-blue-500 text-white rounded text-[10px] font-bold uppercase tracking-widest">
                   850 B/s
                </div>
             </div>
             <div className="h-40 w-full">
               <ResponsiveContainer width="100%" height="100%">
                 <BarChart data={trafficData}>
                   <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                     {trafficData.map((entry, index) => (
                       <Cell key={`cell-${index}`} fill={entry.value > 1000 ? "#6366f1" : "#94a3b8"} fillOpacity={0.4} />
                     ))}
                   </Bar>
                 </BarChart>
               </ResponsiveContainer>
             </div>
          </div>

          {/* Alert Log Section */}
          <div className="bg-white rounded-[32px] border border-slate-200 shadow-sm overflow-hidden min-h-[500px]">
             <div className="px-8 py-6 border-b border-slate-100 flex items-center justify-between">
                <h3 className="text-lg font-bold text-slate-900">Alert Log</h3>
                <div className="flex gap-2">
                   <FilterButton active={filter === 'ALL'} onClick={() => setFilter('ALL')}>All</FilterButton>
                   <FilterButton active={filter === 'CRITICAL'} onClick={() => setFilter('CRITICAL')}>Critical</FilterButton>
                   <FilterButton active={filter === 'HIGH'} onClick={() => setFilter('HIGH')}>High</FilterButton>
                   <FilterButton active={filter === 'MEDIUM'} onClick={() => setFilter('MEDIUM')}>Medium</FilterButton>
                </div>
             </div>

             <div className="p-0 overflow-y-auto">
               <AnimatePresence initial={false}>
                 {filteredAlerts.map((alert) => (
                   <motion.div 
                     key={alert.id}
                     initial={{ opacity: 0, x: -20 }}
                     animate={{ opacity: 1, x: 0 }}
                     exit={{ opacity: 0, x: 20 }}
                     className="px-8 py-4 border-b border-slate-50 flex items-center justify-between group hover:bg-slate-50 transition-colors"
                   >
                     <div className="flex items-center gap-6">
                        <span className={cn(
                          "px-2.5 py-1 rounded-md text-[9px] font-black uppercase tracking-widest w-20 text-center",
                          alert.severity === 'CRITICAL' ? "bg-red-50 text-red-500" :
                          alert.severity === 'HIGH' ? "bg-amber-50 text-amber-500" :
                          alert.severity === 'MEDIUM' ? "bg-blue-50 text-blue-500" : "bg-slate-50 text-slate-500"
                        )}>
                          {alert.severity}
                        </span>
                        <div>
                          <p className="text-sm font-bold text-slate-900 flex items-center gap-2">
                             {alert.type} 
                             <span className="w-1 h-1 bg-slate-300 rounded-full" /> 
                             <span className="text-slate-500 font-mono text-xs">{alert.sourceIp}</span>
                          </p>
                          <p className="text-[11px] text-slate-500 font-medium">{alert.details}</p>
                        </div>
                     </div>
                     <div className="flex items-center gap-4">
                        <span className="text-[10px] font-mono font-bold text-slate-400">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                        <ChevronRight className="w-4 h-4 text-slate-300 opacity-0 group-hover:opacity-100 transition-opacity" />
                     </div>
                   </motion.div>
                 ))}
               </AnimatePresence>
               {filteredAlerts.length === 0 && (
                 <div className="h-64 flex flex-col items-center justify-center text-slate-300">
                    <CheckCircle2 className="w-12 h-12 mb-3" />
                    <p className="text-sm font-bold uppercase tracking-widest">No Active Threats</p>
                    <p className="text-xs">Security engine is optimally filtered.</p>
                 </div>
               )}
             </div>
          </div>
        </main>
      </div>

      <footer className="h-10 bg-white border-t border-slate-200 px-6 flex items-center justify-between text-[10px] font-bold text-slate-400 tracking-widest uppercase">
          <div className="flex gap-6">
            <span>Uptime: 2h 45m</span>
            <span>Kernel: v4.19-ids</span>
          </div>
          <div>© 2026 NETSCOUT CYBERSECURITY INTEGRATION</div>
      </footer>
    </div>
  );
}

// Helper Components
function StatCard({ label, value, color }: { label: string, value: number, color: 'slate' | 'red' | 'amber' | 'emerald' }) {
  const colors = {
    slate: 'text-slate-900 bg-slate-50',
    red: 'text-red-500 bg-red-50/50',
    amber: 'text-amber-500 bg-amber-50/50',
    emerald: 'text-emerald-500 bg-emerald-50/50'
  };

  return (
    <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm flex flex-col gap-2">
      <span className="text-[10px] font-bold text-slate-400 uppercase tracking-[0.2em]">{label}</span>
      <span className={cn("text-3xl font-black font-mono leading-none", colors[color].split(' ')[0])}>{value}</span>
    </div>
  );
}

function RuleToggle({ label, enabled, onChange }: { label: string, enabled: boolean, onChange: () => void }) {
  return (
    <button onClick={onChange} className="w-full flex items-center justify-between group transition-all">
       <span className={cn("text-[13px] font-medium transition-colors", enabled ? "text-slate-700" : "text-slate-400")}>{label}</span>
       <div className={cn(
         "w-10 h-5 rounded-full relative transition-all flex items-center px-1",
         enabled ? "bg-emerald-500" : "bg-slate-200"
       )}>
          <motion.div 
            animate={{ x: enabled ? 20 : 0 }}
            className="w-3 h-3 bg-white rounded-full shadow-sm" 
          />
       </div>
    </button>
  );
}

function FilterButton({ active, onClick, children }: { active: boolean, onClick: () => void, children: React.ReactNode }) {
  return (
    <button 
      onClick={onClick}
      className={cn(
        "px-4 py-1.5 rounded-full text-[11px] font-bold uppercase tracking-wider transition-all border",
        active ? "bg-slate-900 border-slate-900 text-white" : "bg-white border-slate-200 text-slate-500 hover:border-slate-300"
      )}
    >
      {children}
    </button>
  );
}

function Step({ number, title, time, children }: { number: string, title: string, time: string, children: React.ReactNode }) {
  return (
    <div className="relative pl-12">
       <div className="absolute left-0 w-9 h-9 bg-emerald-500 text-white rounded-xl flex items-center justify-center font-black shadow-lg shadow-emerald-500/20 z-10">{number}</div>
       <div className="space-y-1">
          <div className="flex items-center justify-between">
             <h4 className="font-bold text-slate-900">{title}</h4>
             <span className="flex items-center gap-1.5 text-[10px] font-bold text-slate-400 bg-slate-50 px-2.5 py-1 rounded-md uppercase tracking-wider">
                <Clock className="w-3 h-3" /> {time}
             </span>
          </div>
          <p className="text-sm text-slate-600 leading-relaxed">{children}</p>
       </div>
    </div>
  );
}
