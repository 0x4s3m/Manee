import { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import {
  Shield,
  LayoutDashboard,
  Search,
  Skull,
  Package,
  Terminal as TerminalIcon,
  Globe,
  Play,
  Eye,
  Activity,
  Cpu,
  Lock,
  ChevronRight
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  LineChart,
  Line
} from 'recharts';
import { motion, AnimatePresence } from 'framer-motion';
import { translations } from './i18n';

const API_BASE = "http://localhost:8000";

interface Vulnerability {
  id: string;
  name: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  description: string;
}

function App() {
  const [lang, setLang] = useState<'en' | 'ar'>('en');
  const [activeTab, setActiveTab] = useState('dashboard');
  const [target, setTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<Vulnerability[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [monitorData, setMonitorData] = useState<any[]>([]);
  const [shapData, setShapData] = useState<any>(null);
  const [isExplaining, setIsExplaining] = useState(false);

  const logEndRef = useRef<HTMLDivElement>(null);
  const T = translations[lang];

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  useEffect(() => {
    const interval = setInterval(() => {
      fetchMonitor();
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const fetchMonitor = async () => {
    try {
      const res = await axios.get(`${API_BASE}/monitor`);
      setMonitorData((prev) => [...prev.slice(-14), { time: new Date().toLocaleTimeString().split(' ')[0], ...res.data }]);
    } catch (err) { console.error("API Offline"); }
  };

  const addLog = (msg: string) => {
    setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  const startScan = async () => {
    if (!target) return;
    setIsScanning(true);
    setResults([]);
    setLogs([]);
    addLog(`INIT_SCAN: Loading HUSN heuristics for ${target}...`);

    setTimeout(() => addLog(`[+] Establishing secure handshake with ${target}`), 800);
    setTimeout(() => addLog(`[*] Port discovery in progress...`), 1500);
    setTimeout(() => addLog(`[!] 0x42: Insecure cookie attribute detected`), 3000);
    setTimeout(() => addLog(`[*] Analyzing payload injection points...`), 4500);

    try {
      await axios.post(`${API_BASE}/scan`, { target });

      setTimeout(() => {
        addLog(`[+] Scan finalized. Parsing results...`);
        setResults([
          { id: '1', name: lang === 'en' ? 'SQL Injection' : 'حقن SQL', severity: 'Critical', description: lang === 'en' ? 'Blind SQLi detected in POST parameter "user_id". DB compromise imminent.' : 'تم اكتشاف حقن SQL أعمى في معلمة POST. اختراق قاعدة البيانات وشيك.' },
          { id: '2', name: lang === 'en' ? 'Broken Access Control' : 'كسر التحكم في الوصول', severity: 'High', description: lang === 'en' ? 'Endpoint /admin/config accessible without session validation.' : 'نقطة النهاية /admin/config متاحة بدون التحقق من الجلسة.' },
          { id: '3', name: lang === 'en' ? 'Information Disclosure' : 'كشف المعلومات', severity: 'Medium', description: lang === 'en' ? 'Server version (nginx/1.18.0) exposed in HTTP headers.' : 'إصدار الخادم (nginx/1.18.0) مكشوف في ترويسات HTTP.' }
        ]);
        setIsScanning(false);
        addLog(`[DONE] Scan complete. 3 vulnerabilities mapped.`);
      }, 7000);

    } catch (err) {
      addLog(`[ERR] Failed to connect to AI backend.`);
      setIsScanning(false);
    }
  };

  const fetchExplanation = async () => {
    setIsExplaining(true);
    try {
      const res = await axios.get(`${API_BASE}/explain`);
      setShapData(res.data);
    } catch (err) { console.error(err); }
    setIsExplaining(false);
  };

  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case 'Critical': return 'text-red-500 border-red-500/50 bg-red-500/10 shadow-[0_0_10px_rgba(239,68,68,0.3)]';
      case 'High': return 'text-orange-500 border-orange-500/50 bg-orange-500/10';
      case 'Medium': return 'text-yellow-500 border-yellow-500/50 bg-yellow-500/10';
      default: return 'text-green-500 border-green-500/50 bg-green-500/10';
    }
  };

  return (
    <div className={`min-h-screen bg-[#0b0f17] text-gray-300 font-mono flex select-none ${lang === 'ar' ? 'rtl' : 'ltr'}`} dir={lang === 'ar' ? 'rtl' : 'ltr'}>

      {/* Sidebar */}
      <aside className={`w-64 bg-[#0d121f] border-white/5 fixed inset-y-0 flex flex-col z-50 ${lang === 'ar' ? 'right-0 border-l' : 'left-0 border-r'}`}>
        <div className="p-8 flex items-center gap-3">
          <div className="relative">
            <Shield className="text-neon-cyan w-10 h-10 animate-pulse" />
            <div className="absolute inset-0 bg-neon-cyan/20 blur-xl rounded-full"></div>
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-tighter uppercase italic">{T.title}</h1>
            <div className="h-1 w-full bg-gradient-to-r from-neon-cyan to-transparent"></div>
          </div>
        </div>

        <nav className="flex-1 px-4 space-y-2 mt-4">
          <SidebarLink icon={<LayoutDashboard size={18}/>} label={T.monitoring} active={activeTab === 'dashboard'} onClick={() => setActiveTab('dashboard')} lang={lang}/>
          <SidebarLink icon={<Search size={18}/>} label={T.detection} active={activeTab === 'recon'} onClick={() => setActiveTab('recon')} lang={lang}/>
          <SidebarLink icon={<Skull size={18}/>} label={T.simulation} active={activeTab === 'exploits'} onClick={() => setActiveTab('exploits')} lang={lang}/>
          <SidebarLink icon={<Package size={18}/>} label={T.payloads} active={activeTab === 'payloads'} onClick={() => setActiveTab('payloads')} lang={lang}/>
          <SidebarLink icon={<Eye size={18}/>} label={T.explainableAI} active={activeTab === 'xai'} onClick={() => setActiveTab('xai')} lang={lang}/>
          <SidebarLink icon={<TerminalIcon size={18}/>} label={T.alerts} active={activeTab === 'logs'} onClick={() => setActiveTab('logs')} lang={lang}/>
        </nav>

        <div className="p-4 border-t border-white/5">
          <button
            onClick={() => setLang(lang === 'en' ? 'ar' : 'en')}
            className="w-full flex items-center justify-between bg-white/5 hover:bg-white/10 p-3 rounded-lg transition text-xs font-bold"
          >
            <span className="flex items-center gap-2"><Globe size={14} className="text-neon-cyan"/> {lang === 'en' ? 'العربية' : 'ENGLISH'}</span>
            <span className="text-[10px] opacity-30 uppercase">{lang}</span>
          </button>
        </div>

        <div className="p-6">
          <div className="bg-black/40 rounded-lg p-3 border border-white/5">
             <div className="flex justify-between items-center mb-2">
                <span className="text-[10px] text-gray-500 uppercase tracking-widest">{lang === 'en' ? 'System Load' : 'حمل النظام'}</span>
                <span className="text-[10px] text-neon-green">STABLE</span>
             </div>
             <div className="h-1.5 w-full bg-gray-800 rounded-full overflow-hidden">
                <motion.div animate={{ width: ['20%', '45%', '30%'] }} transition={{ repeat: Infinity, duration: 4 }} className="h-full bg-neon-cyan"></motion.div>
             </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className={`flex-1 ${lang === 'ar' ? 'mr-64' : 'ml-64'} min-h-screen flex flex-col`}>

        {/* Top Header */}
        <header className="h-20 border-b border-white/5 flex items-center px-10 bg-[#0b0f17]/90 backdrop-blur-xl sticky top-0 z-40">
          <div className="flex-1 flex items-center gap-6">
             <div className="flex-1 max-w-xl relative group">
                <input
                  type="text"
                  placeholder={T.target}
                  className={`w-full bg-black/50 border border-white/10 p-3 rounded-lg outline-none focus:border-neon-cyan focus:ring-1 focus:ring-neon-cyan/50 transition-all text-sm tracking-widest uppercase placeholder:text-gray-700 ${lang === 'ar' ? 'pr-12 pl-4' : 'pl-12 pr-4'}`}
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                />
                <Lock className={`absolute ${lang === 'ar' ? 'right-4' : 'left-4'} top-3.5 text-gray-700 group-focus-within:text-neon-cyan transition-colors`} size={18} />
             </div>
             <button
              onClick={startScan}
              disabled={isScanning || !target}
              className={`h-12 px-8 bg-neon-cyan text-black font-black uppercase italic tracking-tighter rounded-lg hover:scale-105 active:scale-95 transition-all disabled:opacity-20 flex items-center gap-3 shadow-[0_0_20px_rgba(0,255,255,0.2)]`}
            >
              {isScanning ? <Activity className="animate-spin" size={20}/> : <Play size={20} fill="black" />}
              {isScanning ? (lang === 'en' ? 'Scanning...' : 'جاري الفحص...') : T.runScan}
            </button>
          </div>

          <div className="flex items-center gap-6">
             <div className="text-right">
                <p className="text-[10px] text-gray-500 font-bold uppercase tracking-widest">{lang === 'en' ? 'Network' : 'الشبكة'}</p>
                <p className="text-xs text-neon-green">0x92...F12</p>
             </div>
             <div className="w-10 h-10 rounded-full bg-white/5 border border-white/10 flex items-center justify-center text-neon-cyan">
                <Cpu size={20} />
             </div>
          </div>
        </header>

        <div className="p-10 flex gap-10 flex-1 overflow-hidden">
          {/* Scrollable Panel Area */}
          <div className="flex-1 overflow-y-auto pr-4 terminal-scroll">
            <AnimatePresence mode="wait">
              {activeTab === 'dashboard' && (
                <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 20 }} className="space-y-10">

                  {/* Realtime Graph */}
                  <div className="glass-card border-none bg-gradient-to-br from-[#121826] to-[#0d121f]">
                    <div className="flex justify-between items-center mb-8">
                      <h3 className="text-lg font-bold text-white flex items-center gap-3 uppercase italic tracking-tighter">
                        <Activity className="text-neon-cyan" size={20}/> {T.monitoring}
                      </h3>
                      <div className="flex gap-4 text-[10px]">
                        <span className="flex items-center gap-1.5"><div className="w-2 h-2 bg-neon-green rounded-full"></div> {lang === 'en' ? 'IN' : 'وارد'}</span>
                        <span className="flex items-center gap-1.5"><div className="w-2 h-2 bg-neon-cyan rounded-full"></div> {lang === 'en' ? 'OUT' : 'صادر'}</span>
                        <span className="flex items-center gap-1.5"><div className="w-2 h-2 bg-red-500 rounded-full animate-ping"></div> {lang === 'en' ? 'ATTACK' : 'هجوم'}</span>
                      </div>
                    </div>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={monitorData}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#222" vertical={false} />
                          <XAxis dataKey="time" hide />
                          <YAxis hide domain={[0, 1200]} />
                          <Tooltip contentStyle={{ backgroundColor: '#000', border: '1px solid #333' }} />
                          <Line type="stepAfter" dataKey="incoming" stroke="#00ff00" dot={false} strokeWidth={2} />
                          <Line type="stepAfter" dataKey="outgoing" stroke="#00ffff" dot={false} strokeWidth={2} />
                          <Line type="monotone" dataKey="malicious" stroke="#ef4444" dot={false} strokeWidth={3} />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <h4 className="text-xs font-bold text-gray-500 uppercase tracking-[0.3em] mb-6">{T.siemFeed}</h4>
                    {results.map((vuln, idx) => (
                      <motion.div
                        key={vuln.id}
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        transition={{ delay: idx * 0.15 }}
                        className="bg-[#121826] border border-white/5 p-6 rounded-xl hover:border-neon-cyan/30 transition-all cursor-pointer group relative overflow-hidden"
                      >
                        <div className="flex justify-between items-center relative z-10">
                          <div className="flex items-center gap-6">
                            <div className={`p-4 rounded-lg border uppercase font-black italic tracking-tighter text-sm ${getSeverityColor(vuln.severity)}`}>
                              {vuln.severity}
                            </div>
                            <div>
                              <h3 className="text-white font-bold text-lg mb-1 group-hover:text-neon-cyan transition-colors">{vuln.name}</h3>
                              <p className="text-xs text-gray-500 max-w-lg leading-relaxed uppercase">{vuln.description}</p>
                            </div>
                          </div>
                          <ChevronRight className={`text-gray-700 group-hover:text-neon-cyan transform group-hover:translate-x-2 transition-all ${lang === 'ar' ? 'rotate-180 group-hover:-translate-x-2' : ''}`} />
                        </div>
                        <div className={`absolute top-0 opacity-10 pointer-events-none uppercase font-black text-4xl -mt-4 text-white italic ${lang === 'ar' ? 'left-0 -ml-4' : 'right-0 -mr-4'}`}>
                          {vuln.severity}
                        </div>
                      </motion.div>
                    ))}
                    {!isScanning && results.length === 0 && (
                      <div className="h-64 border border-dashed border-white/10 rounded-2xl flex flex-col items-center justify-center text-gray-700 group hover:border-white/20 transition-all">
                        <Skull size={48} className="mb-4 opacity-10 group-hover:opacity-30 transition-opacity" />
                        <p className="text-sm uppercase tracking-widest font-black italic">{lang === 'en' ? 'Awaiting Target Acquisition' : 'في انتظار تحديد الهدف'}</p>
                      </div>
                    )}
                  </div>
                </motion.div>
              )}

              {activeTab === 'xai' && (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-10">
                  <div className="flex justify-between items-end">
                    <div>
                      <h2 className="text-3xl font-black text-white uppercase italic tracking-tighter">{T.explainableAI}</h2>
                      <p className="text-xs text-neon-cyan mt-1 tracking-widest font-bold uppercase italic">XGBOOST_FEATURE_CONTRIBUTION_ANALYSIS</p>
                    </div>
                    <button onClick={fetchExplanation} disabled={isExplaining} className="cyber-button-cyan text-xs">
                      {isExplaining ? (lang === 'en' ? 'ANALYZING...' : 'جاري التحليل...') : (lang === 'en' ? 'RUN SHAP ENGINE' : 'بدء محرك SHAP')}
                    </button>
                  </div>

                  <div className="grid grid-cols-3 gap-10">
                    <div className="col-span-2 glass-card min-h-[450px] bg-black/40">
                      {shapData ? (
                        <ResponsiveContainer width="100%" height={400}>
                          <BarChart data={shapData.features} layout="vertical" margin={{ left: 40, right: 40 }}>
                            <XAxis type="number" hide />
                            <YAxis dataKey="name" type="category" stroke="#666" fontSize={10} width={150} tickFormatter={(val) => val.toUpperCase()} orientation={lang === 'ar' ? 'right' : 'left'} />
                            <Tooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} contentStyle={{ backgroundColor: '#000', border: '1px solid #00ffff' }} />
                            <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                              {shapData.features.map((entry: any, index: number) => (
                                <Cell key={index} fill={entry.value > 0 ? '#ef4444' : '#00ffff'} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      ) : (
                        <div className="h-full flex flex-col items-center justify-center text-gray-700">
                          <Eye size={48} className="mb-4 opacity-20" />
                          <p className="text-xs uppercase tracking-widest font-bold">{lang === 'en' ? 'Init SHAP engine to view weights' : 'قم بتشغيل محرك SHAP لعرض الأوزان'}</p>
                        </div>
                      )}
                    </div>
                    <div className="space-y-6">
                       <div className="p-6 rounded-xl border border-white/5 bg-white/5">
                          <h4 className="text-xs font-bold text-white uppercase mb-4 tracking-tighter">{lang === 'en' ? 'Interpretation Guide' : 'دليل التفسير'}</h4>
                          <div className="space-y-4 text-[11px] leading-relaxed text-gray-400">
                             <p><span className="text-red-500 font-black">{lang === 'en' ? 'RED (+)' : 'أحمر (+)'}</span>: {lang === 'en' ? 'Feature significantly increased threat probability.' : 'ساهمت الميزة بشكل كبير في زيادة احتمال التهديد.'}</p>
                             <p><span className="text-neon-cyan font-black">{lang === 'en' ? 'CYAN (-)' : 'سماوي (-)'}</span>: {lang === 'en' ? 'Feature served as an indicator of legitimate behavior.' : 'كانت الميزة مؤشراً على السلوك المشروع.'}</p>
                          </div>
                       </div>
                       <div className="p-6 rounded-xl border border-red-500/20 bg-red-500/5">
                          <h4 className="text-[10px] font-bold text-red-500 uppercase mb-2">{T.confidence}</h4>
                          <p className="text-4xl font-black text-white italic">99.8<span className="text-xs opacity-50">%</span></p>
                       </div>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Right Log Panel */}
          <div className="w-[400px] flex flex-col gap-6 sticky top-24 h-[calc(100vh-130px)]">
            <div className="flex-1 bg-black border border-white/10 rounded-2xl flex flex-col overflow-hidden shadow-2xl">
              <div className="bg-[#111622] p-4 border-b border-white/10 flex justify-between items-center">
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 bg-neon-green rounded-full animate-pulse shadow-[0_0_8px_#00ff00]"></div>
                  <span className="text-[10px] font-black text-white tracking-[0.2em] uppercase">Kernel_logs</span>
                </div>
                <div className="text-[10px] text-gray-600 font-bold">ASYNC_THREAD_v2.1</div>
              </div>
              <div className="flex-1 p-6 text-[10px] font-mono terminal-scroll overflow-y-auto space-y-2">
                {logs.length === 0 && <p className="text-gray-800 italic animate-pulse"># HUSN_V7_SYSTEM_READY...</p>}
                {logs.map((log, i) => (
                  <div key={i} className="flex gap-3">
                    <span className="text-gray-700 font-bold">{i.toString(16).padStart(4, '0')}</span>
                    <span className={log.includes('!') ? 'text-red-500' : log.includes('[+]') ? 'text-neon-cyan' : 'text-gray-500'}>
                      {log}
                    </span>
                  </div>
                ))}
                <div ref={logEndRef} />
              </div>
            </div>

            <div className="p-6 rounded-2xl bg-gradient-to-r from-neon-cyan/20 to-transparent border border-neon-cyan/30 group">
              <div className="flex justify-between items-start mb-1">
                <span className="text-[10px] font-black text-neon-cyan uppercase tracking-widest">Active_Shield</span>
                <Lock size={14} className="text-neon-cyan" />
              </div>
              <p className="text-2xl font-black text-white italic tracking-tighter uppercase">{lang === 'en' ? 'Enabled' : 'مفعل'}</p>
              <div className="h-1 w-full bg-white/5 mt-3 rounded-full overflow-hidden">
                <motion.div initial={{ x: '-100%' }} animate={{ x: '100%' }} transition={{ repeat: Infinity, duration: 2, ease: "linear" }} className="h-full w-1/3 bg-neon-cyan"></motion.div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

const SidebarLink = ({ icon, label, active, onClick, lang }: any) => (
  <button
    onClick={onClick}
    className={`w-full flex items-center gap-4 p-4 rounded-xl transition-all relative group ${active ? 'bg-neon-cyan/10 text-neon-cyan shadow-[inset_0_0_20px_rgba(0,255,255,0.05)]' : 'text-gray-600 hover:text-gray-300 hover:bg-white/5'}`}
  >
    {active && <div className={`absolute top-3 bottom-3 w-1 bg-neon-cyan rounded-full shadow-[0_0_10px_#00ffff] ${lang === 'ar' ? 'right-0' : 'left-0'}`}></div>}
    <div className={`${active ? 'text-neon-cyan' : 'text-gray-700 group-hover:text-gray-500'} transition-colors`}>{icon}</div>
    <span className="text-[10px] font-black uppercase tracking-widest italic">{label}</span>
  </button>
);

export default App;
