import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Shield,
  Activity,
  Zap,
  Eye,
  Bell,
  Cpu,
  Globe,
  AlertTriangle,
  Terminal as TerminalIcon,
  Play
} from 'lucide-react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell
} from 'recharts';
import { motion, AnimatePresence } from 'framer-motion';
import { translations } from './i18n';

const API_BASE = "http://localhost:8000";

function App() {
  const [lang, setLang] = useState<'en' | 'ar'>('en');
  const [activeTab, setActiveTab] = useState('monitoring');
  const [monitorData, setMonitorData] = useState<any>([]);
  const [stats, setStats] = useState<any>({});
  const [logs, setLogs] = useState<string[]>([]);
  const [scanResults, setScanResults] = useState<any[]>([]);
  const [shapData, setShapData] = useState<any>(null);
  const [simulationParams, setSimulationParams] = useState({ target_ip: "127.0.0.1", attack_type: "DDoS" });

  const T = translations[lang];

  useEffect(() => {
    const interval = setInterval(() => {
      fetchMonitor();
      fetchLogs();
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const fetchMonitor = async () => {
    try {
      const res = await axios.get(`${API_BASE}/monitor`);
      setStats(res.data);
      setMonitorData((prev: any) => [...prev.slice(-19), { time: new Date().toLocaleTimeString(), ...res.data }]);
    } catch (err) { console.error(err); }
  };

  const fetchLogs = async () => {
    try {
      const res = await axios.get(`${API_BASE}/logs`);
      setLogs(res.data);
    } catch (err) { console.error(err); }
  };

  const runScan = async () => {
    try {
      const res = await axios.get(`${API_BASE}/scan`);
      setScanResults(res.data);
      setActiveTab('detection');
    } catch (err) { console.error(err); }
  };

  const triggerSimulation = async () => {
    try {
      await axios.post(`${API_BASE}/simulate`, simulationParams);
      alert("Simulation Triggered!");
    } catch (err) { console.error(err); }
  };

  const fetchSHAP = async () => {
    try {
      const res = await axios.get(`${API_BASE}/explain`);
      setShapData(res.data);
      setActiveTab('explain');
    } catch (err) { console.error(err); }
  };

  return (
    <div className={`min-h-screen bg-[#0e1117] text-white overflow-x-hidden ${lang === 'ar' ? 'rtl' : 'ltr'}`} dir={lang === 'ar' ? 'rtl' : 'ltr'}>
      {/* Header */}
      <header className="border-b border-gray-800 p-4 flex justify-between items-center bg-[#1a1c24] sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <Shield className="text-neon-green w-10 h-10" />
          <div>
            <h1 className="text-2xl font-bold tracking-wider text-neon-green neon-glow">{T.arabicTitle} / {T.title}</h1>
            <p className="text-xs text-gray-400">{T.tagline}</p>
          </div>
        </div>
        <button
          onClick={() => setLang(lang === 'en' ? 'ar' : 'en')}
          className="flex items-center gap-2 bg-gray-800 px-4 py-2 rounded hover:bg-gray-700 transition"
        >
          <Globe size={18} />
          {lang === 'en' ? 'العربية' : 'English'}
        </button>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <aside className="w-64 bg-[#1a1c24] border-r border-gray-800 min-h-[calc(100vh-73px)] p-4 flex flex-col gap-2">
          <NavItem icon={<Activity />} label={T.monitoring} active={activeTab === 'monitoring'} onClick={() => setActiveTab('monitoring')} />
          <NavItem icon={<AlertTriangle />} label={T.detection} active={activeTab === 'detection'} onClick={() => setActiveTab('detection')} />
          <NavItem icon={<Zap />} label={T.simulation} active={activeTab === 'simulation'} onClick={() => setActiveTab('simulation')} />
          <NavItem icon={<Eye />} label={T.explainableAI} active={activeTab === 'explain'} onClick={() => setActiveTab('explain')} />
          <NavItem icon={<Bell />} label={T.alerts} active={activeTab === 'alerts'} onClick={() => setActiveTab('alerts')} />
          <NavItem icon={<Cpu />} label={T.status} active={activeTab === 'status'} onClick={() => setActiveTab('status')} />

          <div className="mt-auto">
            <button onClick={runScan} className="cyber-button w-full flex items-center justify-center gap-2">
              <Activity size={18} /> {T.runScan}
            </button>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-8">
          <AnimatePresence mode="wait">
            {activeTab === 'monitoring' && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} key="monitoring">
                <div className="grid grid-cols-4 gap-6 mb-8">
                  <StatCard label={T.uptime} value={stats.uptime || 'N/A'} trend="+0.1%" />
                  <StatCard label={T.threatsBlocked} value={stats.threats_blocked || 0} trend="Live" color="text-red-500" />
                  <StatCard label={T.networkLoad} value={`${(stats.incoming / 20).toFixed(1)}%`} trend="Stable" />
                  <StatCard label={T.aiConfidence} value="98.4%" trend="Optimal" color="text-neon-cyan" />
                </div>

                <div className="grid grid-cols-3 gap-6">
                  <div className="col-span-2 glass-card h-96">
                    <h3 className="mb-4 text-neon-green font-bold flex items-center gap-2"><Activity /> {T.monitoring}</h3>
                    <ResponsiveContainer width="100%" height="90%">
                      <LineChart data={monitorData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                        <XAxis dataKey="time" stroke="#666" />
                        <YAxis stroke="#666" />
                        <Tooltip contentStyle={{ backgroundColor: '#1a1c24', border: '1px solid #00ff00' }} />
                        <Line type="monotone" dataKey="incoming" stroke="#00ff00" dot={false} strokeWidth={2} />
                        <Line type="monotone" dataKey="outgoing" stroke="#00ffff" dot={false} strokeWidth={2} />
                        <Line type="monotone" dataKey="malicious" stroke="#ff0000" dot={false} strokeWidth={2} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="glass-card">
                    <h3 className="mb-4 text-neon-cyan font-bold flex items-center gap-2"><TerminalIcon /> {T.siemFeed}</h3>
                    <div className="siem-log text-xs h-[280px]">
                      {logs.map((log, i) => (
                        <div key={i} className={log.includes('ALERT') ? 'text-neon-red font-bold animate-pulse' : 'text-neon-green'}>
                          {log}
                        </div>
                      )).reverse()}
                    </div>
                  </div>
                </div>
              </motion.div>
            )}

            {activeTab === 'detection' && (
              <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} key="detection">
                <h2 className="text-3xl font-bold mb-6 text-neon-green">{T.detection}</h2>
                <div className="glass-card overflow-hidden">
                  <table className="w-full text-left">
                    <thead className="bg-gray-800 text-neon-cyan">
                      <tr>
                        <th className="p-3">Label</th>
                        <th className="p-3">Confidence</th>
                        <th className="p-3">Severity</th>
                        <th className="p-3">Action Taken</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanResults.map((res, i) => (
                        <tr key={i} className="border-b border-gray-800 hover:bg-gray-800/50 transition">
                          <td className="p-3 font-bold">{res.label}</td>
                          <td className="p-3">{(res.confidence * 100).toFixed(1)}%</td>
                          <td className={`p-3 font-bold ${res.severity === 'High' ? 'text-red-500' : 'text-yellow-500'}`}>{res.severity}</td>
                          <td className="p-3 text-gray-400">{res.action}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {scanResults.length === 0 && <p className="p-10 text-center text-gray-500">No results. Run a scan to see data.</p>}
                </div>
              </motion.div>
            )}

            {activeTab === 'simulation' && (
              <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0 }} key="simulation">
                <h2 className="text-3xl font-bold mb-6 text-neon-red">{T.simulation}</h2>
                <div className="glass-card max-w-2xl mx-auto">
                  <div className="space-y-6">
                    <div>
                      <label className="block text-sm text-gray-400 mb-2">{T.target}</label>
                      <input
                        type="text"
                        value={simulationParams.target_ip}
                        onChange={(e) => setSimulationParams({...simulationParams, target_ip: e.target.value})}
                        className="w-full bg-[#0e1117] border border-gray-700 p-3 rounded text-neon-green outline-none focus:border-neon-green"
                      />
                    </div>
                    <div>
                      <label className="block text-sm text-gray-400 mb-2">{T.vector}</label>
                      <select
                        value={simulationParams.attack_type}
                        onChange={(e) => setSimulationParams({...simulationParams, attack_type: e.target.value})}
                        className="w-full bg-[#0e1117] border border-gray-700 p-3 rounded text-neon-cyan outline-none focus:border-neon-cyan"
                      >
                        <option>DDoS Attack</option>
                        <option>Port Scan</option>
                        <option>SSH Brute Force</option>
                        <option>Web Infiltration</option>
                      </select>
                    </div>
                    <button onClick={triggerSimulation} className="w-full py-4 bg-red-600 hover:bg-red-500 text-white font-bold rounded-lg shadow-[0_0_20px_rgba(255,0,0,0.4)] flex items-center justify-center gap-3 transition-all active:scale-95">
                      <Play /> {T.simulate}
                    </button>
                  </div>
                </div>
              </motion.div>
            )}

            {activeTab === 'explain' && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} key="explain">
                <h2 className="text-3xl font-bold mb-6 text-neon-cyan">{T.explainableAI}</h2>
                <div className="grid grid-cols-3 gap-6">
                  <div className="glass-card col-span-2 min-h-[500px]">
                    <h3 className="mb-6 text-neon-green">Feature Importance (SHAP Waterfall)</h3>
                    {shapData ? (
                      <ResponsiveContainer width="100%" height={400}>
                        <BarChart data={shapData.features} layout="vertical">
                          <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                          <XAxis type="number" stroke="#666" />
                          <YAxis dataKey="name" type="category" stroke="#666" width={150} />
                          <Tooltip contentStyle={{ backgroundColor: '#1a1c24', border: '1px solid #00ffff' }} />
                          <Bar dataKey="value">
                            {shapData.features.map((entry: any, index: number) => (
                              <Cell key={`cell-${index}`} fill={entry.value > 0 ? '#ff0000' : '#00ffff'} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    ) : (
                      <div className="h-full flex flex-col items-center justify-center gap-4">
                        <p className="text-gray-500">No SHAP data generated yet.</p>
                        <button onClick={fetchSHAP} className="cyber-button">Generate Explanation</button>
                      </div>
                    )}
                  </div>
                  <div className="glass-card">
                    <h3 className="text-neon-cyan mb-4">Transparency Report</h3>
                    <p className="text-sm text-gray-300 leading-relaxed">
                      This visualization shows how each network feature contributed to the AI's final decision.
                      <br/><br/>
                      <span className="text-red-500 font-bold">Red bars</span> indicate features that increased the threat probability.
                      <br/><br/>
                      <span className="text-cyan-500 font-bold">Blue bars</span> indicate features that decreased the threat probability.
                      <br/><br/>
                      Husn uses SHAP (SHapley Additive exPlanations) to ensure "Right to Explanation" for all security operations.
                    </p>
                  </div>
                </div>
              </motion.div>
            )}

            {activeTab === 'alerts' && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} key="alerts">
                <h2 className="text-3xl font-bold mb-6 text-neon-red">{T.alerts}</h2>
                <div className="space-y-4">
                  {logs.filter(l => l.includes('ALERT')).map((log, i) => (
                    <div key={i} className="bg-red-950/30 border border-red-500 p-4 rounded-lg flex items-center gap-4">
                      <AlertTriangle className="text-red-500" />
                      <div>
                        <p className="text-red-400 font-mono text-sm">{log}</p>
                      </div>
                    </div>
                  )).reverse()}
                  {logs.filter(l => l.includes('ALERT')).length === 0 && <p className="text-gray-500">No critical alerts detected.</p>}
                </div>
              </motion.div>
            )}

            {activeTab === 'status' && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} key="status">
                <h2 className="text-3xl font-bold mb-6 text-neon-green">{T.status}</h2>
                <div className="grid grid-cols-2 gap-6">
                  <div className="glass-card">
                    <h3 className="text-neon-cyan mb-4">Core Services</h3>
                    <div className="space-y-4">
                      <StatusItem label="AI Inference Engine" status="Online" />
                      <StatusItem label="Scapy Packet Sniffer" status="Active" />
                      <StatusItem label="Active Response Shield" status="Active" />
                      <StatusItem label="National Security Database" status="Connected" />
                    </div>
                  </div>
                  <div className="glass-card">
                    <h3 className="text-neon-cyan mb-4">Hardware Stats</h3>
                    <p className="text-gray-400 mb-2">CPU Usage: 14%</p>
                    <div className="w-full bg-gray-800 h-2 rounded-full mb-4 overflow-hidden">
                      <div className="bg-neon-green h-full" style={{ width: '14%' }}></div>
                    </div>
                    <p className="text-gray-400 mb-2">RAM Usage: 2.4GB / 8GB</p>
                    <div className="w-full bg-gray-800 h-2 rounded-full overflow-hidden">
                      <div className="bg-neon-cyan h-full" style={{ width: '30%' }}></div>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}

const NavItem = ({ icon, label, active, onClick }: any) => (
  <button
    onClick={onClick}
    className={`flex items-center gap-3 p-3 rounded-lg transition-all ${active ? 'bg-neon-green text-black font-bold scale-105' : 'text-gray-400 hover:bg-gray-800'}`}
  >
    {React.cloneElement(icon, { size: 20 })}
    <span>{label}</span>
  </button>
);

const StatCard = ({ label, value, trend, color = "text-neon-green" }: any) => (
  <div className="glass-card border-none bg-[#1a1c24] flex flex-col gap-1">
    <span className="text-xs text-gray-500 uppercase tracking-widest">{label}</span>
    <span className={`text-2xl font-bold ${color}`}>{value}</span>
    <span className="text-[10px] text-gray-600">{trend}</span>
  </div>
);

const StatusItem = ({ label, status }: any) => (
  <div className="flex justify-between items-center border-b border-gray-800 pb-2">
    <span className="text-gray-400">{label}</span>
    <span className="text-neon-green text-sm font-bold uppercase">{status}</span>
  </div>
);

export default App;
