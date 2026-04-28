import { useState, useEffect, useRef, useMemo } from 'react';
import axios from 'axios';
import {
  LayoutDashboard, Search, Skull, Globe, Play, Eye, Activity,
  Lock, ChevronRight, AlertTriangle, Server, Network, ShieldOff, RefreshCw,
  Mail, Trash2, HardDrive, Wifi, CheckCircle2, XCircle, GitBranch, Clock,
  Users as UsersIcon, LogOut, UserPlus, ArrowDownToLine, ArrowUpFromLine,
  Cpu, Radio, Sparkles, KeyRound, GitFork, TerminalSquare, Volume2, VolumeX,
  Crosshair, MessageSquare, FileText, X as XClose, Play as PlayIcon,
  Search as SearchIcon,
} from 'lucide-react';
import ForceGraph2D from 'react-force-graph-2d';
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  Cell,
} from 'recharts';
import { motion, AnimatePresence } from 'framer-motion';
import { translations } from './i18n';
import logoEN from './assets/logo.png';
import logoAR from './assets/logo_ar.png';

// Auto-detect the API host from the URL the dashboard was loaded from.
// Works on localhost, on the VPS public IP, on a real domain — no rebuild needed.
const API_BASE = (import.meta as any).env?.VITE_API_BASE
  || (typeof window !== 'undefined'
      ? `${window.location.protocol}//${window.location.hostname}:8000`
      : 'http://localhost:8000');
const TOKEN_KEY = 'husn.token';
const USER_KEY = 'husn.user';

interface AuthUser { username: string; role: string; }
interface Vulnerability { id: string; name: string; severity: string; description: string; }

// ---------------- helpers
// Brief two-tone chime via Web Audio API. No external file. Plays on every
// new High/Critical block when the user has audio enabled.
const playAlertChime = () => {
  try {
    const Ctx = (window as any).AudioContext || (window as any).webkitAudioContext;
    if (!Ctx) return;
    const ctx = new Ctx();
    const tone = (freq: number, t0: number, dur: number) => {
      const osc = ctx.createOscillator();
      const g = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.value = freq;
      g.gain.setValueAtTime(0, ctx.currentTime + t0);
      g.gain.linearRampToValueAtTime(0.18, ctx.currentTime + t0 + 0.02);
      g.gain.linearRampToValueAtTime(0, ctx.currentTime + t0 + dur);
      osc.connect(g); g.connect(ctx.destination);
      osc.start(ctx.currentTime + t0);
      osc.stop(ctx.currentTime + t0 + dur + 0.05);
    };
    tone(880, 0,    0.18);
    tone(660, 0.16, 0.22);
    setTimeout(() => ctx.close(), 700);
  } catch { /* ignore */ }
};

const fmtBytes = (n: number) => {
  if (!n) return '0 B/s';
  const u = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
};
const fmtNum = (n: number) => n?.toLocaleString() ?? '0';
const fmtUptime = (s: number) => {
  if (!s) return '—';
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
};

function App() {
  // ---------- auth
  const [token, setToken] = useState<string | null>(() => localStorage.getItem(TOKEN_KEY));
  const [authUser, setAuthUser] = useState<AuthUser | null>(() => {
    try { return JSON.parse(localStorage.getItem(USER_KEY) || 'null'); } catch { return null; }
  });
  const [authError, setAuthError] = useState<string | null>(null);
  const isAdmin = authUser?.role === 'admin';

  const api = useMemo(() => {
    const a = axios.create({ baseURL: API_BASE });
    if (token) a.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    a.interceptors.response.use(
      (r) => r,
      (err) => {
        if (err?.response?.status === 401) {
          setToken(null); setAuthUser(null);
          localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USER_KEY);
          setAuthError('sessionExpired');
        }
        return Promise.reject(err);
      },
    );
    return a;
  }, [token]);

  // ---------- ui state
  const [lang, setLang] = useState<'en' | 'ar'>('en');
  const [activeTab, setActiveTab] = useState('dashboard');
  const [target, setTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<Vulnerability[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [shapData, setShapData] = useState<any>(null);
  const [isExplaining, setIsExplaining] = useState(false);
  const [systemStatus, setSystemStatus] = useState<any>(null);
  const [isToggling, setIsToggling] = useState(false);

  // ---------- data state (real)
  const [hwSnapshot, setHwSnapshot] = useState<any>(null);
  const [trafficSnap, setTrafficSnap] = useState<any>(null);
  const [monitor, setMonitor] = useState<any>(null);
  const [ports, setPorts] = useState<any[]>([]);
  const [procs, setProcs] = useState<any[]>([]);
  const [procsSusOnly, setProcsSusOnly] = useState(false);
  const [connections, setConnections] = useState<any>(null);
  const [blocked, setBlocked] = useState<any[]>([]);
  const [recipients, setRecipients] = useState<string[]>([]);
  const [smtpEnabled, setSmtpEnabled] = useState(false);
  const [newRecipient, setNewRecipient] = useState('');
  const [updateStatus, setUpdateStatus] = useState<any>(null);
  const [isCheckingUpdate, setIsCheckingUpdate] = useState(false);
  const [isApplyingUpdate, setIsApplyingUpdate] = useState(false);
  const [audit, setAudit] = useState<{ events: string[]; total: number } | null>(null);

  const [userList, setUserList] = useState<any[]>([]);
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'employee' });
  const [userError, setUserError] = useState<string | null>(null);

  // New: sniffer / honeypot / terminal / audio
  const [snifferStatus, setSnifferStatus] = useState<any>(null);
  const [honeypotStatus, setHoneypotStatus] = useState<any>(null);
  const [cliCommands, setCliCommands] = useState<string[]>([]);
  const [cliCmd, setCliCmd] = useState('sysinfo');
  const [cliArgs, setCliArgs] = useState('');
  const [cliOut, setCliOut] = useState<{ html: string; text: string } | null>(null);
  const [cliBusy, setCliBusy] = useState(false);
  const [audioOn, setAudioOn] = useState<boolean>(() => localStorage.getItem('husn.audio') !== 'off');

  // Defense lists (IP + country whitelist/blacklist)
  const [defLists, setDefLists] = useState<any>(null);
  const [newIpAllow, setNewIpAllow] = useState('');
  const [newIpDeny, setNewIpDeny] = useState('');
  const [newCcAllow, setNewCcAllow] = useState('');
  const [newCcDeny, setNewCcDeny] = useState('');

  // Notify settings + chat + reports + investigate
  const [notifyState, setNotifyState] = useState<any>(null);
  const [chatStatus, setChatStatus] = useState<any>(null);
  const [chatHistory, setChatHistory] = useState<any[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [chatBusy, setChatBusy] = useState(false);
  const [reportSched, setReportSched] = useState<any>(null);
  const [reportList, setReportList] = useState<any[]>([]);
  const [reportBusy, setReportBusy] = useState(false);
  const [investigateIp, setInvestigateIp] = useState<string | null>(null);
  const [investigateData, setInvestigateData] = useState<any>(null);
  const [investigateBusy, setInvestigateBusy] = useState(false);

  const T = translations[lang];
  const logScrollRef = useRef<HTMLDivElement>(null);
  const prevLogCount = useRef(0);
  const followLog = useRef(true);

  // Auto-tail the log panel: only scroll to the bottom when (a) new lines
  // were actually appended (not on every poll re-fetch) and (b) the user
  // hasn't deliberately scrolled away. The onScroll handler on the log
  // container flips followLog off the moment the user scrolls up, and only
  // re-arms it when they're back at the very bottom.
  useEffect(() => {
    const el = logScrollRef.current;
    if (!el) return;
    const grew = logs.length > prevLogCount.current;
    prevLogCount.current = logs.length;
    if (grew && followLog.current) {
      el.scrollTop = el.scrollHeight;
    }
  }, [logs]);

  const onLogScroll = (e: any) => {
    const el = e.currentTarget as HTMLDivElement;
    followLog.current = (el.scrollHeight - el.scrollTop - el.clientHeight) < 4;
  };

  // ---------- polling
  useEffect(() => {
    if (!token) return;
    const id = setInterval(() => {
      fetchMonitor(); fetchStatus(); fetchLogs(); fetchTraffic();
      fetchSniffer(); fetchHoneypot();
    }, 2000);
    return () => clearInterval(id);
  }, [token]);
  useEffect(() => {
    if (!token) return;
    const tick = () => {
      fetchHardware(); fetchPorts(); fetchProcs(); fetchBlocked();
      fetchRecipients(); fetchUpdateStatus(); fetchConnections();
      fetchDefLists(); fetchNotifyState(); fetchChatStatus();
      fetchReportSched(); fetchReportList();
      if (isAdmin) { fetchUsers(); fetchAudit(); }
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => clearInterval(id);
  }, [token, isAdmin, procsSusOnly]);

  // Fetch the CLI command whitelist once after login.
  useEffect(() => {
    if (!token) return;
    api.get('/cli/commands').then(r => {
      setCliCommands(r.data.commands || []);
      if (r.data.commands?.length && !r.data.commands.includes(cliCmd)) setCliCmd(r.data.commands[0]);
    }).catch(() => {});
  }, [token]);

  // Audio chime on every NEW high/critical block. Tracks the most recent
  // blocked_at we've seen so we don't replay on dashboard refresh.
  const lastSeenBlockTs = useRef(0);
  useEffect(() => {
    if (!audioOn || !blocked.length) return;
    const newHigh = blocked.find(
      (b: any) => b.blocked_at > lastSeenBlockTs.current
        && (b.severity === 'High' || b.severity === 'Critical'),
    );
    const maxTs = blocked.reduce((m: number, b: any) => Math.max(m, b.blocked_at), 0);
    if (lastSeenBlockTs.current === 0) {
      lastSeenBlockTs.current = maxTs; // first load — don't sound
      return;
    }
    if (newHigh) playAlertChime();
    lastSeenBlockTs.current = maxTs;
  }, [blocked, audioOn]);

  // ---------- API
  const fetchMonitor = async () => { try { setMonitor((await api.get('/monitor')).data); } catch {} };
  const fetchTraffic = async () => { try { setTrafficSnap((await api.get('/system/traffic')).data); } catch {} };
  const fetchStatus = async () => { try { setSystemStatus((await api.get('/status')).data); } catch {} };
  const fetchLogs = async () => { try { setLogs((await api.get('/logs')).data); } catch {} };
  const fetchHardware = async () => { try { setHwSnapshot((await api.get('/system/hardware')).data); } catch {} };
  const fetchPorts = async () => { try { setPorts((await api.get('/system/ports')).data); } catch {} };
  const fetchProcs = async () => {
    try { setProcs((await api.get('/system/processes', { params: { suspicious_only: procsSusOnly } })).data); } catch {}
  };
  const fetchConnections = async () => { try { setConnections((await api.get('/system/connections')).data); } catch {} };
  const fetchBlocked = async () => { try { setBlocked((await api.get('/blocked')).data); } catch {} };
  const fetchRecipients = async () => {
    try { const r = await api.get('/recipients'); setRecipients(r.data.recipients); setSmtpEnabled(r.data.smtp_enabled); } catch {}
  };
  const fetchUpdateStatus = async () => { try { setUpdateStatus((await api.get('/updates/status')).data); } catch {} };
  const fetchAudit = async () => { try { setAudit((await api.get('/auth/audit')).data); } catch {} };
  const fetchSniffer = async () => { try { setSnifferStatus((await api.get('/sniffer/status')).data); } catch {} };
  const fetchHoneypot = async () => { try { setHoneypotStatus((await api.get('/honeypot/status')).data); } catch {} };
  const fetchDefLists = async () => { try { setDefLists((await api.get('/defense/lists')).data); } catch {} };
  const fetchNotifyState = async () => { try { setNotifyState((await api.get('/notify/settings')).data); } catch {} };
  const fetchChatStatus = async () => { try { setChatStatus((await api.get('/chat/status')).data); } catch {} };
  const fetchReportSched = async () => { try { setReportSched((await api.get('/reports/schedule')).data); } catch {} };
  const fetchReportList = async () => { try { setReportList((await api.get('/reports/list')).data); } catch {} };

  const setMinSeverity = async (s: string) => {
    try { setNotifyState((await api.post('/notify/settings/severity', { min_severity: s })).data); } catch {}
  };
  const pauseEmails = async (seconds: number) => {
    try { setNotifyState((await api.post('/notify/settings/pause', { seconds })).data); } catch {}
  };

  const sendChat = async () => {
    if (!chatInput.trim()) return;
    const userMsg = chatInput.trim();
    setChatHistory((h) => [...h, { role: 'user', content: userMsg }]);
    setChatInput(''); setChatBusy(true);
    try {
      const r = await api.post('/chat/send', { message: userMsg, session_id: 'main' });
      const replyText = r.data?.ok ? r.data.reply : (r.data?.error || 'unknown error');
      setChatHistory((h) => [...h, { role: 'assistant', content: replyText, ok: r.data?.ok }]);
    } catch (e: any) {
      setChatHistory((h) => [...h, { role: 'assistant', content: e?.message || 'request failed', ok: false }]);
    }
    setChatBusy(false);
  };
  const resetChat = async () => {
    try { await api.post('/chat/reset', { message: '', session_id: 'main' }); } catch {}
    setChatHistory([]);
  };

  const setReportSchedule = async (frequency: string, hour: number, weekday: number) => {
    try { setReportSched((await api.post('/reports/schedule', { frequency, hour, weekday })).data); } catch {}
  };
  const runReportNow = async () => {
    setReportBusy(true);
    try { await api.post('/reports/run-now'); await fetchReportList(); addLog('REPORTS: manual report generated'); }
    catch { addLog('[ERR] report generation failed'); }
    setReportBusy(false);
  };

  const investigate = async (ip: string) => {
    setInvestigateIp(ip); setInvestigateData(null); setInvestigateBusy(true);
    try { setInvestigateData((await api.get(`/investigate/${encodeURIComponent(ip)}`)).data); }
    catch (e: any) { setInvestigateData({ error: e?.message || 'failed' }); }
    setInvestigateBusy(false);
  };
  const closeInvestigate = () => { setInvestigateIp(null); setInvestigateData(null); };

  const addToList = async (kind: string, value: string) => {
    if (!value.trim()) return;
    try { await api.post(`/defense/lists/${kind}`, { value: value.trim() }); fetchDefLists(); addLog(`DEFENSE: added ${value} to ${kind}`); }
    catch (e: any) { alert(e?.response?.data?.detail || 'failed'); }
  };
  const removeFromList = async (kind: string, value: string) => {
    try { await api.delete(`/defense/lists/${kind}/${encodeURIComponent(value)}`); fetchDefLists(); addLog(`DEFENSE: removed ${value} from ${kind}`); }
    catch (e: any) { alert(e?.response?.data?.detail || 'failed'); }
  };

  const runCli = async () => {
    if (!cliCmd) return;
    setCliBusy(true); setCliOut(null);
    try {
      const r = await api.post('/cli/run', { command: cliCmd, args: cliArgs });
      setCliOut({ html: r.data.html || '', text: r.data.text || r.data.error || '' });
    } catch (e: any) {
      setCliOut({ html: '', text: e?.response?.data?.detail || 'request failed' });
    }
    setCliBusy(false);
  };

  const toggleAudio = () => {
    setAudioOn(v => {
      const nv = !v;
      localStorage.setItem('husn.audio', nv ? 'on' : 'off');
      return nv;
    });
  };

  const toggleDefense = async () => {
    setIsToggling(true);
    try { await api.post('/toggle-defense'); await fetchStatus(); } catch {}
    setIsToggling(false);
  };
  const addLog = (msg: string) => setLogs((p) => [...p, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  const startScan = async () => {
    if (!target) return;
    setIsScanning(true); setResults([]);
    addLog(`SCAN: ${target}`);
    try {
      const res = await api.post('/scan', { target });
      setTimeout(() => {
        setResults(res.data.map((r: any, i: number) => ({
          id: i.toString(), name: r.label, severity: r.severity,
          description: `Confidence ${(r.confidence * 100).toFixed(1)}% · ${r.action || 'No action'}`,
        })));
        setIsScanning(false);
        addLog(`SCAN done.`);
      }, 800);
    } catch { addLog(`[ERR] backend offline`); setIsScanning(false); }
  };
  const triggerSim = async (type: string) => {
    addLog(`SIM: ${type} → ${target || '127.0.0.1'}`);
    try { await api.post('/simulate', { target_ip: target || '127.0.0.1', attack_type: type }); }
    catch { addLog(`[ERR] simulation engine offline`); }
    setTimeout(() => { fetchBlocked(); fetchLogs(); fetchAudit(); }, 1200);
  };
  const fetchExplanation = async () => { setIsExplaining(true); try { setShapData((await api.get('/explain')).data); } catch {} setIsExplaining(false); };
  const unblockIp = async (ip: string) => {
    try { await api.post(`/blocked/${encodeURIComponent(ip)}/unblock`); fetchBlocked(); addLog(`UNBLOCK: ${ip}`); } catch {}
  };
  const sendTestEmail = async () => {
    addLog('TEST_ALERT: dispatch');
    try {
      const r = await api.post('/test-alert');
      const em = r.data?.email;
      if (em?.ok) addLog(`mail delivered → ${em.to.join(', ')}`);
      else if (r.data?.throttled) addLog('throttled — retry in a minute');
      else addLog(`[ERR] ${em?.detail || 'mail failed'}`);
    } catch { addLog('[ERR] /test-alert failed'); }
  };
  const addRecipientFn = async () => {
    if (!newRecipient.includes('@')) return;
    try { await api.post('/recipients', { email: newRecipient }); setNewRecipient(''); fetchRecipients(); } catch {}
  };
  const removeRecipient = async (email: string) => {
    try { await api.delete(`/recipients/${encodeURIComponent(email)}`); fetchRecipients(); } catch {}
  };
  const checkForUpdate = async () => {
    setIsCheckingUpdate(true);
    try { await api.post('/updates/check'); await fetchUpdateStatus(); addLog('UPDATER: check'); } catch {}
    setIsCheckingUpdate(false);
  };
  const applyUpdate = async () => {
    setIsApplyingUpdate(true);
    try { const r = await api.post('/updates/apply'); addLog(`UPDATER: ${r.data?.message || 'apply done'}`); await fetchUpdateStatus(); }
    catch { addLog('[ERR] apply failed'); }
    setIsApplyingUpdate(false);
  };

  const login = async (u: string, p: string) => {
    setAuthError(null);
    try {
      const r = await axios.post(`${API_BASE}/auth/login`, { username: u, password: p });
      localStorage.setItem(TOKEN_KEY, r.data.token);
      localStorage.setItem(USER_KEY, JSON.stringify(r.data.user));
      setToken(r.data.token); setAuthUser(r.data.user);
    } catch (e: any) {
      setAuthError(e?.response?.status === 401 ? 'loginFailed' : 'loginNetwork');
    }
  };
  const logout = () => {
    setToken(null); setAuthUser(null);
    localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USER_KEY);
    setActiveTab('dashboard');
  };
  const fetchUsers = async () => { try { setUserList((await api.get('/auth/users')).data.users); } catch {} };
  const createUser = async () => {
    setUserError(null);
    if (!newUser.username || newUser.password.length < 4) { setUserError(T.userInvalid); return; }
    try { await api.post('/auth/users', newUser); setNewUser({ username: '', password: '', role: 'employee' }); fetchUsers(); addLog(`AUTH: created ${newUser.username}`); }
    catch (e: any) { setUserError(e?.response?.data?.detail || 'failed'); }
  };
  const deleteUser = async (u: string) => {
    if (u === authUser?.username) return;
    if (!confirm(`${T.confirmDelete} ${u}`)) return;
    try { await api.delete(`/auth/users/${encodeURIComponent(u)}`); fetchUsers(); addLog(`AUTH: deleted ${u}`); }
    catch (e: any) { alert(e?.response?.data?.detail || 'delete failed'); }
  };

  // ---------- gate
  if (!token || !authUser) {
    return <Login lang={lang} setLang={setLang} T={T} error={authError} onSubmit={login} />;
  }

  // Build the chart data series from the real traffic sliding window.
  const trafficSeries = (trafficSnap?.totals || []).slice(-60).map((p: any, i: number) => ({
    i,
    inn: p.bytes_in_per_s,
    out: p.bytes_out_per_s,
  }));

  return (
    <div className={`fixed inset-0 bg-husn-bg text-husn-text flex p-4 gap-4 ${lang === 'ar' ? 'rtl' : 'ltr'}`} dir={lang === 'ar' ? 'rtl' : 'ltr'}>
      {/* ============ Investigation modal (overlays everything) ============ */}
      {investigateIp && (
        <InvestigateModal
          ip={investigateIp}
          data={investigateData}
          busy={investigateBusy}
          T={T}
          isAdmin={isAdmin}
          onClose={closeInvestigate}
          onWhitelist={() => { addToList('ip-allow', investigateIp); closeInvestigate(); }}
          onBlacklist={() => { addToList('ip-deny', investigateIp); closeInvestigate(); }}
          onAskSoc={() => {
            setActiveTab('chat');
            setChatInput(`Please analyse IP ${investigateIp} and recommend an action.`);
            closeInvestigate();
          }}
        />
      )}
      {/* Build marker — confirm you have the latest code. Remove before contest. */}
      <div className="fixed bottom-2 right-3 text-[10px] text-husn-text-3 font-mono pointer-events-none z-50 opacity-60">
        husn-ui · scroll-fix-v3
      </div>
      {/* ============ Sidebar (floating card) ============ */}
      <aside className="husn-card flex flex-col w-60 shrink-0 overflow-hidden">
        <div className="px-6 py-7 flex justify-center items-center">
          <img
            src={lang === 'ar' ? logoAR : logoEN}
            alt="Husn"
            className="w-32 h-auto object-contain husn-logo-glow"
          />
        </div>

        <nav className="flex-1 px-3 py-2 space-y-0.5 overflow-y-auto">
          <NavLink icon={<LayoutDashboard size={16}/>} label={T.monitoring} active={activeTab === 'dashboard'} onClick={() => setActiveTab('dashboard')}/>
          <NavLink icon={<Server size={16}/>} label={T.host} active={activeTab === 'host'} onClick={() => setActiveTab('host')}/>
          <NavLink icon={<Network size={16}/>} label={T.network} active={activeTab === 'network'} onClick={() => setActiveTab('network')}/>
          <NavLink icon={<Radio size={16}/>} label={T.connections || 'Connections'} active={activeTab === 'connections'} onClick={() => setActiveTab('connections')}
            badge={connections?.total > 0 ? connections.total : undefined}/>
          <NavLink icon={<GitFork size={16}/>} label={T.topology} active={activeTab === 'topology'} onClick={() => setActiveTab('topology')}/>
          <NavLink icon={<Search size={16}/>} label={T.detection} active={activeTab === 'recon'} onClick={() => setActiveTab('recon')}/>
          <NavLink icon={<Skull size={16}/>} label={T.simulation} active={activeTab === 'exploits'} onClick={() => setActiveTab('exploits')}/>
          <NavLink icon={<Crosshair size={16}/>} label={T.honeypot} active={activeTab === 'honeypot'} onClick={() => setActiveTab('honeypot')}
            dot={(honeypotStatus?.connections_total ?? 0) > 0}/>
          <NavLink icon={<Eye size={16}/>} label={T.explainableAI} active={activeTab === 'xai'} onClick={() => setActiveTab('xai')}/>
          <NavLink icon={<ShieldOff size={16}/>} label={T.defense} active={activeTab === 'defense'} onClick={() => setActiveTab('defense')}
            badge={blocked.length > 0 ? blocked.length : undefined}/>
          <NavLink icon={<RefreshCw size={16}/>} label={T.updates} active={activeTab === 'updates'} onClick={() => setActiveTab('updates')}
            dot={updateStatus?.last_check?.available}/>
          <NavLink icon={<MessageSquare size={16}/>} label={T.chat} active={activeTab === 'chat'} onClick={() => setActiveTab('chat')}
            dot={chatStatus?.configured && chatHistory.length === 0 ? false : undefined}/>
          <NavLink icon={<FileText size={16}/>} label={T.reports} active={activeTab === 'reports'} onClick={() => setActiveTab('reports')}/>
          {isAdmin && <NavLink icon={<TerminalSquare size={16}/>} label={T.terminal} active={activeTab === 'terminal'} onClick={() => setActiveTab('terminal')}/>}
          {isAdmin && <NavLink icon={<UsersIcon size={16}/>} label={T.users} active={activeTab === 'users'} onClick={() => setActiveTab('users')}/>}
        </nav>

        {/* National Defense card (replaces "Upgrade to Premium" in the reference) */}
        <div className="m-3 p-4 rounded-2xl border border-husn-border bg-black/20">
          <div className="flex items-center gap-2 mb-1.5">
            <Sparkles size={14} className={systemStatus?.defense_mode === 'National' ? 'text-husn-danger' : 'text-husn-text-3'}/>
            <span className="text-[11px] text-husn-text-2 font-medium">{T.nationalDefense}</span>
          </div>
          <p className="text-[11px] text-husn-text-3 leading-snug mb-3">
            {systemStatus?.defense_mode === 'National'
              ? (lang === 'en' ? 'Active. Detection threshold raised.' : 'مفعّل. عتبة الاكتشاف مرفوعة.')
              : (lang === 'en' ? 'Standby. Standard threshold.' : 'احتياطي. العتبة الافتراضية.')}
          </p>
          <button onClick={toggleDefense} disabled={isToggling || !isAdmin}
            title={!isAdmin ? 'Admin only' : ''}
            className={`w-full text-xs font-medium py-2 rounded-lg transition disabled:opacity-30 disabled:cursor-not-allowed
              ${systemStatus?.defense_mode === 'National'
                ? 'bg-husn-danger/15 text-husn-danger hover:bg-husn-danger/25 border border-husn-danger/30'
                : 'bg-white text-husn-bg hover:opacity-90'}`}>
            {systemStatus?.defense_mode === 'National' ? T.deactivate || 'Deactivate' : T.activate || 'Activate'}
          </button>
        </div>

        {/* Lang + logout footer */}
        <div className="px-4 pb-4 flex items-center justify-between text-husn-text-3 text-xs">
          <button onClick={() => setLang(lang === 'en' ? 'ar' : 'en')} className="flex items-center gap-1.5 hover:text-white transition">
            <Globe size={12}/> {lang === 'en' ? 'العربية' : 'English'}
          </button>
        </div>
      </aside>

      {/* ============ Main column ============ */}
      <main className="flex-1 min-w-0 min-h-0 flex flex-col gap-4 overflow-hidden">
        {/* Header bar */}
        <header className="husn-card px-6 py-4 flex items-center gap-4">
          <div className="flex items-center gap-2 text-husn-text-2 text-sm">
            <LayoutDashboard size={16}/>
            <span className="capitalize">{tabTitle(activeTab, T)}</span>
          </div>
          <div className="flex-1 max-w-md mx-auto relative">
            <Search size={14} className={`absolute top-2.5 ${lang === 'ar' ? 'right-3' : 'left-3'} text-husn-text-3`}/>
            <input className={`husn-input w-full text-sm ${lang === 'ar' ? 'pr-9 pl-3' : 'pl-9 pr-3'}`}
              placeholder={T.target} value={target} onChange={(e) => setTarget(e.target.value)}/>
          </div>
          <button onClick={startScan} disabled={isScanning || !target || !isAdmin}
            title={!isAdmin ? 'Admin only' : ''}
            className="husn-btn-primary text-sm flex items-center gap-2">
            {isScanning ? <Activity size={14} className="animate-spin"/> : <Play size={14}/>}
            {isScanning ? T.scanning || 'Scanning...' : T.runScan}
          </button>
          {/* audio toggle + user chip */}
          <button onClick={toggleAudio} title={audioOn ? T.audioOn : T.audioOff}
            className={`p-2 rounded-lg border transition ${audioOn ? 'border-husn-border-2 text-white bg-white/[0.04]' : 'border-husn-border text-husn-text-3 hover:text-white'}`}>
            {audioOn ? <Volume2 size={14}/> : <VolumeX size={14}/>}
          </button>
          <div className={`flex items-center gap-3 ${lang === 'ar' ? 'mr-2' : 'ml-2'} pr-2 pl-2`}>
            <div className="text-right">
              <div className="text-xs text-white font-medium leading-tight">{authUser?.username}</div>
              <div className="text-[10px] text-husn-text-3 capitalize">{authUser?.role === 'admin' ? T.admin : T.employee}</div>
            </div>
            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-semibold
              ${authUser?.role === 'admin' ? 'bg-white text-husn-bg' : 'bg-white/10 text-white'}`}>
              {(authUser?.username || '?').slice(0, 1).toUpperCase()}
            </div>
            <button onClick={logout} className="text-husn-text-3 hover:text-husn-danger transition" title={T.signOut}>
              <LogOut size={16}/>
            </button>
          </div>
        </header>

        {/* Welcome line */}
        <div className="flex items-end justify-between mt-1 px-1">
          <div>
            <h1 className="text-[24px] font-light uppercase tracking-[0.18em] text-white leading-tight">
              {lang === 'en' ? `Welcome back, ${authUser?.username}` : `مرحباً، ${authUser?.username}`}
            </h1>
            <p className="text-husn-text-3 text-sm mt-0.5">
              {hwSnapshot?.os?.hostname || '—'} · {systemStatus?.organization || ''}
            </p>
          </div>
          <div className="text-right">
            <div className="text-[11px] text-husn-text-3">{lang === 'en' ? 'Defense mode' : 'وضع الدفاع'}</div>
            <div className={`text-sm font-medium ${systemStatus?.defense_mode === 'National' ? 'text-husn-danger' : 'text-white'}`}>
              {systemStatus?.defense_mode || '—'}
            </div>
          </div>
        </div>

        {/* Tab content */}
        <div className="flex gap-4 min-h-0 flex-1">
          <div className="flex-1 min-w-0 overflow-y-auto pb-2">
            <AnimatePresence mode="wait">
              {activeTab === 'dashboard' && (
                <Tab k="dashboard">
                  {/* KPIs */}
                  <div className="grid grid-cols-4 gap-4">
                    <Kpi label={T.incomingNow || 'Incoming'} value={fmtBytes(monitor?.incoming_bps ?? 0)}
                      sub={`${fmtNum(monitor?.incoming_pps ?? 0)} pkts/s`} icon={<ArrowDownToLine size={16}/>}/>
                    <Kpi label={T.outgoingNow || 'Outgoing'} value={fmtBytes(monitor?.outgoing_bps ?? 0)}
                      sub={`${fmtNum(monitor?.outgoing_pps ?? 0)} pkts/s`} icon={<ArrowUpFromLine size={16}/>}/>
                    <Kpi label={T.blockedIps} value={fmtNum(monitor?.blocked_now ?? 0)}
                      sub={`${monitor?.blocks_total ?? 0} ${T.totalBlocks || 'lifetime'}`}
                      icon={<ShieldOff size={16}/>} highlight={(monitor?.blocked_now ?? 0) > 0}/>
                    <Kpi label={T.uptime} value={fmtUptime(monitor?.uptime_seconds ?? 0)}
                      sub={hwSnapshot?.os?.system || ''} icon={<Clock size={16}/>}/>
                  </div>

                  {/* Real-time sniffer + honeypot status row */}
                  <div className="grid grid-cols-2 gap-4 mt-4">
                    <SnifferCard s={snifferStatus} T={T}/>
                    <HoneypotCard s={honeypotStatus} T={T}/>
                  </div>

                  {/* Real traffic chart + Recent activity side-by-side */}
                  <div className="grid grid-cols-3 gap-4 mt-4">
                    <div className="col-span-2 husn-card p-5">
                      <div className="flex justify-between items-center mb-4">
                        <div>
                          <h3 className="text-[14px] font-light uppercase tracking-[0.18em] text-white">{T.realTraffic || 'Real-time network traffic'}</h3>
                          <p className="text-husn-text-3 text-xs mt-0.5">
                            {trafficSnap?.interfaces?.length
                              ? `${trafficSnap.interfaces.join(' · ')} · ${trafficSeries.length}s window`
                              : (lang === 'en' ? 'Sampler warming up...' : 'جارٍ تهيئة العيّنة...')}
                          </p>
                        </div>
                        <div className="flex gap-3 text-[11px] text-husn-text-2">
                          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-white"/>{T.in || 'In'}</span>
                          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-husn-text-3"/>{T.out || 'Out'}</span>
                        </div>
                      </div>
                      <div className="h-56">
                        <ResponsiveContainer width="100%" height="100%">
                          <AreaChart data={trafficSeries} margin={{ left: 0, right: 0, top: 8, bottom: 0 }}>
                            <defs>
                              <linearGradient id="g-in" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="0%" stopColor="#ffffff" stopOpacity={0.18}/>
                                <stop offset="100%" stopColor="#ffffff" stopOpacity={0}/>
                              </linearGradient>
                              <linearGradient id="g-out" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="0%" stopColor="#8b919e" stopOpacity={0.18}/>
                                <stop offset="100%" stopColor="#8b919e" stopOpacity={0}/>
                              </linearGradient>
                            </defs>
                            <XAxis dataKey="i" hide/>
                            <YAxis hide/>
                            <Tooltip contentStyle={{ backgroundColor: '#0a0e18', border: '1px solid #2a3142', borderRadius: 8, fontSize: 12 }}
                              formatter={(v: any) => fmtBytes(Number(v))}/>
                            <Area type="monotone" dataKey="inn" stroke="#ffffff" strokeWidth={1.8} fill="url(#g-in)" dot={false} isAnimationActive={false}/>
                            <Area type="monotone" dataKey="out" stroke="#8b919e" strokeWidth={1.5} fill="url(#g-out)" dot={false} strokeDasharray="3 3" isAnimationActive={false}/>
                          </AreaChart>
                        </ResponsiveContainer>
                      </div>
                    </div>

                    {/* Recent blocks */}
                    <div className="husn-card p-5 flex flex-col">
                      <div className="flex justify-between items-center mb-3">
                        <h3 className="text-[14px] font-light uppercase tracking-[0.18em] text-white">{T.recentBlocks || 'Recent blocks'}</h3>
                        <span className="text-[11px] text-husn-text-3">{blocked.length}</span>
                      </div>
                      <div className="flex-1 space-y-2 overflow-y-auto">
                        {blocked.length === 0 && (
                          <div className="text-center py-12 text-husn-text-3 text-xs">
                            <ShieldOff size={28} className="mx-auto opacity-40 mb-2"/>
                            {T.noBlocked}
                          </div>
                        )}
                        {blocked.slice(0, 8).map((b: any) => (
                          <div key={b.ip + b.blocked_at} className="flex items-center justify-between px-3 py-2 rounded-lg hover:bg-white/[0.03] transition">
                            <div className="min-w-0">
                              <div className="text-sm text-white font-mono truncate">{b.ip}</div>
                              <div className="text-[11px] text-husn-text-3 truncate">{b.attack_type} · {(b.confidence * 100).toFixed(0)}%</div>
                            </div>
                            <span className="text-[11px] text-husn-text-3 shrink-0 ml-2">
                              {new Date(b.blocked_at * 1000).toLocaleTimeString()}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* SIEM feed */}
                  {results.length > 0 && (
                    <div className="mt-4 husn-card p-5">
                      <h3 className="text-[14px] font-light uppercase tracking-[0.18em] text-white mb-3">{T.siemFeed}</h3>
                      <div className="space-y-2">
                        {results.map((v) => (
                          <div key={v.id} className="flex items-center justify-between px-4 py-3 rounded-lg border border-husn-border hover:border-husn-border-2 transition">
                            <div className="flex items-center gap-3">
                              <SeverityPill sev={v.severity} T={T}/>
                              <div>
                                <div className="text-sm text-white font-medium">{v.name}</div>
                                <div className="text-[11px] text-husn-text-3">{v.description}</div>
                              </div>
                            </div>
                            <ChevronRight size={16} className={`text-husn-text-3 ${lang === 'ar' ? 'rotate-180' : ''}`}/>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </Tab>
              )}

              {activeTab === 'host' && (
                <Tab k="host">
                  <div className="grid grid-cols-3 gap-4">
                    <GaugeCard label={T.cpu} pct={hwSnapshot?.cpu?.usage_percent ?? 0}
                      sub={`${hwSnapshot?.cpu?.physical_cores}c · ${hwSnapshot?.cpu?.frequency_mhz}MHz`}/>
                    <GaugeCard label={T.memory} pct={hwSnapshot?.memory?.percent ?? 0}
                      sub={`${hwSnapshot?.memory?.used_gb ?? 0} / ${hwSnapshot?.memory?.total_gb ?? 0} GB`}/>
                    <GaugeCard label={T.uptime} pct={null}
                      bigText={fmtUptime(hwSnapshot?.os?.uptime_seconds ?? 0)}
                      sub={`${hwSnapshot?.os?.system ?? ''} ${hwSnapshot?.os?.release ?? ''}`}/>
                  </div>

                  <div className="grid grid-cols-2 gap-4 mt-4">
                    <Card title={T.disks} icon={<HardDrive size={14}/>}>
                      <Tbl headers={[T.mountpoint, T.fstype, T.total, T.used, '%']} rows={
                        (hwSnapshot?.disks || []).map((d: any) => [
                          d.mountpoint, <span className="text-husn-text-3">{d.fstype}</span>,
                          `${d.total_gb}G`, `${d.used_gb}G`,
                          <span className={d.percent > 90 ? 'text-husn-danger' : d.percent > 75 ? 'text-husn-warn' : 'text-husn-success'}>{d.percent}%</span>
                        ])
                      }/>
                    </Card>
                    <Card title={T.interfaces} icon={<Wifi size={14}/>}>
                      <Tbl headers={['Iface', 'IPv4', 'MAC', T.up || 'Up', 'Mb/s']} rows={
                        (hwSnapshot?.interfaces || []).map((i: any) => [
                          i.name, i.ipv4 || '—',
                          <span className="text-husn-text-3 text-[11px]">{i.mac || '—'}</span>,
                          i.is_up ? <CheckCircle2 size={14} className="text-husn-success"/> : <XCircle size={14} className="text-husn-text-3"/>,
                          i.speed_mbps,
                        ])
                      }/>
                    </Card>
                  </div>

                  <div className="mt-4">
                    <Card title={T.os} icon={<Server size={14}/>}>
                      <div className="grid grid-cols-2 gap-x-12 gap-y-2 text-sm">
                        <KV k={T.hostname} v={hwSnapshot?.os?.hostname}/>
                        <KV k="FQDN" v={hwSnapshot?.os?.fqdn}/>
                        <KV k={T.os} v={`${hwSnapshot?.os?.system} ${hwSnapshot?.os?.release}`}/>
                        <KV k={T.kernel} v={hwSnapshot?.os?.version}/>
                        <KV k="Python" v={hwSnapshot?.os?.python}/>
                        <KV k="Arch" v={hwSnapshot?.os?.machine}/>
                      </div>
                    </Card>
                  </div>
                </Tab>
              )}

              {activeTab === 'network' && (
                <Tab k="network">
                  <Card title={`${T.listeningPorts} (${ports.length})`} icon={<Network size={14}/>}>
                    <Tbl headers={[T.port, T.proto, T.address, T.service, T.pid, T.process]} rows={
                      ports.map((p) => [
                        <span className="font-medium text-white">{p.port}</span>,
                        <span className="text-husn-text-3">{p.protocol}</span>,
                        p.address,
                        <span className="text-white">{p.service}</span>,
                        <span className="text-husn-text-3">{p.pid || '—'}</span>,
                        p.process || '—',
                      ])
                    }/>
                  </Card>
                  <div className="mt-4">
                    <Card title={`${T.processes} (${procs.length})`} icon={<Cpu size={14}/>}
                      action={
                        <button onClick={() => setProcsSusOnly(v => !v)}
                          className={`text-[11px] font-medium px-3 py-1 rounded-md border transition
                            ${procsSusOnly ? 'border-husn-danger/40 text-husn-danger bg-husn-danger/10' : 'border-husn-border text-husn-text-2 hover:text-white'}`}>
                          {procsSusOnly ? T.suspiciousOnly : T.showAll}
                        </button>
                      }>
                      {procs.length === 0 && procsSusOnly && (
                        <div className="text-center py-8 text-sm text-husn-success">✓ {lang === 'en' ? 'No suspicious processes' : 'لا توجد عمليات مشبوهة'}</div>
                      )}
                      <Tbl headers={[T.pid, T.user, T.process, T.cpuPct, T.memPct, T.connections, T.suspicious]} rows={
                        procs.map((p) => [
                          <span className="text-husn-text-3">{p.pid}</span>,
                          p.user, <span className="text-white">{p.name}</span>,
                          p.cpu_percent, p.memory_percent,
                          p.connections >= 0 ? p.connections : '—',
                          p.suspicious ? <span className="text-husn-danger text-[11px]">⚠ {p.reason}</span> : '',
                        ])
                      }/>
                    </Card>
                  </div>
                </Tab>
              )}

              {activeTab === 'connections' && (
                <Tab k="connections">
                  <div className="grid grid-cols-3 gap-4">
                    <Kpi label={T.totalConnections || 'Established'} value={fmtNum(connections?.total ?? 0)} sub="" icon={<Radio size={16}/>}/>
                    <Kpi label={T.uniqueRemotes || 'Unique remotes'} value={fmtNum(connections?.by_remote?.length ?? 0)} sub="" icon={<Globe size={16}/>}/>
                    <Kpi label={T.topProcesses || 'Top process'} value={connections?.top_processes?.[0]?.process || '—'}
                      sub={`${connections?.top_processes?.[0]?.count ?? 0} conn`} icon={<Cpu size={16}/>}/>
                  </div>

                  <div className="grid grid-cols-2 gap-4 mt-4">
                    <Card title={T.byRemote || 'By remote IP'} icon={<Globe size={14}/>}>
                      <Tbl headers={[T.sourceIp, T.connections, T.service, T.process]} rows={
                        (connections?.by_remote || []).slice(0, 12).map((r: any) => [
                          <span className="font-mono text-white">{r.remote_ip}</span>,
                          <span className="font-medium">{r.count}</span>,
                          <span className="text-husn-text-2">{r.services.slice(0, 2).join(', ')}</span>,
                          <span className="text-husn-text-3 truncate max-w-[140px] inline-block">{r.processes.slice(0, 2).join(', ') || '—'}</span>,
                        ])
                      }/>
                    </Card>
                    <Card title={T.topProcesses || 'Top processes'} icon={<Cpu size={14}/>}>
                      <Tbl headers={[T.process, T.connections, T.uniqueRemotes || 'Remotes']} rows={
                        (connections?.top_processes || []).map((p: any) => [
                          <span className="text-white">{p.process}</span>,
                          <span className="font-medium">{p.count}</span>,
                          <span className="text-husn-text-3 text-[11px]">{p.remotes.length}</span>,
                        ])
                      }/>
                    </Card>
                  </div>

                  <div className="mt-4">
                    <Card title={T.allEstablished || 'All established'} icon={<Network size={14}/>}>
                      <Tbl headers={['Local', 'Remote', T.service, T.process]} rows={
                        (connections?.established || []).slice(0, 30).map((r: any, i: number) => [
                          <span className="text-husn-text-3 font-mono text-[11px]" key={'l' + i}>{r.local}</span>,
                          <span className="text-white font-mono text-[11px]" key={'r' + i}>{r.remote}</span>,
                          <span className="text-husn-text-2" key={'s' + i}>{r.service}</span>,
                          <span className="text-husn-text-3" key={'p' + i}>{r.process || '—'}</span>,
                        ])
                      }/>
                    </Card>
                  </div>
                </Tab>
              )}

              {activeTab === 'recon' && (
                <Tab k="recon">
                  <Card title={T.detection} icon={<Search size={14}/>}>
                    <p className="text-sm text-husn-text-2 mb-4">
                      {lang === 'en' ? 'Type a target IP in the search bar above and run a network scan against it.' : 'اكتب IP الهدف في شريط البحث أعلاه وابدأ الفحص.'}
                    </p>
                    {results.length > 0 && (
                      <div className="space-y-2">
                        {results.map((v) => (
                          <div key={v.id} className="flex items-center justify-between px-4 py-3 rounded-lg border border-husn-border">
                            <div className="flex items-center gap-3">
                              <SeverityPill sev={v.severity} T={T}/>
                              <div>
                                <div className="text-sm text-white font-medium">{v.name}</div>
                                <div className="text-[11px] text-husn-text-3">{v.description}</div>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </Card>
                </Tab>
              )}

              {activeTab === 'exploits' && (
                <Tab k="exploits">
                  <div className="grid grid-cols-2 gap-4">
                    <SimBtn label="DDoS Attack" onClick={() => triggerSim('DDoS')} disabled={!isAdmin}/>
                    <SimBtn label="Port Scan" onClick={() => triggerSim('Port Scan')} disabled={!isAdmin}/>
                    <SimBtn label="SSH Brute Force" onClick={() => triggerSim('Brute Force')} disabled={!isAdmin}/>
                    <SimBtn label={T.rceExploit} onClick={() => triggerSim('RCE Exploit')} disabled={!isAdmin} highlight/>
                  </div>
                  <div className="mt-4 p-5 rounded-2xl border border-husn-danger/30 bg-husn-danger/5">
                    <div className="flex items-center gap-2 mb-2">
                      <AlertTriangle size={14} className="text-husn-danger"/>
                      <span className="text-[13px] font-medium text-husn-danger">{T.liveTesting || 'Live vulnerability testing'}</span>
                    </div>
                    <p className="text-[12px] text-husn-text-2 leading-relaxed">
                      {lang === 'en'
                        ? 'Each button drives the AI through a real prediction with the IP from the search bar. The classifier runs, the IsolationForest scores, the responder fires (real iptables in production mode), and an HTML email lands in the configured inbox with the SHAP chart inline.'
                        : 'يقوم كل زر بتشغيل تنبؤ AI حقيقي بـ IP من شريط البحث. المصنّف يعمل، IsolationForest يحسب الدرجة، المستجيب يطلق (iptables حقيقي في وضع الإنتاج)، ويصل بريد HTML إلى صندوق الوارد مع مخطط SHAP المضمّن.'}
                    </p>
                  </div>
                </Tab>
              )}

              {activeTab === 'xai' && (
                <Tab k="xai">
                  <div className="flex justify-between items-center mb-2">
                    <div>
                      <h3 className="text-[14px] font-light uppercase tracking-[0.18em] text-white">{T.explainableAI}</h3>
                      <p className="text-husn-text-3 text-xs mt-0.5">XGBoost feature contribution analysis</p>
                    </div>
                    <button onClick={fetchExplanation} disabled={isExplaining} className="husn-btn-primary text-sm">
                      {isExplaining ? T.analyzing || 'Analyzing...' : T.runShap || 'Run SHAP'}
                    </button>
                  </div>
                  <div className="grid grid-cols-3 gap-4 mt-3">
                    <div className="col-span-2 husn-card p-5 min-h-[420px]">
                      {shapData ? (
                        <ResponsiveContainer width="100%" height={400}>
                          <BarChart data={shapData.features} layout="vertical" margin={{ left: 30, right: 20 }}>
                            <XAxis type="number" hide/>
                            <YAxis dataKey="name" type="category" stroke="#5c6473" fontSize={11} width={130}
                              tickFormatter={(v) => v}
                              orientation={lang === 'ar' ? 'right' : 'left'}/>
                            <Tooltip cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                              contentStyle={{ backgroundColor: '#0a0e18', border: '1px solid #2a3142', borderRadius: 8 }}/>
                            <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                              {shapData.features.map((e: any, i: number) => (
                                <Cell key={i} fill={e.value > 0 ? '#ffffff' : '#5c6473'}/>
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      ) : (
                        <div className="h-full flex flex-col items-center justify-center text-husn-text-3">
                          <Eye size={36} className="opacity-30 mb-3"/>
                          <p className="text-sm">{T.shapEmpty || 'Run SHAP to view weights'}</p>
                        </div>
                      )}
                    </div>
                    <div className="space-y-3">
                      <div className="husn-card p-5">
                        <h4 className="text-[13px] font-medium text-white mb-3">{T.legend || 'Legend'}</h4>
                        <div className="space-y-2 text-[12px] text-husn-text-2 leading-relaxed">
                          <p><span className="inline-block w-3 h-3 bg-white rounded-sm mr-2 align-middle"/>{T.legendPos || 'Increased threat probability'}</p>
                          <p><span className="inline-block w-3 h-3 bg-husn-text-3 rounded-sm mr-2 align-middle"/>{T.legendNeg || 'Indicator of legitimate behavior'}</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </Tab>
              )}

              {activeTab === 'defense' && (
                <Tab k="defense">
                  <div className="flex justify-between items-center mb-1">
                    <h3 className="text-[14px] font-light uppercase tracking-[0.18em] text-white">{T.defense}</h3>
                    {isAdmin && (
                      <button onClick={sendTestEmail} className="husn-btn-primary text-sm flex items-center gap-2">
                        <Mail size={14}/> {T.sendTest}
                      </button>
                    )}
                  </div>

                  <Card title={`${T.blockedIps} (${blocked.length})`} icon={<ShieldOff size={14}/>}>
                    {blocked.length === 0 ? (
                      <div className="text-center py-8 text-husn-success text-sm">✓ {T.noBlocked}</div>
                    ) : (
                      <Tbl headers={[T.sourceIp, T.country, T.attackType, T.severity, T.abuseScore, T.when, '']} rows={
                        blocked.map((b: any) => [
                          <span className="font-mono text-white">{b.ip}</span>,
                          <span className="text-husn-text-2"><span className="text-base mr-1">{b.geo?.flag || '🏳️'}</span>{b.geo?.country || '?'}{b.geo?.city ? ` · ${b.geo.city}` : ''}{b.geo?.asn ? <span className="block text-[10px] text-husn-text-3">{b.geo.asn}</span> : null}</span>,
                          b.attack_type,
                          <SeverityPill sev={b.severity} T={T}/>,
                          <ReputationPill rep={b.reputation}/>,
                          <span className="text-husn-text-3 text-[11px]">{new Date(b.blocked_at * 1000).toLocaleTimeString()}</span>,
                          <div className="flex gap-3">
                            <button onClick={() => investigate(b.ip)}
                              className="text-[11px] text-husn-success hover:underline uppercase tracking-widest font-medium flex items-center gap-1">
                              <SearchIcon size={11}/> {T.investigate}
                            </button>
                            {isAdmin && (
                              <button onClick={() => unblockIp(b.ip)} className="text-[11px] text-husn-text-2 hover:text-white uppercase tracking-widest">{T.unblock}</button>
                            )}
                          </div>,
                        ])
                      }/>
                    )}
                  </Card>

                  <div className="mt-4">
                    <Card title={T.recipients} icon={<Mail size={14}/>}
                      action={
                        <span className={`husn-pill ${smtpEnabled ? 'bg-husn-success/15 text-husn-success' : 'bg-husn-warn/15 text-husn-warn'}`}>
                          {smtpEnabled ? T.smtpEnabled : 'SMTP OFF'}
                        </span>
                      }>
                      {!smtpEnabled && <p className="text-[11px] text-husn-warn mb-3">{T.smtpDisabled}</p>}
                      <div className="space-y-1.5 mb-3">
                        {recipients.map((r) => (
                          <div key={r} className="flex items-center justify-between px-3 py-2 rounded-lg border border-husn-border">
                            <span className="text-sm text-white font-mono">{r}</span>
                            {isAdmin && <button onClick={() => removeRecipient(r)} className="text-husn-text-3 hover:text-husn-danger transition"><Trash2 size={14}/></button>}
                          </div>
                        ))}
                        {recipients.length === 0 && <p className="text-[12px] text-husn-text-3">— no recipients —</p>}
                      </div>
                      {isAdmin && (
                        <div className="flex gap-2">
                          <input type="email" value={newRecipient} onChange={(e) => setNewRecipient(e.target.value)}
                            placeholder={T.addEmailPlaceholder} className="husn-input flex-1 text-sm"/>
                          <button onClick={addRecipientFn} className="husn-btn-primary text-sm">{T.addRecipient}</button>
                        </div>
                      )}
                    </Card>
                  </div>

                  {/* Notify settings: pause + severity threshold */}
                  <div className="mt-4">
                    <Card title={T.notifySettings} icon={<Mail size={14}/>}
                      action={
                        <span className={`husn-pill ${notifyState?.is_paused ? 'bg-husn-warn/15 text-husn-warn' : 'bg-husn-success/15 text-husn-success'}`}>
                          {notifyState?.is_paused ? `${T.paused} · ${notifyState.paused_for_seconds}s` : T.notPaused}
                        </span>
                      }>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="text-[11px] text-husn-text-3 uppercase tracking-widest">{T.minSeverity}</label>
                          <select value={notifyState?.min_severity || 'low'}
                            onChange={(e) => isAdmin && setMinSeverity(e.target.value)}
                            disabled={!isAdmin}
                            className="husn-input w-full mt-2 text-sm capitalize">
                            {(notifyState?.severity_options || ['low','medium','high','critical']).map((s: string) =>
                              <option key={s} value={s}>{s}</option>)}
                          </select>
                        </div>
                        <div>
                          <label className="text-[11px] text-husn-text-3 uppercase tracking-widest">{T.pauseEmails}</label>
                          <div className="grid grid-cols-4 gap-1 mt-2">
                            <button onClick={() => isAdmin && pauseEmails(300)} disabled={!isAdmin} className="husn-btn-ghost text-[11px] !py-2">{T.pauseFor5min}</button>
                            <button onClick={() => isAdmin && pauseEmails(3600)} disabled={!isAdmin} className="husn-btn-ghost text-[11px] !py-2">{T.pauseFor1hour}</button>
                            <button onClick={() => isAdmin && pauseEmails(86400)} disabled={!isAdmin} className="husn-btn-ghost text-[11px] !py-2">{T.pauseFor24hours}</button>
                            <button onClick={() => isAdmin && pauseEmails(-1)} disabled={!isAdmin} className="husn-btn-ghost text-[11px] !py-2 border-husn-danger/40 text-husn-danger">{T.pauseForever}</button>
                          </div>
                          {notifyState?.is_paused && isAdmin && (
                            <button onClick={() => pauseEmails(0)}
                              className="mt-2 w-full text-[11px] py-2 bg-husn-success/10 border border-husn-success/30 text-husn-success rounded-lg uppercase tracking-widest font-medium">
                              ▶ {T.resumeEmails}
                            </button>
                          )}
                        </div>
                      </div>
                    </Card>
                  </div>

                  {/* IP allow / deny lists */}
                  <div className="mt-4">
                    <Card title={T.ipLists} icon={<ShieldOff size={14}/>}>
                      <div className="grid grid-cols-2 gap-4">
                        <ListBox
                          title={T.whitelistTitle}
                          help={T.whitelistHelp}
                          items={defLists?.ip_whitelist ?? []}
                          renderItem={(v: string) => <span className="font-mono text-husn-success">{v}</span>}
                          isAdmin={isAdmin}
                          inputValue={newIpAllow} setInputValue={setNewIpAllow}
                          inputPlaceholder={T.addIp}
                          onAdd={() => { addToList('ip-allow', newIpAllow); setNewIpAllow(''); }}
                          onRemove={(v: string) => removeFromList('ip-allow', v)}
                          accent="success"
                        />
                        <ListBox
                          title={T.blacklistTitle}
                          help={T.blacklistHelp}
                          items={defLists?.ip_blacklist ?? []}
                          renderItem={(v: string) => <span className="font-mono text-husn-danger">{v}</span>}
                          isAdmin={isAdmin}
                          inputValue={newIpDeny} setInputValue={setNewIpDeny}
                          inputPlaceholder={T.addIp}
                          onAdd={() => { addToList('ip-deny', newIpDeny); setNewIpDeny(''); }}
                          onRemove={(v: string) => removeFromList('ip-deny', v)}
                          accent="danger"
                        />
                      </div>
                    </Card>
                  </div>

                  {/* Country allow / deny lists */}
                  <div className="mt-4">
                    <Card title={T.countryLists} icon={<Globe size={14}/>}>
                      <div className="grid grid-cols-2 gap-4">
                        <ListBox
                          title={T.whitelistTitle}
                          help={T.countryWhitelistHelp}
                          items={defLists?.country_whitelist ?? []}
                          renderItem={(c: any) => <span><span className="text-base mr-1">{c.flag}</span><span className="font-mono text-husn-success">{c.code}</span></span>}
                          itemKey={(c: any) => c.code}
                          isAdmin={isAdmin}
                          inputValue={newCcAllow} setInputValue={setNewCcAllow}
                          inputPlaceholder={T.addCountry}
                          onAdd={() => { addToList('country-allow', newCcAllow); setNewCcAllow(''); }}
                          onRemove={(c: any) => removeFromList('country-allow', c.code)}
                          accent="success"
                        />
                        <ListBox
                          title={T.blacklistTitle}
                          help={T.countryBlacklistHelp}
                          items={defLists?.country_blacklist ?? []}
                          renderItem={(c: any) => <span><span className="text-base mr-1">{c.flag}</span><span className="font-mono text-husn-danger">{c.code}</span></span>}
                          itemKey={(c: any) => c.code}
                          isAdmin={isAdmin}
                          inputValue={newCcDeny} setInputValue={setNewCcDeny}
                          inputPlaceholder={T.addCountry}
                          onAdd={() => { addToList('country-deny', newCcDeny); setNewCcDeny(''); }}
                          onRemove={(c: any) => removeFromList('country-deny', c.code)}
                          accent="danger"
                        />
                      </div>
                    </Card>
                  </div>

                  {isAdmin && (
                    <div className="mt-4">
                      <Card title={T.auditLog || 'Authentication audit'} icon={<KeyRound size={14}/>}
                        action={<span className="text-[11px] text-husn-text-3">{audit?.total ?? 0}</span>}>
                        {(audit?.events || []).length === 0 ? (
                          <p className="text-[12px] text-husn-text-3 py-2">— no events yet —</p>
                        ) : (
                          <div className="space-y-1 max-h-72 overflow-y-auto">
                            {(audit?.events || []).map((e, i) => (
                              <div key={i} className="text-[12px] font-mono text-husn-text-2 py-1.5 px-2 rounded hover:bg-white/[0.03]">
                                {e}
                              </div>
                            ))}
                          </div>
                        )}
                      </Card>
                    </div>
                  )}
                </Tab>
              )}

              {activeTab === 'updates' && (
                <Tab k="updates">
                  <div className="flex justify-between items-center mb-2">
                    <div>
                      <h3 className="text-[14px] font-light uppercase tracking-[0.18em] text-white">{T.updates}</h3>
                      <p className="text-husn-text-3 text-xs mt-0.5">
                        {lang === 'en' ? `Auto-check every ${updateStatus?.interval_minutes ?? 5} min` : `فحص كل ${updateStatus?.interval_minutes ?? 5} دقائق`}
                      </p>
                    </div>
                    <div className="flex gap-2">
                      <button onClick={checkForUpdate} disabled={isCheckingUpdate || !isAdmin}
                        className="husn-btn-ghost text-sm flex items-center gap-2">
                        <RefreshCw size={14} className={isCheckingUpdate ? 'animate-spin' : ''}/> {T.checkNow}
                      </button>
                      <button onClick={applyUpdate} disabled={isApplyingUpdate || !updateStatus?.last_check?.available || !isAdmin}
                        className="husn-btn-primary text-sm">{T.applyUpdate}</button>
                    </div>
                  </div>

                  <Card title={T.updaterStatus} icon={<GitBranch size={14}/>}>
                    <div className="grid grid-cols-2 gap-x-12 gap-y-2 text-sm">
                      <KV k={T.lastChecked} v={updateStatus?.last_check?.checked_at ? new Date(updateStatus.last_check.checked_at * 1000).toLocaleString() : '—'}/>
                      <KV k={T.repo} v={updateStatus?.repo_url || '—'}/>
                      <KV k={T.branch} v={updateStatus?.branch || 'main'}/>
                      <KV k={T.autoApply} v={updateStatus?.auto_apply ? T.yes : T.no}/>
                      <KV k={T.behind} v={updateStatus?.last_check?.behind ?? 0}/>
                      <KV k={T.ahead} v={updateStatus?.last_check?.ahead ?? 0}/>
                      <KV k="HEAD" v={updateStatus?.last_check?.current_commit || '—'}/>
                      <KV k="origin" v={updateStatus?.last_check?.remote_commit || '—'}/>
                    </div>
                    <div className={`mt-5 px-4 py-3 rounded-lg text-sm text-center
                      ${updateStatus?.last_check?.available ? 'bg-husn-warn/10 text-husn-warn border border-husn-warn/30' : 'bg-husn-success/10 text-husn-success border border-husn-success/30'}`}>
                      {updateStatus?.last_check?.message || T.upToDate}
                    </div>
                  </Card>

                  <div className="mt-4">
                    <Card title={T.history} icon={<Clock size={14}/>}>
                      <div className="space-y-1 max-h-72 overflow-y-auto">
                        {(updateStatus?.history || []).slice(0, 15).map((h: any, i: number) => (
                          <div key={i} className="flex items-center gap-3 text-[12px] py-2 px-2 rounded hover:bg-white/[0.03]">
                            {h.ok ? <CheckCircle2 size={12} className="text-husn-success shrink-0"/> : <XCircle size={12} className="text-husn-danger shrink-0"/>}
                            <span className="text-husn-text-3 font-mono shrink-0">{h.ts_iso}</span>
                            <span className="text-white font-medium uppercase text-[10px] shrink-0">{h.action}</span>
                            <span className="text-husn-text-2 truncate">{h.message}</span>
                          </div>
                        ))}
                        {!(updateStatus?.history || []).length && <p className="text-[12px] text-husn-text-3 py-2">— no entries yet —</p>}
                      </div>
                    </Card>
                  </div>
                </Tab>
              )}

              {activeTab === 'topology' && (
                <Tab k="topology">
                  <div className="grid grid-cols-3 gap-4 mb-4">
                    <Kpi label={T.totalConnections || 'Established'} value={fmtNum(connections?.total ?? 0)} sub="" icon={<Radio size={16}/>}/>
                    <Kpi label={T.uniqueRemotes || 'Unique remotes'} value={fmtNum(connections?.by_remote?.length ?? 0)} sub="" icon={<Globe size={16}/>}/>
                    <Kpi label={T.blockedIps} value={fmtNum(blocked.length)}
                      sub={blocked.length ? 'red nodes' : 'none'} icon={<ShieldOff size={16}/>}
                      highlight={blocked.length > 0}/>
                  </div>
                  <div className="husn-card p-2" style={{ height: 'calc(100vh - 280px)' }}>
                    <TopologyGraph
                      hostLabel={hwSnapshot?.os?.hostname || 'host'}
                      remotes={connections?.by_remote || []}
                      blocked={blocked}
                    />
                  </div>
                </Tab>
              )}

              {activeTab === 'honeypot' && (
                <Tab k="honeypot">
                  <div className="grid grid-cols-4 gap-4">
                    <Kpi label={T.honeypot}
                      value={honeypotStatus?.running ? T.sniffActive : T.sniffOff}
                      sub={honeypotStatus?.error || (honeypotStatus?.enabled ? 'enabled' : 'disabled in config')}
                      icon={<Crosshair size={16}/>}
                      highlight={(honeypotStatus?.connections_total ?? 0) > 0}/>
                    <Kpi label={T.honeypotPorts} value={(honeypotStatus?.listening_ports || []).join(', ') || '—'} sub="" icon={<Network size={16}/>}/>
                    <Kpi label={T.honeypotHits} value={fmtNum(honeypotStatus?.connections_total ?? 0)} sub={`${honeypotStatus?.blocks_fired ?? 0} blocked`} icon={<Activity size={16}/>}/>
                    <Kpi label={T.uptime} value={fmtUptime(honeypotStatus?.uptime_seconds ?? 0)} sub="" icon={<Clock size={16}/>}/>
                  </div>
                  <div className="mt-4">
                    <Card title={T.recentHits} icon={<Crosshair size={14}/>}>
                      {!honeypotStatus?.events?.length ? (
                        <p className="text-[12px] text-husn-text-3 py-3">— no probes yet —</p>
                      ) : (
                        <Tbl headers={[T.when, T.sourceIp, T.port, T.service, 'Payload preview']} rows={
                          (honeypotStatus.events).slice(0, 30).map((e: any) => [
                            <span className="text-husn-text-3 text-[11px]">{new Date(e.ts * 1000).toLocaleTimeString()}</span>,
                            <span className="font-mono text-husn-danger">{e.src_ip}</span>,
                            <span className="text-white">{e.dst_port}</span>,
                            <span className="text-husn-text-2">{e.service}</span>,
                            <code className="text-[11px] text-husn-text-3">{e.payload_preview || '—'}</code>,
                          ])
                        }/>
                      )}
                    </Card>
                  </div>
                  {!honeypotStatus?.enabled && (
                    <div className="mt-4 p-4 rounded-xl border border-husn-warn/30 bg-husn-warn/5 text-[12px] text-husn-warn">
                      Honeypot is disabled. Enable it in <code>/etc/husn/config.yml</code> under <code>honeypot.enabled: true</code> and restart the backend.
                    </div>
                  )}
                </Tab>
              )}

              {activeTab === 'chat' && (
                <Tab k="chat">
                  <div className="flex justify-between items-center mb-1">
                    <h3 className="text-[15px] font-light uppercase tracking-[0.18em] text-white">{T.chat}</h3>
                    <div className="flex items-center gap-3">
                      <span className={`husn-pill ${chatStatus?.configured ? 'bg-husn-success/15 text-husn-success' : 'bg-husn-warn/15 text-husn-warn'}`}>
                        {chatStatus?.configured ? (chatStatus.model || 'configured') : 'NO API KEY'}
                      </span>
                      <button onClick={resetChat} className="husn-btn-ghost text-[11px]">{T.reset}</button>
                    </div>
                  </div>
                  {!chatStatus?.configured && (
                    <p className="text-[12px] text-husn-warn mb-3">{T.chatNotConfigured}</p>
                  )}
                  <Card title={T.chat} icon={<MessageSquare size={14}/>}>
                    <div className="bg-black/40 border border-husn-border rounded-xl p-4 min-h-[420px] max-h-[55vh] overflow-y-auto"
                      style={{ scrollBehavior: 'auto', overflowAnchor: 'none' }}>
                      {chatHistory.length === 0 && (
                        <p className="text-[12px] text-husn-text-3 italic">husn analyst ready — ask anything about your live security state.</p>
                      )}
                      {chatHistory.map((m, i) => (
                        <div key={i} className={`mb-3 ${m.role === 'user' ? 'text-white' : 'text-husn-text'}`}>
                          <div className={`text-[10px] uppercase tracking-[0.18em] mb-1 ${m.role === 'user' ? 'text-husn-text-3' : 'text-husn-success'}`}>
                            {m.role === 'user' ? (authUser?.username || 'you') : 'analyst'}
                          </div>
                          <div className={`text-[13px] whitespace-pre-wrap leading-relaxed ${m.ok === false ? 'text-husn-danger' : ''}`}>{m.content}</div>
                        </div>
                      ))}
                      {chatBusy && <p className="text-[12px] text-husn-text-3 italic">{T.thinking}</p>}
                    </div>
                    <div className="flex gap-2 mt-3">
                      <input value={chatInput} onChange={(e) => setChatInput(e.target.value)}
                        onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); } }}
                        placeholder={T.askAnything} disabled={chatBusy || !chatStatus?.configured}
                        className="husn-input flex-1 text-sm"/>
                      <button onClick={sendChat} disabled={chatBusy || !chatInput.trim() || !chatStatus?.configured}
                        className="husn-btn-primary text-sm flex items-center gap-2">
                        {chatBusy ? <Activity size={14} className="animate-spin"/> : <PlayIcon size={14}/>}
                        {T.send}
                      </button>
                    </div>
                  </Card>
                </Tab>
              )}

              {activeTab === 'reports' && (
                <Tab k="reports">
                  <div className="flex justify-between items-center mb-1">
                    <h3 className="text-[15px] font-light uppercase tracking-[0.18em] text-white">{T.reports}</h3>
                    {isAdmin && (
                      <button onClick={runReportNow} disabled={reportBusy}
                        className="husn-btn-primary text-sm flex items-center gap-2">
                        {reportBusy ? <Activity size={14} className="animate-spin"/> : <FileText size={14}/>}
                        {T.runReportNow}
                      </button>
                    )}
                  </div>

                  <Card title={T.reportSchedule} icon={<Clock size={14}/>}>
                    <div className="grid grid-cols-3 gap-3">
                      <div>
                        <label className="text-[10px] text-husn-text-3 uppercase tracking-widest">{T.frequency}</label>
                        <select value={reportSched?.frequency || 'weekly'}
                          onChange={(e) => isAdmin && setReportSchedule(e.target.value, reportSched?.hour ?? 9, reportSched?.weekday ?? 0)}
                          disabled={!isAdmin}
                          className="husn-input w-full mt-1 text-sm">
                          <option value="off">{T.off}</option>
                          <option value="daily">{T.daily}</option>
                          <option value="weekly">{T.weekly}</option>
                        </select>
                      </div>
                      <div>
                        <label className="text-[10px] text-husn-text-3 uppercase tracking-widest">{T.hour}</label>
                        <select value={reportSched?.hour ?? 9}
                          onChange={(e) => isAdmin && setReportSchedule(reportSched?.frequency || 'weekly', parseInt(e.target.value), reportSched?.weekday ?? 0)}
                          disabled={!isAdmin}
                          className="husn-input w-full mt-1 text-sm">
                          {Array.from({ length: 24 }, (_, h) => (
                            <option key={h} value={h}>{h.toString().padStart(2, '0')}:00</option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="text-[10px] text-husn-text-3 uppercase tracking-widest">{T.weekday}</label>
                        <select value={reportSched?.weekday ?? 0}
                          onChange={(e) => isAdmin && setReportSchedule(reportSched?.frequency || 'weekly', reportSched?.hour ?? 9, parseInt(e.target.value))}
                          disabled={!isAdmin || reportSched?.frequency !== 'weekly'}
                          className="husn-input w-full mt-1 text-sm">
                          {['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map((d, i) =>
                            <option key={i} value={i}>{d}</option>)}
                        </select>
                      </div>
                    </div>
                  </Card>

                  <div className="mt-4">
                    <Card title={T.pastReports} icon={<FileText size={14}/>}
                      action={<span className="text-[11px] text-husn-text-3">{reportList.length}</span>}>
                      {reportList.length === 0 ? (
                        <p className="text-[12px] text-husn-text-3 italic py-2">— no reports yet —</p>
                      ) : (
                        <Tbl headers={[T.created || 'Created', 'Name', 'Size', '']} rows={
                          reportList.map((r: any) => [
                            <span className="text-husn-text-3 text-[11px]">{new Date(r.mtime * 1000).toLocaleString()}</span>,
                            <span className="font-mono text-white">{r.name}</span>,
                            <span className="text-husn-text-3">{Math.round(r.size_bytes / 1024)} KB</span>,
                            <a href={`${API_BASE}${r.url}`} target="_blank" rel="noreferrer"
                              className="text-husn-success hover:underline text-[11px] uppercase tracking-widest font-bold">{T.download}</a>,
                          ])
                        }/>
                      )}
                    </Card>
                  </div>
                </Tab>
              )}

              {activeTab === 'terminal' && isAdmin && (
                <Tab k="terminal">
                  <Card title={T.terminal} icon={<TerminalSquare size={14}/>}>
                    <div className="flex gap-2 mb-3">
                      <select value={cliCmd} onChange={(e) => setCliCmd(e.target.value)}
                        className="husn-input text-sm" style={{ minWidth: 140 }}>
                        {cliCommands.map(c => <option key={c} value={c}>{c}</option>)}
                      </select>
                      <input value={cliArgs} onChange={(e) => setCliArgs(e.target.value)}
                        placeholder={T.commandArgs}
                        onKeyDown={(e) => { if (e.key === 'Enter') runCli(); }}
                        className="husn-input flex-1 text-sm font-mono"/>
                      <button onClick={runCli} disabled={cliBusy || !cliCmd}
                        className="husn-btn-primary text-sm flex items-center gap-2">
                        {cliBusy ? <Activity size={14} className="animate-spin"/> : <Play size={14}/>}
                        {T.runCommand}
                      </button>
                    </div>
                    <div className="bg-black border border-husn-border rounded-xl p-4 min-h-[420px] max-h-[60vh] overflow-y-auto"
                      style={{ scrollBehavior: 'auto', overflowAnchor: 'none' }}>
                      {cliOut?.html ? (
                        <div className="text-[12.5px] leading-snug" dangerouslySetInnerHTML={{ __html: cliOut.html }}/>
                      ) : cliOut?.text ? (
                        <pre className="text-[12.5px] text-husn-text-2 whitespace-pre-wrap font-mono">{cliOut.text}</pre>
                      ) : (
                        <p className="text-[12px] text-husn-text-3 italic">husn $ — pick a command and press Run.</p>
                      )}
                    </div>
                  </Card>
                </Tab>
              )}

              {activeTab === 'users' && isAdmin && (
                <Tab k="users">
                  <Card title={T.addUser} icon={<UserPlus size={14}/>}>
                    <div className="grid grid-cols-4 gap-2">
                      <input type="text" value={newUser.username} onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                        placeholder={T.username} className="husn-input text-sm"/>
                      <input type="password" value={newUser.password} onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                        placeholder={T.password} className="husn-input text-sm"/>
                      <select value={newUser.role} onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                        className="husn-input text-sm">
                        <option value="employee">{T.employee}</option>
                        <option value="admin">{T.admin}</option>
                      </select>
                      <button onClick={createUser} className="husn-btn-primary text-sm flex items-center justify-center gap-2">
                        <UserPlus size={14}/> {T.addUser}
                      </button>
                    </div>
                    {userError && <p className="text-xs text-husn-danger mt-3">{userError}</p>}
                  </Card>

                  <div className="mt-4">
                    <Card title={`${T.users} (${userList.length})`} icon={<UsersIcon size={14}/>}>
                      <Tbl headers={[T.username, T.role, T.created, '']} rows={
                        userList.map((u: any) => [
                          <span className="font-medium text-white">{u.username}</span>,
                          <span className={`husn-pill ${u.role === 'admin' ? 'bg-white/15 text-white' : 'bg-husn-border text-husn-text-2'}`}>
                            {u.role === 'admin' ? T.admin : T.employee}
                          </span>,
                          <span className="text-husn-text-3 text-[11px]">{u.created_at}</span>,
                          u.username !== authUser?.username
                            ? <button onClick={() => deleteUser(u.username)} className="text-husn-text-3 hover:text-husn-danger" title={T.deleteUser}><Trash2 size={14}/></button>
                            : <span className="text-[11px] text-husn-text-3 italic">(you)</span>,
                        ])
                      }/>
                    </Card>
                  </div>
                </Tab>
              )}
            </AnimatePresence>
          </div>

          {/* Right: live log panel */}
          <aside className="w-[340px] shrink-0 flex flex-col gap-3 min-h-0">
            <div className="husn-card flex-1 flex flex-col overflow-hidden">
              <div className="px-3 py-2 border-b border-husn-border flex justify-between items-center">
                <div className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-husn-success animate-pulse"/>
                  <span className="text-[10px] text-white font-medium uppercase tracking-[0.18em]">{T.kernelLogs || 'Kernel logs'}</span>
                </div>
                <span className="text-[9px] text-husn-text-3">{logs.length}</span>
              </div>
              <div ref={logScrollRef} onScroll={onLogScroll}
                className="flex-1 px-3 py-2 overflow-y-auto text-[10px] font-mono space-y-0.5 leading-relaxed"
                style={{ scrollBehavior: 'auto' }}>
                {logs.length === 0 && <p className="text-husn-text-3 italic text-[10px]">SYSTEM_READY...</p>}
                {logs.map((log, i) => (
                  <div key={i} className="flex gap-1.5">
                    <span className="text-husn-text-4 shrink-0">{i.toString(16).padStart(3, '0')}</span>
                    <span className={
                      log.includes('ERR') || log.includes('!') ? 'text-husn-danger' :
                      log.includes('BLOCK') || log.includes('ACTIVE') || log.includes('UNBLOCK') ? 'text-white' :
                      log.includes('AUTH') ? 'text-husn-warn' :
                      'text-husn-text-2'
                    }>
                      {log}
                    </span>
                  </div>
                ))}
              </div>
            </div>
            <div className="husn-card p-3">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] text-husn-text-3 uppercase tracking-[0.15em]">{T.activeShield || 'Active shield'}</span>
                <Lock size={11} className="text-husn-text-3"/>
              </div>
              <div className="text-[12px] font-light uppercase tracking-[0.18em] text-white">
                {systemStatus?.real_iptables ? (lang === 'en' ? 'Real iptables' : 'iptables حقيقي') : (lang === 'en' ? 'Simulated' : 'محاكاة')}
              </div>
              <div className="mt-2 h-0.5 bg-husn-border rounded overflow-hidden">
                <motion.div initial={{ x: '-100%' }} animate={{ x: '100%' }}
                  transition={{ repeat: Infinity, duration: 2.5, ease: 'linear' }}
                  className="h-full w-1/3 bg-white/40"/>
              </div>
            </div>
          </aside>
        </div>
      </main>
    </div>
  );
}

// ---------- presentational atoms

const tabTitle = (t: string, T: any) => ({
  dashboard: T.monitoring, host: T.host, network: T.network,
  connections: T.connections || 'Connections',
  topology: T.topology, terminal: T.terminal, honeypot: T.honeypot,
  recon: T.detection, exploits: T.simulation, xai: T.explainableAI,
  defense: T.defense, updates: T.updates, users: T.users,
  chat: T.chat, reports: T.reports,
}[t] || 'Dashboard');

const Tab = ({ children }: any) => (
  // Plain div — no motion animation. Framer's transform-on-mount can interact
  // with overflow containers in subtle ways and isn't worth the visual cost.
  <div>{children}</div>
);

const NavLink = ({ icon, label, active, onClick, badge, dot }: any) => (
  <button onClick={onClick}
    className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-[9.5px] font-medium uppercase tracking-[0.15em] transition-all relative
      ${active
        ? 'bg-white/10 text-white border border-white/20 shadow-[inset_0_0_30px_rgba(255,255,255,0.04)]'
        : 'text-husn-text-3 border border-transparent hover:text-white hover:bg-white/[0.03]'}`}>
    <span className={active ? 'text-white' : 'text-husn-text-3'}>{icon}</span>
    <span className="flex-1 text-left">{label}</span>
    {badge !== undefined && (
      <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded-full bg-husn-danger/90 text-white tracking-normal">
        {badge}
      </span>
    )}
    {dot && <span className="w-1.5 h-1.5 rounded-full bg-husn-warn animate-pulse"/>}
  </button>
);

const Kpi = ({ label, value, sub, icon, highlight }: any) => (
  <div className={`husn-card p-5 flex items-start justify-between ${highlight ? 'border-husn-danger/40' : ''}`}>
    <div>
      <p className="text-[12px] text-husn-text-2">{label}</p>
      <p className={`text-[24px] font-light uppercase tracking-[0.18em] tracking-tight mt-1 ${highlight ? 'text-husn-danger' : 'text-white'}`}>{value}</p>
      {sub && <p className="text-[11px] text-husn-text-3 mt-1">{sub}</p>}
    </div>
    <div className={`w-9 h-9 rounded-lg border flex items-center justify-center
      ${highlight ? 'border-husn-danger/40 text-husn-danger' : 'border-husn-border text-husn-text-2'}`}>{icon}</div>
  </div>
);

const Card = ({ title, icon, action, children }: any) => (
  <div className="husn-card p-5">
    <div className="flex justify-between items-center mb-4">
      <h3 className="text-[12px] font-medium text-white uppercase tracking-[0.18em] flex items-center gap-2">
        <span className="text-husn-text-3">{icon}</span> {title}
      </h3>
      {action}
    </div>
    {children}
  </div>
);

const Tbl = ({ headers, rows }: { headers: string[]; rows: any[][] }) => (
  <div className="overflow-x-auto -mx-2">
    <table className="w-full text-[13px]">
      <thead>
        <tr className="text-[11px] text-husn-text-3 font-medium">
          {headers.map((h, i) => <th key={i} className="px-3 py-2 text-left font-medium">{h}</th>)}
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="border-t border-husn-border hover:bg-white/[0.02]">
            {r.map((c, j) => <td key={j} className="px-3 py-2.5 align-middle">{c}</td>)}
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

const KV = ({ k, v }: any) => (
  <div className="flex justify-between items-baseline border-b border-husn-border py-2">
    <span className="text-[12px] text-husn-text-3">{k}</span>
    <span className="text-white font-mono text-[12px] truncate max-w-[60%] text-right">{v ?? '—'}</span>
  </div>
);

const SeverityPill = ({ sev, T }: any) => {
  const c = sev === 'High' || sev === 'Critical' ? 'bg-husn-danger/15 text-husn-danger'
    : sev === 'Medium' ? 'bg-husn-warn/15 text-husn-warn'
    : 'bg-husn-success/15 text-husn-success';
  const label = T?.[sev?.toLowerCase()] || sev;
  return <span className={`husn-pill ${c}`}>{label}</span>;
};

const SimBtn = ({ label, onClick, highlight, disabled }: any) => (
  <button onClick={onClick} disabled={disabled} title={disabled ? 'Admin only' : ''}
    className={`p-8 rounded-2xl border transition text-left disabled:opacity-30 disabled:cursor-not-allowed
      ${highlight ? 'border-husn-danger/40 bg-husn-danger/5 hover:bg-husn-danger/10' : 'border-husn-border bg-husn-surface hover:border-husn-border-2 hover:bg-husn-surface-2'}`}>
    <div className={`w-9 h-9 rounded-lg flex items-center justify-center mb-3
      ${highlight ? 'bg-husn-danger/15 text-husn-danger' : 'bg-white/5 text-husn-text-2'}`}>
      <Skull size={18}/>
    </div>
    <div className={`text-[14px] font-light uppercase tracking-[0.18em] ${highlight ? 'text-husn-danger' : 'text-white'}`}>{label}</div>
    <div className="text-[11px] text-husn-text-3 mt-1">Simulate · classify · respond · email</div>
  </button>
);

const GaugeCard = ({ label, pct, sub, bigText }: any) => {
  const color = pct == null ? '#ffffff'
    : pct > 90 ? '#ef4444' : pct > 75 ? '#f59e0b' : '#10b981';
  return (
    <div className="husn-card p-5 flex items-center gap-4">
      {pct != null ? (
        <div className="relative shrink-0 w-20 h-20">
          <div className="husn-gauge w-full h-full rounded-full"
            style={{ ['--gauge-color' as any]: color, ['--pct' as any]: Math.min(100, pct) }}/>
          <div className="absolute inset-2 rounded-full bg-husn-surface flex items-center justify-center">
            <span className="text-sm font-semibold text-white">{Math.round(pct)}%</span>
          </div>
        </div>
      ) : (
        <div className="shrink-0 w-20 h-20 rounded-full border border-husn-border flex items-center justify-center">
          <span className="text-[11px] text-husn-text-3 text-center leading-tight">{bigText}</span>
        </div>
      )}
      <div className="min-w-0">
        <p className="text-[12px] text-husn-text-2">{label}</p>
        {bigText && pct != null && <p className="text-[20px] font-semibold text-white tracking-tight">{bigText}</p>}
        <p className="text-[11px] text-husn-text-3 truncate">{sub}</p>
      </div>
    </div>
  );
};

// ---------- Live sniffer + honeypot status cards (Dashboard row)

const SnifferCard = ({ s, T }: any) => {
  const on = s?.running;
  return (
    <div className="husn-card p-5">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-[12px] font-medium text-white uppercase tracking-[0.18em] flex items-center gap-2">
          <Radio size={14} className={on ? 'text-husn-success' : 'text-husn-text-3'}/>
          {T.sniffer}
        </h3>
        <span className={`husn-pill ${on ? 'bg-husn-success/15 text-husn-success' : 'bg-husn-text-3/15 text-husn-text-3'}`}>
          {on ? T.sniffActive : T.sniffOff}
        </span>
      </div>
      <div className="grid grid-cols-4 gap-3 text-center">
        <MiniStat label={T.packetsSeen} value={fmtNum(s?.packets_seen ?? 0)}/>
        <MiniStat label={T.activeFlows} value={fmtNum(s?.active_flows ?? 0)}/>
        <MiniStat label={T.aiPredictions} value={fmtNum(s?.predictions ?? 0)}/>
        <MiniStat label={T.autoBlocks} value={fmtNum(s?.blocks_fired ?? 0)} accent={s?.blocks_fired > 0}/>
      </div>
      {s?.error && <p className="mt-3 text-[11px] text-husn-warn">{s.error}</p>}
      {!on && !s?.error && <p className="mt-3 text-[11px] text-husn-text-3">Enable in /etc/husn/config.yml → sniffer.enabled.</p>}
    </div>
  );
};

const HoneypotCard = ({ s, T }: any) => {
  const on = s?.running;
  return (
    <div className="husn-card p-5">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-[12px] font-medium text-white uppercase tracking-[0.18em] flex items-center gap-2">
          <Crosshair size={14} className={on ? 'text-husn-success' : 'text-husn-text-3'}/>
          {T.honeypot}
        </h3>
        <span className={`husn-pill ${on ? 'bg-husn-success/15 text-husn-success' : 'bg-husn-text-3/15 text-husn-text-3'}`}>
          {on ? T.sniffActive : T.sniffOff}
        </span>
      </div>
      <div className="grid grid-cols-3 gap-3 text-center">
        <MiniStat label={T.honeypotPorts} value={(s?.listening_ports || []).length || '0'}/>
        <MiniStat label={T.honeypotHits} value={fmtNum(s?.connections_total ?? 0)} accent={s?.connections_total > 0}/>
        <MiniStat label={T.autoBlocks} value={fmtNum(s?.blocks_fired ?? 0)} accent={s?.blocks_fired > 0}/>
      </div>
      {s?.listening_ports?.length > 0 && (
        <p className="mt-3 text-[11px] text-husn-text-3 truncate">
          ports: <span className="font-mono text-husn-text-2">{s.listening_ports.join(', ')}</span>
        </p>
      )}
      {!on && <p className="mt-3 text-[11px] text-husn-text-3">Enable in /etc/husn/config.yml → honeypot.enabled.</p>}
    </div>
  );
};

const MiniStat = ({ label, value, accent }: any) => (
  <div>
    <div className={`text-[18px] font-semibold ${accent ? 'text-husn-danger' : 'text-white'}`}>{value}</div>
    <div className="text-[10px] text-husn-text-3 mt-0.5">{label}</div>
  </div>
);

const ListBox = ({
  title, help, items, renderItem, itemKey, isAdmin,
  inputValue, setInputValue, inputPlaceholder, onAdd, onRemove, accent,
}: any) => {
  const accentBorder = accent === 'success' ? 'border-husn-success/30'
    : accent === 'danger' ? 'border-husn-danger/30'
    : 'border-husn-border';
  const accentTitle = accent === 'success' ? 'text-husn-success'
    : accent === 'danger' ? 'text-husn-danger'
    : 'text-white';
  return (
    <div className={`rounded-xl border ${accentBorder} bg-husn-surface-2 p-4`}>
      <div className="flex justify-between items-baseline mb-1">
        <h4 className={`text-[12px] font-medium uppercase tracking-[0.18em] ${accentTitle}`}>{title}</h4>
        <span className="text-[10px] text-husn-text-3">{(items ?? []).length}</span>
      </div>
      <p className="text-[11px] text-husn-text-3 mb-3 leading-snug">{help}</p>
      <div className="space-y-1.5 mb-3 max-h-44 overflow-y-auto">
        {(items ?? []).length === 0 && <p className="text-[11px] text-husn-text-3 italic">— empty —</p>}
        {(items ?? []).map((it: any) => {
          const k = itemKey ? itemKey(it) : it;
          return (
            <div key={k} className="flex items-center justify-between bg-black/30 px-3 py-1.5 rounded border border-husn-border">
              <div className="text-[13px]">{renderItem(it)}</div>
              {isAdmin && (
                <button onClick={() => onRemove(it)} className="text-husn-text-3 hover:text-husn-danger transition" title="Remove">
                  <Trash2 size={13}/>
                </button>
              )}
            </div>
          );
        })}
      </div>
      {isAdmin && (
        <div className="flex gap-2">
          <input
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            placeholder={inputPlaceholder}
            onKeyDown={(e) => { if (e.key === 'Enter') onAdd(); }}
            className="husn-input flex-1 text-[12px]"
          />
          <button onClick={onAdd} className="husn-btn-primary text-[11px] !py-2 !px-3">+</button>
        </div>
      )}
    </div>
  );
};

const ReputationPill = ({ rep }: { rep?: any }) => {
  if (!rep) return <span className="text-husn-text-3 text-[11px]">—</span>;
  const score = rep.score ?? 0;
  const cls = score >= 75 ? 'bg-husn-danger/15 text-husn-danger'
    : score >= 25 ? 'bg-husn-warn/15 text-husn-warn'
    : score > 0 ? 'bg-husn-text-3/15 text-husn-text-2'
    : 'bg-husn-text-3/10 text-husn-text-3';
  return <span className={`husn-pill ${cls}`} title={`${rep.source}${rep.reports ? ` · ${rep.reports} reports` : ''}`}>
    {rep.classification || 'unknown'}{score ? ` ${score}` : ''}
  </span>;
};

// ---------- Topology graph (force-directed, react-force-graph-2d)

const TopologyGraph = ({ hostLabel, remotes, blocked }: any) => {
  const fgRef = useRef<any>(null);

  // Build nodes/links from real data. Host in the centre; every unique remote
  // IP becomes a satellite. Blocked IPs that aren't currently connected are
  // also rendered as red satellites so the graph shows recent attackers too.
  const data = useMemo(() => {
    const nodes: any[] = [{
      id: '__host__', name: hostLabel || 'host', type: 'host',
      val: 18, color: '#ffffff',
    }];
    const links: any[] = [];
    const blockedSet = new Set(blocked.map((b: any) => b.ip));
    const seen = new Set<string>();

    for (const r of remotes || []) {
      if (seen.has(r.remote_ip)) continue;
      seen.add(r.remote_ip);
      const isBlocked = blockedSet.has(r.remote_ip);
      nodes.push({
        id: r.remote_ip,
        name: r.remote_ip,
        country: r.geo?.country, flag: r.geo?.flag,
        val: Math.min(2 + Math.log2(1 + (r.count || 1)) * 2, 14),
        color: isBlocked ? '#ef4444' : (r.geo?.country_code === 'SA' ? '#10b981' : '#8b919e'),
        blocked: isBlocked,
        count: r.count,
      });
      links.push({
        source: '__host__', target: r.remote_ip,
        width: Math.min(1 + Math.log2(1 + (r.count || 1)), 4),
        color: isBlocked ? 'rgba(239,68,68,0.55)' : 'rgba(255,255,255,0.18)',
      });
    }
    for (const b of blocked || []) {
      if (seen.has(b.ip)) continue;
      seen.add(b.ip);
      nodes.push({
        id: b.ip, name: b.ip,
        country: b.geo?.country, flag: b.geo?.flag,
        val: 8, color: '#ef4444', blocked: true, attack: b.attack_type,
      });
      links.push({ source: '__host__', target: b.ip, width: 1.5, color: 'rgba(239,68,68,0.6)' });
    }
    return { nodes, links };
  }, [hostLabel, remotes, blocked]);

  return (
    <div className="w-full h-full">
      <ForceGraph2D
        ref={fgRef}
        graphData={data}
        backgroundColor="#151a26"
        nodeRelSize={4}
        linkWidth={(l: any) => l.width || 1}
        linkColor={(l: any) => l.color || 'rgba(255,255,255,0.2)'}
        linkDirectionalParticles={(l: any) => l.color?.includes('239') ? 2 : 0}
        linkDirectionalParticleSpeed={0.005}
        linkDirectionalParticleColor={() => '#ef4444'}
        nodeCanvasObject={(node: any, ctx: any, scale: number) => {
          const r = (node.val || 6);
          ctx.fillStyle = node.color || '#fff';
          ctx.beginPath();
          ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
          ctx.fill();
          if (node.blocked) {
            ctx.strokeStyle = '#ef4444';
            ctx.lineWidth = 2 / scale;
            ctx.beginPath();
            ctx.arc(node.x, node.y, r + 3, 0, 2 * Math.PI);
            ctx.stroke();
          }
          if (scale > 1.2) {
            ctx.font = `${10 / scale}px Inter, sans-serif`;
            ctx.fillStyle = '#e6f1ff';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            const label = node.id === '__host__' ? `⌂ ${node.name}` : `${node.flag || ''} ${node.name}`;
            ctx.fillText(label, node.x, node.y + r + 10 / scale);
          }
        }}
        nodeLabel={(n: any) => `<b>${n.name}</b>${n.country ? `<br/>${n.flag} ${n.country}` : ''}${n.count ? `<br/>${n.count} connections` : ''}${n.blocked ? `<br/><span style="color:#ef4444">BLOCKED${n.attack ? ' · ' + n.attack : ''}</span>` : ''}`}
        cooldownTicks={80}
        d3AlphaDecay={0.04}
        d3VelocityDecay={0.4}
      />
    </div>
  );
};

// ---------- Investigation modal (one-click)

const InvestigateModal = ({ ip, data, busy, T, isAdmin, onClose, onWhitelist, onBlacklist, onAskSoc }: any) => (
  <div className="fixed inset-0 z-[100] bg-black/70 backdrop-blur-sm flex items-center justify-center p-6"
    onClick={onClose}>
    <div className="husn-card w-full max-w-3xl max-h-[88vh] overflow-y-auto p-6" onClick={(e) => e.stopPropagation()}>
      <div className="flex items-start justify-between mb-4">
        <div>
          <div className="text-[10px] uppercase tracking-[0.25em] text-husn-text-3">{T.investigation}</div>
          <h2 className="text-[22px] font-light text-white tracking-tight font-mono mt-1">{ip}</h2>
        </div>
        <button onClick={onClose} className="text-husn-text-3 hover:text-white"><XClose size={20}/></button>
      </div>

      {busy && (
        <div className="text-center py-12 text-husn-text-3">
          <Activity size={20} className="animate-spin inline mr-2"/> Investigating…
        </div>
      )}

      {data && !busy && (
        <>
          {data.error && <p className="text-husn-danger text-sm mb-4">{data.error}</p>}

          {data.geo && (
            <div className="grid grid-cols-2 gap-x-12 gap-y-2 mb-4">
              <KV k="Country" v={`${data.geo.flag || ''} ${data.geo.country || '?'}`}/>
              <KV k="City" v={data.geo.city || '—'}/>
              <KV k="ASN" v={data.geo.asn || '—'}/>
              <KV k="Source" v={data.geo.source || '—'}/>
              <KV k="Reputation" v={`${data.reputation?.classification || '?'} (${data.reputation?.source || ''})`}/>
              <KV k="Score" v={data.reputation?.score ?? 0}/>
              <KV k="Block events" v={data.block_event_count ?? 0}/>
              <KV k="Honeypot hits" v={data.honeypot_hits?.length ?? 0}/>
            </div>
          )}

          {data.list_status && (
            <div className="mb-4">
              <div className="text-[10px] text-husn-text-3 uppercase tracking-widest mb-2">{T.listStatus}</div>
              <div className="flex gap-2 flex-wrap text-[11px]">
                {data.list_status.in_ip_whitelist && <span className="husn-pill bg-husn-success/15 text-husn-success">IP whitelisted</span>}
                {data.list_status.in_ip_blacklist && <span className="husn-pill bg-husn-danger/15 text-husn-danger">IP blacklisted</span>}
                {data.list_status.in_country_whitelist && <span className="husn-pill bg-husn-success/15 text-husn-success">Country whitelisted</span>}
                {data.list_status.in_country_blacklist && <span className="husn-pill bg-husn-danger/15 text-husn-danger">Country blacklisted</span>}
                {!Object.values(data.list_status).some(Boolean) && <span className="text-husn-text-3 italic">no list membership</span>}
              </div>
            </div>
          )}

          {data.analysis && (
            <div className="mb-4 rounded-xl border border-husn-border bg-black/40 p-4">
              <div className="text-[10px] uppercase tracking-[0.25em] text-husn-success mb-2">{T.summary}</div>
              <pre className="whitespace-pre-wrap text-[13px] leading-relaxed text-husn-text">{data.analysis}</pre>
            </div>
          )}

          {data.block_events?.length > 0 && (
            <div className="mb-4">
              <div className="text-[10px] text-husn-text-3 uppercase tracking-widest mb-2">{T.eventTimeline}</div>
              <div className="space-y-1 max-h-48 overflow-y-auto text-[11px]">
                {data.block_events.map((e: any, i: number) => (
                  <div key={i} className="flex justify-between gap-3 py-1 border-b border-husn-border">
                    <span className="text-husn-text-3 font-mono">{new Date(e.ts * 1000).toLocaleString()}</span>
                    <span className="text-white">{e.attack_type}</span>
                    <span className="text-husn-text-2">{e.severity}</span>
                    <span className="text-husn-text-3">{((e.confidence || 0) * 100).toFixed(0)}%</span>
                    <span className={`text-[10px] ${e.feedback === 'confirmed' ? 'text-husn-success' : e.feedback === 'false_positive' ? 'text-husn-danger' : 'text-husn-text-3'}`}>{e.feedback || 'unconfirmed'}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {isAdmin && (
            <div className="grid grid-cols-3 gap-2 mt-4">
              <button onClick={onWhitelist} className="text-[11px] py-2 bg-husn-success/10 border border-husn-success/30 text-husn-success rounded-lg uppercase tracking-widest font-medium hover:bg-husn-success/20 transition">
                {T.addToWhitelist}
              </button>
              <button onClick={onBlacklist} className="text-[11px] py-2 bg-husn-danger/10 border border-husn-danger/30 text-husn-danger rounded-lg uppercase tracking-widest font-medium hover:bg-husn-danger/20 transition">
                {T.addToBlacklist}
              </button>
              <button onClick={onAskSoc} className="text-[11px] py-2 bg-white/5 border border-husn-border text-white rounded-lg uppercase tracking-widest font-medium hover:bg-white/10 transition flex items-center justify-center gap-1">
                <MessageSquare size={11}/> {T.askSocAnalyst}
              </button>
            </div>
          )}
        </>
      )}
    </div>
  </div>
);

// ---------- Login screen
const Login = ({ lang, setLang, T, error, onSubmit }: any) => {
  const [u, setU] = useState('');
  const [p, setP] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async (e: any) => {
    e.preventDefault();
    if (!u || !p) return;
    setBusy(true);
    await onSubmit(u, p);
    setBusy(false);
  };
  return (
    <div className={`min-h-screen bg-husn-bg flex items-center justify-center p-6 ${lang === 'ar' ? 'rtl' : 'ltr'}`} dir={lang === 'ar' ? 'rtl' : 'ltr'}>
      <div className="w-full max-w-sm">
        <div className="flex justify-end mb-4">
          <button onClick={() => setLang(lang === 'en' ? 'ar' : 'en')}
            className="text-husn-text-3 hover:text-white text-[12px] flex items-center gap-1.5">
            <Globe size={12}/> {lang === 'en' ? 'العربية' : 'English'}
          </button>
        </div>
        <div className="husn-card p-8">
          <div className="flex flex-col items-center mb-8">
            <img
              src={lang === 'ar' ? logoAR : logoEN}
              alt="Husn"
              className="w-28 h-auto object-contain husn-logo-glow mb-3"
            />
            <div className="text-[10px] text-husn-text-3 uppercase tracking-[0.25em]">{T.tagline}</div>
          </div>
          <h1 className="text-[20px] font-light text-white uppercase tracking-[0.2em]">{T.signIn}</h1>
          <p className="text-husn-text-3 text-[12px] mt-1">{T.loginSubtitle}</p>

          <form onSubmit={submit} className="mt-6 space-y-3">
            <div>
              <label className="text-[11px] text-husn-text-3">{T.username}</label>
              <input type="text" autoFocus value={u} onChange={(e) => setU(e.target.value)}
                className="husn-input w-full mt-1.5 text-sm" autoComplete="username"/>
            </div>
            <div>
              <label className="text-[11px] text-husn-text-3">{T.password}</label>
              <input type="password" value={p} onChange={(e) => setP(e.target.value)}
                className="husn-input w-full mt-1.5 text-sm" autoComplete="current-password"/>
            </div>
            {error && <div className="text-[12px] text-husn-danger bg-husn-danger/10 border border-husn-danger/30 px-3 py-2 rounded-lg">{T[error] || error}</div>}
            <button type="submit" disabled={busy || !u || !p} className="husn-btn-primary w-full mt-2 text-sm flex items-center justify-center gap-2 h-10">
              {busy ? <Activity size={14} className="animate-spin"/> : <Lock size={14}/>}
              {T.signIn}
            </button>
          </form>
        </div>
        <p className="text-center text-[11px] text-husn-text-3 mt-5">
          {lang === 'en' ? 'Default: admin / admin@ — change immediately' : 'الافتراضي: admin / admin@ — غيّرها فوراً'}
        </p>
      </div>
    </div>
  );
};

export default App;
