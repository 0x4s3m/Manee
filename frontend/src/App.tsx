import { useState, useEffect, useRef, useMemo } from 'react';
import axios from 'axios';
import {
  LayoutDashboard, Search, Globe, Play, Eye, Activity,
  Lock, ChevronRight, Server, Network, ShieldOff, RefreshCw,
  Mail, Trash2, HardDrive, Wifi, CheckCircle2, XCircle, GitBranch, Clock,
  Users as UsersIcon, LogOut, UserPlus,
  Cpu, Radio, Sparkles, KeyRound, GitFork, TerminalSquare, Volume2, VolumeX,
  Crosshair, MessageSquare, FileText, X as XClose, Play as PlayIcon,
  Search as SearchIcon, ChevronLeft, Target, Menu, ShieldCheck,
  EyeOff, AlertCircle, Check, Wrench,
  Home, BarChart3, ShieldHalf, FlaskConical, Cog,
} from 'lucide-react';
import ForceGraph2D from 'react-force-graph-2d';
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  Cell,
} from 'recharts';
import { motion, AnimatePresence } from 'framer-motion';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { translations } from './i18n';
import logoEN from './assets/logo.png';
import logoAR from './assets/logo_ar.png';
import KillChainVisualizer from './components/KillChainVisualizer';
import AIInspector from './components/AIInspector';
import AutoPatch from './components/AutoPatch';

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
  const [newUserConfirm, setNewUserConfirm] = useState('');
  const [newUserShowPwd, setNewUserShowPwd] = useState(false);
  const [userError, setUserError] = useState<string | null>(null);
  const [userSearch, setUserSearch] = useState('');
  const [userToDelete, setUserToDelete] = useState<string | null>(null);

  // New: sniffer / honeypot / terminal / audio
  const [snifferStatus, setSnifferStatus] = useState<any>(null);
  const [honeypotStatus, setHoneypotStatus] = useState<any>(null);
  const [cliCommands, setCliCommands] = useState<string[]>([]);
  const [cliCmd, setCliCmd] = useState('sysinfo');
  const [cliArgs, setCliArgs] = useState('');
  const [cliOut, setCliOut] = useState<{ html: string; text: string } | null>(null);
  const [cliBusy, setCliBusy] = useState(false);
  const [audioOn, setAudioOn] = useState<boolean>(() => localStorage.getItem('husn.audio') !== 'off');
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(() => localStorage.getItem('husn.sidebar') === 'collapsed');
  const toggleSidebar = () => {
    setSidebarCollapsed((c) => {
      const next = !c;
      try { localStorage.setItem('husn.sidebar', next ? 'collapsed' : 'expanded'); } catch {}
      return next;
    });
  };

  // Responsive sidebar — three breakpoints:
  //   • < 768px  (mobile)  → sidebar is a drawer; hamburger in header opens it
  //   • 768-1023 (tablet)  → sidebar is auto-collapsed to icon-only
  //   • >= 1024  (desktop) → sidebar is full and the user controls collapse
  const [isMobile, setIsMobile] = useState<boolean>(
    typeof window !== 'undefined' ? window.matchMedia('(max-width: 767px)').matches : false,
  );
  const [isTablet, setIsTablet] = useState<boolean>(
    typeof window !== 'undefined' ? window.matchMedia('(min-width: 768px) and (max-width: 1023px)').matches : false,
  );
  const [drawerOpen, setDrawerOpen] = useState<boolean>(false);

  useEffect(() => {
    const mqMobile = window.matchMedia('(max-width: 767px)');
    const mqTablet = window.matchMedia('(min-width: 768px) and (max-width: 1023px)');
    const onM = (e: MediaQueryListEvent | MediaQueryList) => setIsMobile(('matches' in e ? e.matches : (e as MediaQueryListEvent).matches));
    const onT = (e: MediaQueryListEvent | MediaQueryList) => setIsTablet(('matches' in e ? e.matches : (e as MediaQueryListEvent).matches));
    setIsMobile(mqMobile.matches);
    setIsTablet(mqTablet.matches);
    mqMobile.addEventListener('change', onM as any);
    mqTablet.addEventListener('change', onT as any);
    return () => {
      mqMobile.removeEventListener('change', onM as any);
      mqTablet.removeEventListener('change', onT as any);
    };
  }, []);

  // Drawer auto-closes whenever the user picks a tab on mobile.
  useEffect(() => { if (isMobile) setDrawerOpen(false); }, [activeTab, isMobile]);

  // Effective collapsed state — tablet always collapses; mobile uses drawer.
  const effectiveCollapsed = isTablet ? true : sidebarCollapsed;

  // Sidebar nav uses accordion behavior: opening a section auto-folds the
  // others so the sidebar never gets long enough to scroll. Click an open
  // section to fold everything. Persisted across reloads.
  const [navOpen, setNavOpen] = useState<Record<string, boolean>>(() => {
    try {
      const raw = localStorage.getItem('husn.nav-open');
      if (raw) {
        const parsed = JSON.parse(raw);
        // Migrate old multi-open state → single-open accordion.
        const firstOpen = Object.keys(parsed).find((k) => parsed[k]);
        return firstOpen ? { [firstOpen]: true } : { overview: true };
      }
    } catch {}
    return { overview: true };
  });
  const toggleNavGroup = (k: string) => {
    setNavOpen((o) => {
      const wasOpen = !!o[k];
      const next: Record<string, boolean> = wasOpen ? {} : { [k]: true };
      try { localStorage.setItem('husn.nav-open', JSON.stringify(next)); } catch {}
      return next;
    });
  };

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
  const chatScrollRef = useRef<HTMLDivElement>(null);

  // Snap chat panel to the bottom whenever a new message lands (user sent
  // or bot reply). Also runs when "thinking…" appears so the typing
  // indicator is visible.
  useEffect(() => {
    const el = chatScrollRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [chatHistory.length, chatBusy]);

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
      // Clear soft-lockout state on success.
      try { sessionStorage.removeItem('husn.login-fail'); sessionStorage.removeItem('husn.login-lock'); } catch {}
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
    if (!newUser.username || newUser.password.length < 8) { setUserError(T.userInvalid); return; }
    if (newUser.password !== newUserConfirm) { setUserError('passwordsDoNotMatch'); return; }
    try { await api.post('/auth/users', newUser); setNewUser({ username: '', password: '', role: 'employee' }); setNewUserConfirm(''); setNewUserShowPwd(false); fetchUsers(); addLog(`AUTH: created ${newUser.username}`); }
    catch (e: any) { setUserError(e?.response?.data?.detail || 'failed'); }
  };
  const deleteUser = async (u: string) => {
    if (u === authUser?.username) return;
    try { await api.delete(`/auth/users/${encodeURIComponent(u)}`); fetchUsers(); addLog(`AUTH: deleted ${u}`); }
    catch (e: any) { setUserError(e?.response?.data?.detail || 'delete failed'); }
    setUserToDelete(null);
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
    <div className={`fixed inset-0 bg-husn-bg text-husn-text flex ${isMobile ? 'p-2 gap-2' : 'p-4 gap-4'} ${lang === 'ar' ? 'rtl' : 'ltr'}`} dir={lang === 'ar' ? 'rtl' : 'ltr'}>
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
      {/* Mobile drawer backdrop — shown only when the sidebar is open on a
          mobile viewport. Click to dismiss. */}
      {isMobile && drawerOpen && (
        <div
          onClick={() => setDrawerOpen(false)}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-40 transition-opacity"
        />
      )}

      {/* ============ Sidebar ============ */}
      <aside
        className={`husn-card flex flex-col shrink-0 overflow-hidden transition-all duration-300 ease-out
          ${isMobile
            ? `fixed top-2 ${lang === 'ar' ? 'right-2' : 'left-2'} bottom-2 z-50 w-72
               ${drawerOpen ? 'translate-x-0 opacity-100' : (lang === 'ar' ? 'translate-x-[110%] opacity-0 pointer-events-none' : '-translate-x-[110%] opacity-0 pointer-events-none')}`
            : (effectiveCollapsed ? 'w-14' : 'w-60')
          }`}
      >
        {/* Mobile-only close button at the top-right of the drawer */}
        {isMobile && (
          <button
            onClick={() => setDrawerOpen(false)}
            aria-label="Close menu"
            className={`absolute top-3 ${lang === 'ar' ? 'left-3' : 'right-3'} p-1.5 rounded-md text-husn-text-3 hover:text-white hover:bg-white/[0.05] transition`}
          >
            <XClose size={16}/>
          </button>
        )}

        {/* Brand / logo block — clean, centered, with a subtle subtitle.
            On collapsed sidebars only the icon-sized logo shows. */}
        <div className={`flex flex-col items-center justify-center ${effectiveCollapsed ? 'px-2 pt-5 pb-3' : 'px-5 pt-6 pb-4'}`}>
          <img
            src={lang === 'ar' ? logoAR : logoEN}
            alt="Husn"
            className={`${effectiveCollapsed ? 'w-9' : 'w-24'} h-auto object-contain husn-logo-glow transition-all duration-300`}
          />
          {!effectiveCollapsed && (
            <div className="mt-2 flex items-center gap-1.5 text-[9px] uppercase tracking-[0.18em] text-husn-text-3">
              <ShieldCheck size={9}/>
              <span>{lang === 'en' ? 'Defense Grid' : 'الشبكة الدفاعية'}</span>
            </div>
          )}
        </div>

        {/* Compact status pill — minimal, no bordered card */}
        <SystemStatusPill
          collapsed={effectiveCollapsed}
          online={!!systemStatus}
          uptimeSeconds={monitor?.uptime_seconds ?? hwSnapshot?.os?.uptime_seconds ?? 0}
          lang={lang}
        />

        <div className={`mx-3 mt-3 mb-1 h-px ${effectiveCollapsed ? 'opacity-0' : 'bg-husn-border'}`}/>

        <nav className={`flex-1 ${effectiveCollapsed ? 'px-2' : 'px-3'} py-1 overflow-y-auto`}>
          {/* OVERVIEW */}
          <NavSection k="overview" title={T.navGroupOverview} alert={blocked.length > 0}
            icon={<Home size={14}/>}
            collapsed={effectiveCollapsed} open={navOpen.overview} onToggle={toggleNavGroup}>
            <NavLink icon={<LayoutDashboard size={16}/>} label={T.monitoring} collapsed={effectiveCollapsed} active={activeTab === 'dashboard'} onClick={() => setActiveTab('dashboard')}/>
            <NavLink icon={<Target size={16}/>} label={T.killChain} collapsed={effectiveCollapsed} active={activeTab === 'kill-chain'} onClick={() => setActiveTab('kill-chain')}
              badge={blocked.length > 0 ? blocked.length : undefined}/>
          </NavSection>

          {/* TELEMETRY */}
          <NavSection k="telemetry" title={T.navGroupTelemetry}
            icon={<BarChart3 size={14}/>}
            collapsed={effectiveCollapsed} open={navOpen.telemetry} onToggle={toggleNavGroup}>
            <NavLink icon={<Server size={16}/>} label={T.host} collapsed={effectiveCollapsed} active={activeTab === 'host'} onClick={() => setActiveTab('host')}/>
            <NavLink icon={<Network size={16}/>} label={T.network} collapsed={effectiveCollapsed} active={activeTab === 'network'} onClick={() => setActiveTab('network')}/>
            <NavLink icon={<Radio size={16}/>} label={T.connections || 'Connections'} collapsed={effectiveCollapsed} active={activeTab === 'connections'} onClick={() => setActiveTab('connections')}
              badge={connections?.total > 0 ? connections.total : undefined}/>
            <NavLink icon={<GitFork size={16}/>} label={T.topology} collapsed={effectiveCollapsed} active={activeTab === 'topology'} onClick={() => setActiveTab('topology')}/>
          </NavSection>

          {/* DEFENSE */}
          <NavSection k="detect" title={T.navGroupDetect} alert={blocked.length > 0}
            icon={<ShieldHalf size={14}/>}
            collapsed={effectiveCollapsed} open={navOpen.detect} onToggle={toggleNavGroup}>
            <NavLink icon={<Search size={16}/>} label={T.detection} collapsed={effectiveCollapsed} active={activeTab === 'recon'} onClick={() => setActiveTab('recon')}/>
            <NavLink icon={<Eye size={16}/>} label={T.aiInspector} collapsed={effectiveCollapsed} active={activeTab === 'ai-inspect'} onClick={() => setActiveTab('ai-inspect')}
              dot={(snifferStatus?.recent_packets?.length ?? 0) > 0}/>
            <NavLink icon={<Eye size={16}/>} label={T.explainableAI} collapsed={effectiveCollapsed} active={activeTab === 'xai'} onClick={() => setActiveTab('xai')}/>
            <NavLink icon={<ShieldOff size={16}/>} label={T.defense} collapsed={effectiveCollapsed} active={activeTab === 'defense'} onClick={() => setActiveTab('defense')}
              badge={blocked.length > 0 ? blocked.length : undefined}/>
            <NavLink icon={<Crosshair size={16}/>} label={T.honeypot} collapsed={effectiveCollapsed} active={activeTab === 'honeypot'} onClick={() => setActiveTab('honeypot')}
              dot={(honeypotStatus?.connections_total ?? 0) > 0}/>
          </NavSection>

          {/* ANALYSIS */}
          <NavSection k="analysis" title={T.navGroupAnalysis}
            icon={<FlaskConical size={14}/>}
            collapsed={effectiveCollapsed} open={navOpen.analysis} onToggle={toggleNavGroup}>
            <NavLink icon={<MessageSquare size={16}/>} label={T.chat} collapsed={effectiveCollapsed} active={activeTab === 'chat'} onClick={() => setActiveTab('chat')}
              dot={chatStatus?.configured && chatHistory.length === 0 ? false : undefined}/>
            <NavLink icon={<FileText size={16}/>} label={T.reports} collapsed={effectiveCollapsed} active={activeTab === 'reports'} onClick={() => setActiveTab('reports')}/>
          </NavSection>

          {/* ADMIN */}
          {isAdmin && (
            <NavSection k="admin" title={T.navGroupAdmin}
              icon={<Cog size={14}/>}
              collapsed={effectiveCollapsed} open={navOpen.admin} onToggle={toggleNavGroup}>
              <NavLink icon={<Wrench size={16}/>} label={T.autoPatch} collapsed={effectiveCollapsed} active={activeTab === 'autopatch'} onClick={() => setActiveTab('autopatch')}/>
              <NavLink icon={<RefreshCw size={16}/>} label={T.updates} collapsed={effectiveCollapsed} active={activeTab === 'updates'} onClick={() => setActiveTab('updates')}
                dot={updateStatus?.last_check?.available}/>
              <NavLink icon={<TerminalSquare size={16}/>} label={T.terminal} collapsed={effectiveCollapsed} active={activeTab === 'terminal'} onClick={() => setActiveTab('terminal')}/>
              <NavLink icon={<UsersIcon size={16}/>} label={T.users} collapsed={effectiveCollapsed} active={activeTab === 'users'} onClick={() => setActiveTab('users')}/>
            </NavSection>
          )}
        </nav>

        {/* Live traffic sparkline — only when expanded */}
        {!effectiveCollapsed && (
          <SidebarSparkline series={trafficSeries} blockedCount={blocked.length} lang={lang}/>
        )}

        {/* National Defense card — bigger, neon, attention-grabbing.
            This is one of the centerpieces judges look at, so the
            button is the largest interactive element in the sidebar. */}
        {!effectiveCollapsed && (
          <div
            className={`mx-3 mb-2 p-3.5 rounded-xl border transition-all
              ${systemStatus?.defense_mode === 'National'
                ? 'border-husn-danger/40 bg-husn-danger/5 shadow-[0_0_24px_rgba(244,63,94,0.20)]'
                : 'border-husn-border bg-black/30'}`}
          >
            <div className="flex items-center justify-between mb-2.5">
              <span className="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.14em] text-husn-text-2 font-medium">
                <Sparkles size={12} className={systemStatus?.defense_mode === 'National' ? 'text-husn-danger animate-pulse' : 'text-husn-text-3'}/>
                {T.nationalDefense}
              </span>
              <span
                className={`text-[9px] uppercase tracking-[0.14em] flex items-center gap-1
                  ${systemStatus?.defense_mode === 'National' ? 'text-husn-danger' : 'text-husn-text-3'}`}>
                <span
                  className={`w-1 h-1 rounded-full
                    ${systemStatus?.defense_mode === 'National' ? 'bg-husn-danger animate-pulse' : 'bg-husn-text-3'}`}/>
                {systemStatus?.defense_mode === 'National' ? (lang === 'en' ? 'active' : 'مفعّل') : (lang === 'en' ? 'standby' : 'احتياطي')}
              </span>
            </div>
            <button
              onClick={toggleDefense}
              disabled={isToggling || !isAdmin}
              title={!isAdmin ? 'Admin only' : ''}
              className={`w-full text-[12px] font-semibold py-2.5 rounded-lg transition-all uppercase tracking-[0.14em]
                disabled:opacity-30 disabled:cursor-not-allowed flex items-center justify-center gap-2
                ${systemStatus?.defense_mode === 'National'
                  ? 'bg-husn-danger/20 text-husn-danger hover:bg-husn-danger/30 border border-husn-danger/50 shadow-[0_0_16px_rgba(244,63,94,0.30)] hover:shadow-[0_0_22px_rgba(244,63,94,0.45)]'
                  : 'bg-husn-success text-black hover:brightness-110 border border-husn-success shadow-[0_0_16px_rgba(16,185,129,0.40)] hover:shadow-[0_0_24px_rgba(16,185,129,0.60)]'}`}
            >
              {isToggling ? <Activity size={13} className="animate-spin"/> : <Sparkles size={13}/>}
              {systemStatus?.defense_mode === 'National' ? (T.deactivate || 'Deactivate') : (T.activate || 'Activate')}
            </button>
          </div>
        )}

        {/* Footer — language + collapse toggle in one tight row */}
        <div className={`border-t border-husn-border ${effectiveCollapsed ? 'p-2 flex-col gap-1.5' : 'px-3 py-2.5 justify-between'} flex items-center`}>
          {!effectiveCollapsed && (
            <button onClick={() => setLang(lang === 'en' ? 'ar' : 'en')}
              className="flex items-center gap-1.5 px-2 py-1 rounded-md text-[10px] uppercase tracking-[0.14em] text-husn-text-3 hover:text-white hover:bg-white/[0.04] transition">
              <Globe size={11}/> {lang === 'en' ? 'العربية' : 'English'}
            </button>
          )}
          {effectiveCollapsed && (
            <button onClick={() => setLang(lang === 'en' ? 'ar' : 'en')}
              title={lang === 'en' ? 'العربية' : 'English'}
              className="p-1.5 rounded-md text-husn-text-3 hover:text-white hover:bg-white/[0.04] transition">
              <Globe size={14}/>
            </button>
          )}
          {/* The collapse toggle is hidden on tablet (auto-collapsed) and
              on mobile (drawer mode). It's a desktop-only control. */}
          {!isMobile && !isTablet && (
            <button onClick={toggleSidebar}
              title={sidebarCollapsed ? (lang === 'en' ? 'Expand' : 'توسيع') : (lang === 'en' ? 'Collapse' : 'طي')}
              className="p-1.5 rounded-md text-husn-text-3 hover:text-white hover:bg-white/[0.04] transition">
              {sidebarCollapsed
                ? (lang === 'ar' ? <ChevronLeft size={14}/> : <ChevronRight size={14}/>)
                : (lang === 'ar' ? <ChevronRight size={14}/> : <ChevronLeft size={14}/>)}
            </button>
          )}
        </div>
      </aside>

      {/* ============ Main column ============ */}
      <main className="flex-1 min-w-0 min-h-0 flex flex-col gap-4 overflow-hidden">
        {/* Header bar — collapses gracefully on small screens. The
            search box hides on mobile (the dashboard is read-only there
            mostly) and the run-scan button shrinks to an icon. */}
        <header className={`husn-card flex items-center gap-2 sm:gap-4 ${isMobile ? 'px-3 py-3' : 'px-6 py-4'}`}>
          {/* Mobile-only hamburger to open the drawer */}
          {isMobile && (
            <button onClick={() => setDrawerOpen(true)}
              aria-label="Open menu"
              className="p-2 rounded-lg border border-husn-border text-husn-text-2 hover:text-white hover:border-husn-border-2 transition shrink-0">
              <Menu size={18}/>
            </button>
          )}
          <div className="flex items-center gap-2 text-husn-text-2 text-sm min-w-0">
            <LayoutDashboard size={16} className="shrink-0"/>
            <span className="capitalize truncate">{tabTitle(activeTab, T)}</span>
          </div>
          {!isMobile && (
            <div className="flex-1 max-w-md mx-auto relative">
              <Search size={14} className={`absolute top-2.5 ${lang === 'ar' ? 'right-3' : 'left-3'} text-husn-text-3`}/>
              <input className={`husn-input w-full text-sm ${lang === 'ar' ? 'pr-9 pl-3' : 'pl-9 pr-3'}`}
                placeholder={T.target} value={target} onChange={(e) => setTarget(e.target.value)}/>
            </div>
          )}
          {isMobile && <div className="flex-1"/>}
          <button onClick={startScan} disabled={isScanning || !target || !isAdmin}
            title={!isAdmin ? 'Admin only' : (isMobile ? T.runScan : '')}
            className="husn-btn-primary text-sm flex items-center gap-2 shrink-0">
            {isScanning ? <Activity size={14} className="animate-spin"/> : <Play size={14}/>}
            {!isMobile && (isScanning ? T.scanning || 'Scanning...' : T.runScan)}
          </button>
          {/* audio toggle */}
          <button onClick={toggleAudio} title={audioOn ? T.audioOn : T.audioOff}
            className={`p-2 rounded-lg border transition shrink-0 ${audioOn ? 'border-husn-border-2 text-white bg-white/[0.04]' : 'border-husn-border text-husn-text-3 hover:text-white'}`}>
            {audioOn ? <Volume2 size={14}/> : <VolumeX size={14}/>}
          </button>
          <div className={`flex items-center gap-2 sm:gap-3 ${lang === 'ar' ? 'mr-1 sm:mr-2' : 'ml-1 sm:ml-2'} px-1 sm:px-2 shrink-0`}>
            {!isMobile && (
              <div className="text-right">
                <div className="text-xs text-white font-medium leading-tight">{authUser?.username}</div>
                <div className="text-[10px] text-husn-text-3 capitalize">{authUser?.role === 'admin' ? T.admin : T.employee}</div>
              </div>
            )}
            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-semibold
              ${authUser?.role === 'admin' ? 'bg-white text-husn-bg' : 'bg-white/10 text-white'}`}>
              {(authUser?.username || '?').slice(0, 1).toUpperCase()}
            </div>
            <button onClick={logout} className="text-husn-text-3 hover:text-husn-danger transition" title={T.signOut}>
              <LogOut size={16}/>
            </button>
          </div>
        </header>

        {/* Welcome line + prominent Defense Mode pill */}
        <div className="flex items-end justify-between mt-1 px-1 gap-3">
          <div className="min-w-0">
            <h1 className="text-[22px] sm:text-[24px] font-light uppercase tracking-[0.16em] text-white leading-tight truncate">
              {lang === 'en' ? `Welcome back, ${authUser?.username}` : `مرحباً، ${authUser?.username}`}
            </h1>
            <p className="text-husn-text-3 text-[11px] uppercase tracking-[0.16em] mt-1 flex items-center gap-2">
              <ShieldCheck size={11} className="text-husn-success"/>
              <span>{lang === 'en' ? 'Husn Defense Grid' : 'شبكة حصن الدفاعية'}</span>
              <span className="text-husn-border-2">·</span>
              <span className="flex items-center gap-1">
                <span className="w-1 h-1 rounded-full bg-husn-success animate-pulse"/>
                {lang === 'en' ? 'Active' : 'نشطة'}
              </span>
            </p>
          </div>
          {/* Big neon Defense Mode pill — clearly the primary status indicator */}
          <div className={`shrink-0 flex items-center gap-3 px-4 py-2.5 rounded-xl border transition-all
            ${systemStatus?.defense_mode === 'National'
              ? 'bg-husn-danger/10 border-husn-danger/40 shadow-[0_0_24px_rgba(244,63,94,0.25)]'
              : 'bg-husn-success/10 border-husn-success/30 shadow-[0_0_18px_rgba(16,185,129,0.18)]'}`}>
            <span className="relative flex w-2 h-2">
              <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping
                ${systemStatus?.defense_mode === 'National' ? 'bg-husn-danger' : 'bg-husn-success'}`}/>
              <span className={`relative inline-flex rounded-full h-2 w-2
                ${systemStatus?.defense_mode === 'National' ? 'bg-husn-danger' : 'bg-husn-success'}`}/>
            </span>
            <div className="leading-tight">
              <div className="text-[9px] uppercase tracking-[0.18em] text-husn-text-3">
                {lang === 'en' ? 'Defense mode' : 'وضع الدفاع'}
              </div>
              <div className={`text-[14px] font-semibold uppercase tracking-[0.10em]
                ${systemStatus?.defense_mode === 'National' ? 'text-husn-danger' : 'text-husn-success'}`}>
                {systemStatus?.defense_mode === 'National'
                  ? (lang === 'en' ? 'National' : 'وطني')
                  : (lang === 'en' ? 'Standard' : 'قياسي')}
              </div>
            </div>
          </div>
        </div>

        {/* Tab content */}
        <div className="flex gap-4 min-h-0 flex-1">
          <div className="flex-1 min-w-0 overflow-y-auto pb-2">
            <AnimatePresence mode="wait">
              {activeTab === 'dashboard' && (
                <Tab k="dashboard">
                  {/* Hero KPIs — analyst-focused: what was blocked, how
                      sure the AI was, what's live right now, and
                      whether the grid itself is healthy. */}
                  <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                    <Kpi
                      label={lang === 'en' ? 'Threats blocked' : 'تهديدات محظورة'}
                      value={fmtNum(monitor?.blocks_total ?? blocked.length)}
                      sub={`${monitor?.blocked_now ?? 0} ${lang === 'en' ? 'currently' : 'حالياً'}`}
                      icon={<ShieldOff size={16}/>}
                      highlight={(monitor?.blocks_total ?? 0) > 0}
                    />
                    <Kpi
                      label={lang === 'en' ? 'AI confidence' : 'ثقة الذكاء'}
                      value={(() => {
                        const arr = snifferStatus?.recent_packets || [];
                        if (!arr.length) return '—';
                        const avg = arr.reduce((s: number, p: any) => s + (p.confidence || 0), 0) / arr.length;
                        return `${Math.round(avg * 100)}%`;
                      })()}
                      sub={`${snifferStatus?.recent_packets?.length ?? 0} ${lang === 'en' ? 'flows scored' : 'تدفقات مفحوصة'}`}
                      icon={<Eye size={16}/>}
                    />
                    <Kpi
                      label={lang === 'en' ? 'Live threats' : 'تهديدات حيّة'}
                      value={fmtNum((snifferStatus?.recent_packets || []).filter((p: any) => p.is_anomaly && p.label !== 'BENIGN').length)}
                      sub={`${snifferStatus?.predictions ?? 0} ${lang === 'en' ? 'AI runs' : 'تشغيل ذكاء'}`}
                      icon={<Activity size={16}/>}
                      highlight={((snifferStatus?.recent_packets || []).filter((p: any) => p.is_anomaly && p.label !== 'BENIGN').length) > 0}
                    />
                    <Kpi
                      label={lang === 'en' ? 'System status' : 'حالة النظام'}
                      value={systemStatus
                        ? (lang === 'en' ? 'ONLINE' : 'متصل')
                        : (lang === 'en' ? 'OFFLINE' : 'منقطع')}
                      sub={fmtUptime(monitor?.uptime_seconds ?? 0)}
                      icon={<ShieldCheck size={16}/>}
                    />
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

              {activeTab === 'kill-chain' && (
                <Tab k="kill-chain">
                  <KillChainVisualizer
                    blocked={blocked}
                    shap={shapData}
                    lang={lang}
                    T={T}
                    onInvestigate={investigate}
                  />
                </Tab>
              )}

              {activeTab === 'ai-inspect' && (
                <Tab k="ai-inspect">
                  <div className="flex justify-between items-end mb-3">
                    <div>
                      <h3 className="text-[15px] font-light uppercase tracking-[0.18em] text-white">{T.aiInspector}</h3>
                      <p className="text-husn-text-3 text-[11px] mt-1 tracking-normal max-w-2xl">
                        {T.aiInspectorDesc}
                      </p>
                    </div>
                  </div>
                  <AIInspector
                    packets={snifferStatus?.recent_packets || []}
                    lang={lang}
                    T={T}
                    onInvestigate={investigate}
                  />
                </Tab>
              )}

              {activeTab === 'autopatch' && isAdmin && (
                <Tab k="autopatch">
                  <div className="flex justify-between items-end mb-3">
                    <div>
                      <h3 className="text-[15px] font-light uppercase tracking-[0.18em] text-white">{T.autoPatch}</h3>
                      <p className="text-husn-text-3 text-[11px] mt-1 tracking-normal max-w-2xl">
                        {T.autoPatchDesc}
                      </p>
                    </div>
                  </div>
                  <AutoPatch api={api} isAdmin={isAdmin} T={T} lang={lang} addLog={addLog}/>
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
                    <div ref={chatScrollRef}
                      className="bg-black/40 border border-husn-border rounded-xl p-4 min-h-[420px] max-h-[55vh] overflow-y-auto"
                      style={{ scrollBehavior: 'smooth', overflowAnchor: 'none' }}>
                      {chatHistory.length === 0 && (
                        <p className="text-[12px] text-husn-text-3 italic">husn analyst ready — ask anything about your live security state.</p>
                      )}
                      {chatHistory.map((m, i) => (
                        <div key={i} className={`mb-4 ${m.role === 'user' ? 'text-white' : 'text-husn-text'}`}>
                          <div className={`text-[10px] uppercase tracking-[0.18em] mb-1 ${m.role === 'user' ? 'text-husn-text-3' : 'text-husn-success'}`}>
                            {m.role === 'user' ? (authUser?.username || 'you') : 'analyst'}
                          </div>
                          <div className={`text-[13px] leading-relaxed husn-markdown ${m.ok === false ? 'text-husn-danger' : ''}`}>
                            {m.role === 'user' ? (
                              <span className="whitespace-pre-wrap">{m.content}</span>
                            ) : (
                              <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                {m.content}
                              </ReactMarkdown>
                            )}
                          </div>
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
                  <UsersPanel
                    T={T}
                    lang={lang}
                    authUser={authUser}
                    userList={userList}
                    userSearch={userSearch}
                    setUserSearch={setUserSearch}
                    newUser={newUser}
                    setNewUser={setNewUser}
                    newUserConfirm={newUserConfirm}
                    setNewUserConfirm={setNewUserConfirm}
                    newUserShowPwd={newUserShowPwd}
                    setNewUserShowPwd={setNewUserShowPwd}
                    userError={userError}
                    onCreate={createUser}
                    onAskDelete={(u: string) => setUserToDelete(u)}
                  />

                  {/* Delete-user confirmation modal */}
                  {userToDelete && (
                    <div
                      className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4"
                      onClick={() => setUserToDelete(null)}
                    >
                      <div
                        className="husn-card p-6 max-w-sm w-full"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <div className="flex items-center gap-2 mb-2">
                          <AlertCircle size={16} className="text-husn-danger"/>
                          <h4 className="text-white text-[13px] uppercase tracking-[0.16em]">{T.confirmDelete}</h4>
                        </div>
                        <p className="text-[12px] text-husn-text-2 mb-1 font-mono">{userToDelete}</p>
                        <p className="text-[11px] text-husn-text-3 mb-5">{T.deleteUserWarn}</p>
                        <div className="flex gap-2 justify-end">
                          <button onClick={() => setUserToDelete(null)} className="husn-btn-ghost text-xs">
                            {T.cancel}
                          </button>
                          <button
                            onClick={() => deleteUser(userToDelete!)}
                            className="text-xs uppercase tracking-[0.14em] px-4 py-2 rounded-lg bg-husn-danger/15 text-husn-danger border border-husn-danger/30 hover:bg-husn-danger/25 transition flex items-center gap-2"
                          >
                            <Trash2 size={12}/> {T.deleteUser}
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
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
  recon: T.detection, xai: T.explainableAI,
  defense: T.defense, updates: T.updates, users: T.users,
  chat: T.chat, reports: T.reports,
  'kill-chain': T.killChain,
  'ai-inspect': T.aiInspector,
  autopatch: T.autoPatch,
}[t] || 'Dashboard');

const Tab = ({ children }: any) => (
  // Plain div — no motion animation. Framer's transform-on-mount can interact
  // with overflow containers in subtle ways and isn't worth the visual cost.
  <div>{children}</div>
);

const NavLink = ({ icon, label, active, onClick, badge, dot, collapsed }: any) => (
  <button onClick={onClick} title={collapsed ? label : undefined}
    className={`w-full flex items-center ${collapsed ? 'justify-center px-1 py-2' : 'gap-2.5 px-3 py-2'} rounded-lg text-[9.5px] font-medium uppercase tracking-[0.15em] transition-all relative
      ${active
        ? 'bg-white/10 text-white border border-white/20 shadow-[inset_0_0_30px_rgba(255,255,255,0.04)]'
        : 'text-husn-text-3 border border-transparent hover:text-white hover:bg-white/[0.03]'}`}>
    {/* Smooth active-tab indicator that slides between tabs using framer
        layoutId. Only one instance is rendered at any time, which is what
        triggers the morph animation. */}
    {active && (
      <motion.span
        layoutId="nav-active-rail"
        className="absolute left-0 top-1.5 bottom-1.5 w-[2px] rounded-full bg-white"
        transition={{ type: 'spring', stiffness: 380, damping: 32 }}
      />
    )}
    <span className={active ? 'text-white' : 'text-husn-text-3'}>{icon}</span>
    {!collapsed && <span className="flex-1 text-left">{label}</span>}
    {!collapsed && badge !== undefined && (
      <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded-full bg-husn-danger/90 text-white tracking-normal">
        {badge}
      </span>
    )}
    {collapsed && badge !== undefined && (
      <span className="absolute top-0.5 right-0.5 w-1.5 h-1.5 rounded-full bg-husn-danger"/>
    )}
    {dot && <span className={`${collapsed ? 'absolute top-0.5 right-0.5' : ''} w-1.5 h-1.5 rounded-full bg-husn-warn animate-pulse`}/>}
  </button>
);

// ---- Sidebar premium widgets ---------------------------------------

// Live system status pill — minimal, no bordered card. Just a pulsing dot
// and tight typography so it reads as a status line, not a notification.
const SystemStatusPill = ({ collapsed, online, uptimeSeconds, lang }: {
  collapsed: boolean; online: boolean; uptimeSeconds: number; lang: 'en' | 'ar';
}) => {
  const color = online ? '#10b981' : '#f43f5e';
  const stateLabel = lang === 'en'
    ? (online ? 'Online' : 'Offline')
    : (online ? 'متصل'    : 'منقطع');
  const uptimeText = online && uptimeSeconds ? fmtUptime(uptimeSeconds) : (lang === 'en' ? '—' : '—');

  if (collapsed) {
    return (
      <div className="flex justify-center pb-1" title={stateLabel}>
        <span className="relative flex w-1.5 h-1.5">
          {online && (
            <span className="absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping"
              style={{ background: color }}/>
          )}
          <span className="relative inline-flex rounded-full h-1.5 w-1.5"
            style={{ background: color, boxShadow: `0 0 6px ${color}` }}/>
        </span>
      </div>
    );
  }

  return (
    <div className="mx-5 flex items-center gap-2 text-[10px] uppercase tracking-[0.14em]">
      <span className="relative flex w-1.5 h-1.5 shrink-0">
        {online && (
          <span className="absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping"
            style={{ background: color }}/>
        )}
        <span className="relative inline-flex rounded-full h-1.5 w-1.5"
          style={{ background: color, boxShadow: `0 0 6px ${color}` }}/>
      </span>
      <span style={{ color }}>{stateLabel}</span>
      <span className="text-husn-border-2">·</span>
      <span className="text-husn-text-3 tracking-normal">{uptimeText}</span>
    </div>
  );
};

// Sidebar live traffic sparkline. Reuses the trafficSeries the dashboard
// is already polling — zero extra network cost. Renders as an inline SVG
// so we don't pull in Recharts overhead inside the sidebar (the main
// dashboard area still uses Recharts for the big chart).
const SidebarSparkline = ({ series, blockedCount, lang }: {
  series: { i: number; inn: number; out: number }[]; blockedCount: number; lang: 'en' | 'ar';
}) => {
  const w = 200, h = 36;
  const pts = series.length ? series : Array.from({ length: 60 }, (_, i) => ({ i, inn: 0, out: 0 }));
  const max = Math.max(1, ...pts.map((p) => p.inn + p.out));
  const path = pts.map((p, i) => {
    const x = (i / (pts.length - 1 || 1)) * w;
    const y = h - ((p.inn + p.out) / max) * (h - 2);
    return `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(' ');
  const area = `${path} L ${w} ${h} L 0 ${h} Z`;
  const last = pts[pts.length - 1];
  const lastBytes = last ? last.inn + last.out : 0;

  return (
    <div className="m-3 p-3 rounded-2xl border border-husn-border bg-black/20">
      <div className="flex items-baseline justify-between mb-1.5">
        <span className="text-[9px] font-semibold uppercase tracking-[0.16em] text-husn-text-3">
          {lang === 'en' ? 'Live traffic' : 'حركة مباشرة'}
        </span>
        <span className="text-[10px] text-white tracking-normal font-mono">{fmtBytes(lastBytes)}</span>
      </div>
      <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-9">
        <defs>
          <linearGradient id="ssGrad" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%"   stopColor="rgba(255,255,255,0.35)"/>
            <stop offset="100%" stopColor="rgba(255,255,255,0)"/>
          </linearGradient>
        </defs>
        <path d={area} fill="url(#ssGrad)"/>
        <path d={path} fill="none" stroke="rgba(255,255,255,0.85)" strokeWidth="1.2" strokeLinecap="round"/>
        {/* Throbbing dot at the leading edge */}
        <circle cx={w} cy={h - ((last?.inn ?? 0) + (last?.out ?? 0)) / max * (h - 2)} r="2"
          fill={blockedCount > 0 ? '#f43f5e' : '#10b981'}>
          <animate attributeName="opacity" values="1;0.3;1" dur="1.4s" repeatCount="indefinite"/>
        </circle>
      </svg>
      <div className="flex justify-between mt-1.5">
        <span className="text-[9px] text-husn-text-3 tracking-normal">{pts.length}s</span>
        <span className="text-[9px] tracking-normal" style={{ color: blockedCount > 0 ? '#f43f5e' : '#10b981' }}>
          {blockedCount > 0
            ? (lang === 'en' ? `${blockedCount} blocked` : `${blockedCount} محظور`)
            : (lang === 'en' ? 'all clear' : 'الوضع آمن')}
        </span>
      </div>
    </div>
  );
};

// Sidebar section header + collapsible body. Acts like a folder: clicking
// anywhere on the header toggles its items. The chevron is always visible
// so it reads as clearly interactive. When the whole sidebar is in
// icon-only mode, the header collapses to a small centered divider so the
// grouping is still legible without taking a whole row.
const NavSection = ({ k, title, children, collapsed, open, onToggle, alert, icon }: any) => {
  if (collapsed) {
    // Collapsed mode: section is identified by a small centered icon
    // (instead of a horizontal divider line). Hover shows the title as
    // tooltip. Sections are visually grouped by the spacing around the
    // icon plus a tiny faded divider underneath it.
    return (
      <div className="my-1.5 relative">
        <div className="flex justify-center" title={title}>
          <span className={`flex items-center justify-center w-7 h-7 rounded-md border transition
            ${alert
              ? 'border-husn-danger/40 text-husn-danger bg-husn-danger/5'
              : 'border-husn-border text-husn-text-3 bg-white/[0.02]'}`}>
            {icon || <ChevronRight size={12}/>}
            {alert && (
              <span className="absolute -top-0.5 right-1 w-1.5 h-1.5 rounded-full bg-husn-danger animate-pulse"/>
            )}
          </span>
        </div>
        <div className="mt-1 space-y-0.5">{children}</div>
      </div>
    );
  }
  return (
    <div className="mb-1.5">
      <button
        onClick={() => onToggle(k)}
        className="w-full flex items-center justify-between gap-1.5 px-2 py-1.5 rounded-md
          text-[9px] font-semibold uppercase tracking-[0.10em] whitespace-nowrap
          text-husn-text-3 hover:text-white hover:bg-white/[0.02] transition group"
      >
        <span className="flex items-center gap-2 min-w-0">
          {icon ? (
            <span className={`shrink-0 ${alert ? 'text-husn-danger' : (open ? 'text-white' : 'text-husn-text-3')} group-hover:text-white transition-colors`}>
              {icon}
            </span>
          ) : (
            <span className={`block w-1 h-1 rounded-full shrink-0 transition-colors ${
              alert ? 'bg-husn-danger animate-pulse' : (open ? 'bg-white/70' : 'bg-husn-text-3')
            }`}/>
          )}
          <span className={`truncate ${alert ? 'text-husn-danger' : ''}`}>{title}</span>
        </span>
        <ChevronRight
          size={10}
          className={`shrink-0 transition-transform duration-200 text-husn-text-3 group-hover:text-white ${open ? 'rotate-90' : ''}`}
        />
      </button>
      <div
        className="overflow-hidden transition-[max-height,opacity] duration-200 ease-out"
        style={{ maxHeight: open ? 720 : 0, opacity: open ? 1 : 0 }}
      >
        <div className="ml-2 pl-2 border-l border-husn-border space-y-0.5 pt-1 pb-1">
          {children}
        </div>
      </div>
    </div>
  );
};

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
              <div className="text-[13px] leading-relaxed text-husn-text husn-markdown">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{data.analysis}</ReactMarkdown>
              </div>
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

// ---------- Users panel
// A small password-strength scorer. Cheap rules-based — *not* a security
// boundary (the backend still enforces hashing / rate limit / etc) — but
// gives visible feedback so admins don't create weak accounts.
function pwStrength(pw: string): { score: 0|1|2|3|4; label: string; color: string } {
  let s = 0;
  if (pw.length >= 8)  s++;
  if (pw.length >= 12) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  const score = Math.max(0, Math.min(4, s)) as 0|1|2|3|4;
  const presets = [
    { label: 'pwStrengthWeak',   color: '#f43f5e' },
    { label: 'pwStrengthWeak',   color: '#f43f5e' },
    { label: 'pwStrengthFair',   color: '#f59e0b' },
    { label: 'pwStrengthGood',   color: '#a1a1aa' },
    { label: 'pwStrengthStrong', color: '#10b981' },
  ];
  return { score, ...presets[score] };
}

const UsersPanel = ({
  T, lang, authUser, userList, userSearch, setUserSearch,
  newUser, setNewUser, newUserConfirm, setNewUserConfirm,
  newUserShowPwd, setNewUserShowPwd, userError, onCreate, onAskDelete,
}: any) => {
  const strength = pwStrength(newUser.password);
  const matches  = newUser.password.length > 0 && newUser.password === newUserConfirm;
  const filtered = userList.filter(
    (u: any) => !userSearch || u.username.toLowerCase().includes(userSearch.toLowerCase())
  );

  return (
    <>
      {/* Add User card */}
      <Card title={T.addUser} icon={<UserPlus size={14}/>}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {/* Username + Role */}
          <div className="space-y-3">
            <div>
              <label className="text-[10px] uppercase tracking-[0.14em] text-husn-text-3">{T.username}</label>
              <input
                type="text" value={newUser.username}
                onChange={(e) => setNewUser({ ...newUser, username: e.target.value.replace(/\s/g, '').toLowerCase() })}
                placeholder="alice.smith"
                spellCheck={false}
                autoCapitalize="off"
                className="husn-input w-full text-sm font-mono tracking-normal mt-1.5"/>
            </div>
            <div>
              <label className="text-[10px] uppercase tracking-[0.14em] text-husn-text-3">{T.role}</label>
              <div className="grid grid-cols-2 gap-2 mt-1.5">
                {(['employee', 'admin'] as const).map((r) => (
                  <button key={r} type="button"
                    onClick={() => setNewUser({ ...newUser, role: r })}
                    className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-[11px] uppercase tracking-[0.12em] transition
                      ${newUser.role === r
                        ? 'border-white/30 bg-white/5 text-white'
                        : 'border-husn-border text-husn-text-3 hover:text-white hover:border-husn-border-2'}`}>
                    {r === 'admin' ? <KeyRound size={12}/> : <UsersIcon size={12}/>}
                    {r === 'admin' ? T.admin : T.employee}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Password + confirm + strength */}
          <div className="space-y-3">
            <div>
              <label className="text-[10px] uppercase tracking-[0.14em] text-husn-text-3">{T.password}</label>
              <div className="relative mt-1.5">
                <input
                  type={newUserShowPwd ? 'text' : 'password'}
                  value={newUser.password}
                  onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                  className={`husn-input w-full text-sm font-mono tracking-normal ${lang === 'ar' ? 'pl-10 pr-3' : 'pr-10 pl-3'}`}
                  autoComplete="new-password"/>
                <button type="button"
                  onClick={() => setNewUserShowPwd((s: boolean) => !s)}
                  title={newUserShowPwd ? T.hidePassword : T.showPassword}
                  className={`absolute top-1/2 -translate-y-1/2 ${lang === 'ar' ? 'left-2.5' : 'right-2.5'} text-husn-text-3 hover:text-white transition`}>
                  {newUserShowPwd ? <EyeOff size={14}/> : <Eye size={14}/>}
                </button>
              </div>
              {/* Strength meter (4 segments) */}
              {newUser.password && (
                <div className="mt-2">
                  <div className="flex gap-1">
                    {[0, 1, 2, 3].map((i) => (
                      <div key={i} className="flex-1 h-1 rounded-full bg-husn-border overflow-hidden">
                        <div
                          className="h-full transition-all duration-200"
                          style={{
                            width: strength.score > i ? '100%' : '0%',
                            background: strength.color,
                          }}
                        />
                      </div>
                    ))}
                  </div>
                  <p className="text-[10px] mt-1 tracking-normal" style={{ color: strength.color }}>
                    {T.passwordStrength} · {T[strength.label]}
                  </p>
                </div>
              )}
            </div>

            <div>
              <label className="text-[10px] uppercase tracking-[0.14em] text-husn-text-3">{T.confirmPassword}</label>
              <div className="relative mt-1.5">
                <input
                  type={newUserShowPwd ? 'text' : 'password'}
                  value={newUserConfirm}
                  onChange={(e) => setNewUserConfirm(e.target.value)}
                  className={`husn-input w-full text-sm font-mono tracking-normal ${lang === 'ar' ? 'pl-10 pr-3' : 'pr-10 pl-3'}`}
                  autoComplete="new-password"/>
                {newUserConfirm && (
                  <span className={`absolute top-1/2 -translate-y-1/2 ${lang === 'ar' ? 'left-2.5' : 'right-2.5'}`}>
                    {matches
                      ? <Check size={14} className="text-husn-success"/>
                      : <XClose size={14} className="text-husn-danger"/>}
                  </span>
                )}
              </div>
              {newUserConfirm && !matches && (
                <p className="mt-1 text-[10px] text-husn-danger tracking-normal">{T.passwordsDoNotMatch}</p>
              )}
            </div>
          </div>
        </div>

        {/* Rules */}
        <div className="mt-4 pt-3 border-t border-husn-border">
          <p className="text-[10px] uppercase tracking-[0.14em] text-husn-text-3 mb-2">{T.passwordRulesTitle}</p>
          <ul className="grid grid-cols-1 sm:grid-cols-3 gap-1.5 text-[11px]">
            {[
              { ok: newUser.password.length >= 8, label: T.pwRuleLen },
              { ok: /[a-z]/.test(newUser.password) && /[A-Z]/.test(newUser.password) && /[0-9]/.test(newUser.password), label: T.pwRuleMix },
              { ok: !['password', 'admin', '12345678', 'qwerty123', 'husn1234'].includes(newUser.password.toLowerCase()) && newUser.password.length > 0, label: T.pwRuleNoCommon },
            ].map((r, i) => (
              <li key={i} className="flex items-center gap-1.5">
                {r.ok
                  ? <Check size={11} className="text-husn-success"/>
                  : <span className="w-[11px] h-[11px] rounded-full border border-husn-border-2 inline-block"/>}
                <span className={r.ok ? 'text-husn-text-2' : 'text-husn-text-3'}>{r.label}</span>
              </li>
            ))}
          </ul>
        </div>

        {userError && (
          <div className="mt-3 text-[12px] text-husn-danger bg-husn-danger/10 border border-husn-danger/30 px-3 py-2 rounded-lg flex items-center gap-2">
            <AlertCircle size={12}/> {T[userError] || userError}
          </div>
        )}

        <div className="mt-4 flex justify-end">
          <button onClick={onCreate}
            disabled={!newUser.username || newUser.password.length < 8 || !matches}
            className="husn-btn-primary text-sm flex items-center gap-2">
            <UserPlus size={14}/> {T.addUser}
          </button>
        </div>
      </Card>

      {/* Existing users with search + cards */}
      <div className="mt-4">
        <Card title={`${T.users} (${userList.length})`} icon={<UsersIcon size={14}/>}>
          <div className="relative mb-3">
            <SearchIcon size={12} className={`absolute top-1/2 -translate-y-1/2 ${lang === 'ar' ? 'right-3' : 'left-3'} text-husn-text-3`}/>
            <input
              value={userSearch}
              onChange={(e) => setUserSearch(e.target.value)}
              placeholder={lang === 'en' ? 'Search users...' : 'بحث عن مستخدم...'}
              className={`husn-input w-full text-sm ${lang === 'ar' ? 'pr-9 pl-3' : 'pl-9 pr-3'}`}/>
          </div>

          {filtered.length === 0 ? (
            <p className="text-[12px] text-husn-text-3 italic py-4 text-center">
              {lang === 'en' ? 'No users match.' : 'لا يوجد مستخدمون مطابقون.'}
            </p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {filtered.map((u: any) => {
                const isSelf = u.username === authUser?.username;
                const isAdminUser = u.role === 'admin';
                return (
                  <div key={u.username}
                    className="flex items-center gap-3 px-3 py-2.5 rounded-lg border border-husn-border bg-black/20 hover:border-husn-border-2 transition">
                    <div className={`w-9 h-9 shrink-0 rounded-full flex items-center justify-center text-sm font-semibold
                      ${isAdminUser ? 'bg-white text-husn-bg' : 'bg-white/10 text-white'}`}>
                      {u.username.slice(0, 1).toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-white text-[13px] font-medium truncate font-mono tracking-normal">{u.username}</span>
                        {isSelf && (
                          <span className="text-[9px] uppercase tracking-[0.14em] text-husn-text-3 italic">
                            {lang === 'en' ? '· you' : '· أنت'}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        {isAdminUser
                          ? <KeyRound size={10} className="text-white"/>
                          : <UsersIcon size={10} className="text-husn-text-2"/>}
                        <span className={`text-[10px] uppercase tracking-[0.14em] ${isAdminUser ? 'text-white' : 'text-husn-text-2'}`}>
                          {isAdminUser ? T.admin : T.employee}
                        </span>
                        {u.created_at && (
                          <>
                            <span className="text-husn-border-2">·</span>
                            <span className="text-[10px] text-husn-text-3 tracking-normal">{u.created_at}</span>
                          </>
                        )}
                      </div>
                    </div>
                    {!isSelf && (
                      <button onClick={() => onAskDelete(u.username)}
                        title={T.deleteUser}
                        className="p-2 rounded-md text-husn-text-3 hover:text-husn-danger hover:bg-husn-danger/10 transition">
                        <Trash2 size={14}/>
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>
    </>
  );
};

// ---------- Login screen
// Defence-in-depth additions:
//   • Caps Lock detection (typing the right password with Caps on is the
//     most common cause of "right password / wrong" tickets).
//   • Show/hide password toggle so users actually verify what they typed
//     instead of mashing the same wrong password.
//   • Client-side soft lockout — after 5 failed attempts in a session we
//     lock the form for 30s. The backend has its own rate-limiting (see
//     `auth/ratelimit.py`); this is the UX layer on top.
//   • Connection security indicator — flags non-HTTPS prod URLs in red.
//   • Autofocus the username, autocomplete hints set so password
//     managers work but the browser never offers to save creds for new
//     accounts mid-form.
const LOCK_AFTER = 5;
const LOCK_SECS  = 30;

const Login = ({ lang, setLang, T, error, onSubmit }: any) => {
  const [u, setU] = useState('');
  const [p, setP] = useState('');
  const [busy, setBusy] = useState(false);
  const [showPwd, setShowPwd] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const [failures, setFailures] = useState<number>(() => {
    try { return Number(sessionStorage.getItem('husn.login-fail') || 0); } catch { return 0; }
  });
  const [lockedUntil, setLockedUntil] = useState<number>(() => {
    try { return Number(sessionStorage.getItem('husn.login-lock') || 0); } catch { return 0; }
  });
  const [tick, setTick] = useState(0);

  // Refresh once a second while locked so the countdown updates.
  useEffect(() => {
    if (lockedUntil > Date.now()) {
      const id = setInterval(() => setTick((t) => t + 1), 1000);
      return () => clearInterval(id);
    }
  }, [lockedUntil]);

  // When the parent reports an auth error, treat it as a failure.
  useEffect(() => {
    if (!error || error === 'sessionExpired') return;
    const next = failures + 1;
    setFailures(next);
    try { sessionStorage.setItem('husn.login-fail', String(next)); } catch {}
    if (next >= LOCK_AFTER) {
      const until = Date.now() + LOCK_SECS * 1000;
      setLockedUntil(until);
      try { sessionStorage.setItem('husn.login-lock', String(until)); } catch {}
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [error]);

  const isLocked = lockedUntil > Date.now();
  const lockRemaining = Math.max(0, Math.ceil((lockedUntil - Date.now()) / 1000));
  const remainingAttempts = Math.max(0, LOCK_AFTER - failures);

  const isHttps = typeof window !== 'undefined'
    ? (window.location.protocol === 'https:' || window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
    : true;

  const submit = async (e: any) => {
    e.preventDefault();
    if (!u || !p || isLocked) return;
    setBusy(true);
    await onSubmit(u, p);
    setBusy(false);
  };

  // Caps Lock handler — fires on every key event while the field has focus.
  const onPwdKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (typeof e.getModifierState === 'function') {
      setCapsLock(e.getModifierState('CapsLock'));
    }
  };

  // Reset failure tracker on a successful login (parent will unmount us).
  // No effect needed — when parent mounts the dashboard, this component is gone.

  return (
    <div className={`min-h-screen bg-husn-bg flex items-center justify-center p-6 ${lang === 'ar' ? 'rtl' : 'ltr'}`} dir={lang === 'ar' ? 'rtl' : 'ltr'}>
      <div className="w-full max-w-sm">
        {/* Top bar — language toggle + connection security indicator */}
        <div className="flex justify-between items-center mb-4">
          <div className={`flex items-center gap-1.5 text-[10px] uppercase tracking-[0.16em]
            ${isHttps ? 'text-husn-success' : 'text-husn-warn'}`}>
            <ShieldCheck size={12}/>
            <span>{isHttps ? T.secureConnection : T.insecureConnection}</span>
          </div>
          <button onClick={() => setLang(lang === 'en' ? 'ar' : 'en')}
            className="text-husn-text-3 hover:text-white text-[12px] flex items-center gap-1.5">
            <Globe size={12}/> {lang === 'en' ? 'العربية' : 'English'}
          </button>
        </div>

        <div className="husn-card p-8">
          <div className="flex flex-col items-center mb-7">
            <img
              src={lang === 'ar' ? logoAR : logoEN}
              alt="Husn"
              className="w-24 h-auto object-contain husn-logo-glow mb-3"
            />
            <div className="text-[10px] text-husn-text-3 uppercase tracking-[0.25em]">{T.tagline}</div>
          </div>
          <h1 className="text-[18px] font-light text-white uppercase tracking-[0.18em]">{T.signIn}</h1>
          <p className="text-husn-text-3 text-[11px] mt-1">{T.loginSubtitle}</p>

          <form onSubmit={submit} className="mt-6 space-y-3" autoComplete="off">
            {/* Username */}
            <div>
              <label className="text-[10px] uppercase tracking-[0.14em] text-husn-text-3">{T.username}</label>
              <input
                type="text" autoFocus value={u}
                onChange={(e) => setU(e.target.value)}
                disabled={isLocked}
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
                className="husn-input w-full mt-1.5 text-sm font-mono tracking-normal"
                autoComplete="username"
                aria-label="Username"
              />
            </div>

            {/* Password with show/hide toggle */}
            <div>
              <label className="text-[10px] uppercase tracking-[0.14em] text-husn-text-3">{T.password}</label>
              <div className="relative mt-1.5">
                <input
                  type={showPwd ? 'text' : 'password'}
                  value={p}
                  onChange={(e) => setP(e.target.value)}
                  onKeyUp={onPwdKey}
                  onKeyDown={onPwdKey}
                  disabled={isLocked}
                  className={`husn-input w-full text-sm font-mono tracking-normal ${lang === 'ar' ? 'pl-10 pr-3' : 'pr-10 pl-3'}`}
                  autoComplete="current-password"
                  aria-label="Password"
                />
                <button
                  type="button"
                  onClick={() => setShowPwd((s) => !s)}
                  title={showPwd ? T.hidePassword : T.showPassword}
                  aria-label={showPwd ? T.hidePassword : T.showPassword}
                  className={`absolute top-1/2 -translate-y-1/2 ${lang === 'ar' ? 'left-2.5' : 'right-2.5'} text-husn-text-3 hover:text-white transition`}
                >
                  {showPwd ? <EyeOff size={14}/> : <Eye size={14}/>}
                </button>
              </div>
              {capsLock && !isLocked && (
                <p className="mt-1.5 text-[11px] text-husn-warn flex items-center gap-1.5">
                  <AlertCircle size={11}/> {T.capsLockOn}
                </p>
              )}
            </div>

            {/* Lockout state */}
            {isLocked && (
              <div className="text-[12px] text-husn-danger bg-husn-danger/10 border border-husn-danger/30 px-3 py-2 rounded-lg flex items-center gap-2">
                <Lock size={12}/>
                <span>{T.lockedTemporarily} {lockRemaining}{tick >= 0 ? '' : ''} {T.seconds}.</span>
              </div>
            )}

            {/* Server-side error */}
            {error && !isLocked && (
              <div className="text-[12px] text-husn-danger bg-husn-danger/10 border border-husn-danger/30 px-3 py-2 rounded-lg">
                {T[error] || error}
                {failures > 0 && remainingAttempts > 0 && (
                  <span className="text-husn-text-3 block mt-0.5 text-[11px] tracking-normal">
                    {remainingAttempts} {T.attemptsRemaining}
                  </span>
                )}
              </div>
            )}

            <button type="submit"
              disabled={busy || !u || !p || isLocked}
              className="husn-btn-primary w-full mt-2 text-sm flex items-center justify-center gap-2 h-10">
              {busy ? <Activity size={14} className="animate-spin"/> :
                isLocked ? <Lock size={14}/> : <KeyRound size={14}/>}
              {isLocked ? `${lockRemaining}s` : T.signIn}
            </button>
          </form>
        </div>

        {/* Subtle footer */}
        <p className="text-center text-[10px] text-husn-text-3 mt-5 uppercase tracking-[0.18em]">
          {lang === 'en' ? 'Husn · حصن · Defense Grid' : 'حصن · Husn · شبكة الدفاع'}
        </p>
      </div>
    </div>
  );
};

export default App;
