// Auto Patch Center
// =================
// Reads /autopatch/scan, lists issues with severity pills + diff view,
// admin actions (Apply / Manual / Reject / LLM Suggest), and a rolling
// audit history. Polls the scan API every 30s and on demand.

import { useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Wrench, AlertCircle, RefreshCw, Activity, Check, X as XClose,
  Sparkles, Edit3, Clock, ChevronRight, Archive, Trash2, Download,
} from 'lucide-react';

type Issue = {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  confidence: number;
  file: string;
  line_number: number;
  line_content: string;
  suggested_fix: string | null;
  rationale: string;
  description: string;
  detected_at: number;
  detected_at_iso: string;
  can_auto_fix: boolean;
};

type ScanResp = {
  scanned_at_iso: string;
  files_scanned: number | null;
  issues_total: number;
  by_severity: Record<string, number>;
  rules_loaded: number;
  took_seconds: number | null;
  issues: Issue[];
};

type HistoryItem = {
  ts: number;
  ts_iso: string;
  action: string;
  actor: string;
  issue_id: string;
  rule_id: string;
  file: string;
  line_number: number;
  outcome: string;
  reason?: string;
  detail?: string;
};

const SEV_COLOR: Record<string, string> = {
  Critical: '#f43f5e',
  High:     '#f97316',
  Medium:   '#f59e0b',
  Low:      '#a1a1aa',
};

const ACTION_COLOR: Record<string, string> = {
  apply:         '#10b981',
  manual:        '#a1a1aa',
  reject:        '#71717a',
  'llm-suggest': '#a1a1aa',
};

interface Props {
  api: any;        // axios instance
  isAdmin: boolean;
  T: any;
  lang: 'en' | 'ar';
  addLog?: (s: string) => void;
}

export default function AutoPatch({ api, isAdmin, T: _T, lang, addLog }: Props) {
  void _T;  // T accepted for API symmetry but every string is bilingual via `lang`
  const [resp, setResp] = useState<ScanResp | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [scanning, setScanning] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>('all'); // all | Critical | High | Medium | Low | auto-fixable
  const [showHistory, setShowHistory] = useState(false);

  // Per-issue scratch state for manual edits + LLM suggestions
  const [manualText, setManualText] = useState<Record<string, string>>({});
  const [llmSuggestion, setLlmSuggestion] = useState<Record<string, string>>({});
  const [llmModel, setLlmModel] = useState<Record<string, string>>({});
  const [actionMsg, setActionMsg] = useState<Record<string, string>>({});

  // Bulk-fix-with-AI state
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkProgress, setBulkProgress] = useState<{ done: number; total: number; current: string } | null>(null);
  const [bulkResults, setBulkResults] = useState<{ id: string; file: string; line: number; status: 'ok' | 'failed' | 'no-suggestion'; message: string }[] | null>(null);
  const [showBulkConfirm, setShowBulkConfirm] = useState(false);

  // Project-level backups
  const [backups, setBackups] = useState<{ filename: string; size_bytes: number; created_at_iso: string }[]>([]);
  const [backupBusy, setBackupBusy] = useState(false);
  const [backupMsg, setBackupMsg] = useState<string>('');
  const [showBackups, setShowBackups] = useState(false);

  const fetchBackups = async () => {
    try { setBackups((await api.get('/autopatch/backups')).data.backups || []); } catch {}
  };

  useEffect(() => { fetchBackups(); /* eslint-disable-next-line */ }, []);

  const fmtSize = (b: number) => {
    if (b < 1024) return `${b} B`;
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
    if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`;
    return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`;
  };

  const createBackup = async () => {
    setBackupBusy(true);
    setBackupMsg('');
    try {
      const r = await api.post('/autopatch/backup');
      if (r.data?.ok) {
        setBackupMsg(lang === 'en'
          ? `✓ ${r.data.filename} · ${fmtSize(r.data.size_bytes)} · ${r.data.files} files · ${r.data.took_seconds}s`
          : `✓ ${r.data.filename} · ${fmtSize(r.data.size_bytes)} · ${r.data.files} ملف`);
        addLog?.(`AUTOPATCH: backup created ${r.data.filename}`);
        await fetchBackups();
        setShowBackups(true);
      } else {
        setBackupMsg(`✗ ${r.data?.error || 'failed'}`);
      }
    } catch (e: any) {
      setBackupMsg(`✗ ${e?.message}`);
    }
    setBackupBusy(false);
  };

  const deleteBackup = async (filename: string) => {
    if (!confirm(lang === 'en' ? `Delete backup ${filename}?` : `حذف النسخة ${filename}؟`)) return;
    try {
      const r = await api.delete(`/autopatch/backups/${encodeURIComponent(filename)}`);
      if (r.data?.ok) {
        addLog?.(`AUTOPATCH: deleted backup ${filename}`);
        await fetchBackups();
      }
    } catch {}
  };

  const downloadBackup = (filename: string) => {
    // Open in new tab so the auth header rides along via existing session.
    // Note: FileResponse on the backend handles streaming.
    const base = (api?.defaults?.baseURL || '');
    const token = (api?.defaults?.headers?.common?.Authorization || '').toString().replace('Bearer ', '');
    const url = `${base}/autopatch/backups/${encodeURIComponent(filename)}/download${token ? `?token=${encodeURIComponent(token)}` : ''}`;
    // Most reliable: use a hidden anchor with the Authorization header is impossible
    // for downloads, so we fall back to fetching the blob ourselves and saving it.
    api.get(`/autopatch/backups/${encodeURIComponent(filename)}/download`, { responseType: 'blob' })
      .then((r: any) => {
        const blob = new Blob([r.data], { type: 'application/gzip' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
      })
      .catch(() => {
        // Last-resort fallback — opens raw URL (will 401 if no cookie auth)
        window.open(url, '_blank');
      });
  };

  const toggleSelect = (id: string, e?: React.MouseEvent) => {
    e?.stopPropagation();
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id); else n.add(id);
      return n;
    });
  };
  const selectAllVisible = () => setSelected(new Set(filtered.map((i) => i.id)));
  const selectAutoFixable = () => setSelected(new Set(filtered.filter((i) => i.can_auto_fix).map((i) => i.id)));
  const clearSelection = () => setSelected(new Set());

  const bulkFixWithAI = async () => {
    setShowBulkConfirm(false);
    setBulkBusy(true);
    setBulkResults(null);
    const ids = Array.from(selected);
    const results: NonNullable<typeof bulkResults> = [];
    setBulkProgress({ done: 0, total: ids.length, current: '' });

    for (let idx = 0; idx < ids.length; idx++) {
      const id = ids[idx];
      const issue = (resp?.issues || []).find((i) => i.id === id);
      const fileLabel = issue ? `${issue.file}:${issue.line_number}` : id;
      setBulkProgress({ done: idx, total: ids.length, current: fileLabel });
      const baseRow = { id, file: issue?.file || '', line: issue?.line_number || 0 };

      try {
        // 1. Ask LLM
        const llm = await api.post('/autopatch/llm-suggest', { issue_id: id });
        if (!llm.data?.ok || !llm.data?.suggestion) {
          results.push({ ...baseRow, status: 'no-suggestion', message: llm.data?.error || 'LLM gave no suggestion' });
          continue;
        }
        // 2. Apply via manual endpoint (reason captures the bulk origin)
        const ap = await api.post('/autopatch/manual', {
          issue_id: id,
          new_line: llm.data.suggestion,
          reason: `bulk AI fix (${llm.data.model || 'llm'})`,
        });
        if (ap.data?.ok) {
          results.push({ ...baseRow, status: 'ok', message: `applied · backup ${ap.data.backup}` });
        } else {
          results.push({ ...baseRow, status: 'failed', message: ap.data?.error || 'apply failed' });
        }
      } catch (e: any) {
        results.push({ ...baseRow, status: 'failed', message: e?.message || 'request error' });
      }
    }

    setBulkProgress({ done: ids.length, total: ids.length, current: '' });
    setBulkResults(results);
    setBulkBusy(false);
    clearSelection();
    addLog?.(`AUTOPATCH: bulk fix — ${results.filter((r) => r.status === 'ok').length}/${results.length} applied`);
    await fetchScan(true);
    await fetchHistory();
    // Keep progress on screen for a moment so the user sees 100%
    setTimeout(() => setBulkProgress(null), 800);
  };

  const fetchScan = async (force = false) => {
    setScanning(true);
    try {
      const r = await api.get(`/autopatch/scan${force ? '?force=true' : ''}`);
      setResp(r.data);
    } catch (e: any) {
      addLog?.(`[ERR] autopatch scan: ${e?.message}`);
    }
    setScanning(false);
  };

  const fetchHistory = async () => {
    try { setHistory((await api.get('/autopatch/history?limit=80')).data.items); } catch {}
  };

  useEffect(() => {
    fetchScan(false);
    fetchHistory();
    const id = setInterval(() => { fetchScan(false); fetchHistory(); }, 30000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const issues = resp?.issues || [];
  const filtered = useMemo(() => {
    if (filter === 'all') return issues;
    if (filter === 'auto-fixable') return issues.filter((i) => i.can_auto_fix);
    return issues.filter((i) => i.severity === filter);
  }, [issues, filter]);

  const apply = async (id: string) => {
    setBusyId(id);
    try {
      const r = await api.post('/autopatch/apply', { issue_id: id });
      setActionMsg((m) => ({ ...m, [id]: r.data?.ok
        ? (lang === 'en' ? `✓ Applied · backup: ${r.data.backup}` : `✓ تم التطبيق · نسخة: ${r.data.backup}`)
        : `✗ ${r.data?.error || 'failed'}` }));
      if (r.data?.ok) addLog?.(`AUTOPATCH: applied ${id}`);
      await fetchScan(true); await fetchHistory();
    } catch (e: any) {
      setActionMsg((m) => ({ ...m, [id]: `✗ ${e?.message}` }));
    }
    setBusyId(null);
  };

  const reject = async (id: string) => {
    const reason = prompt(lang === 'en' ? 'Reason for rejecting (logged)?' : 'سبب الرفض (سيُسجَّل):') || '';
    if (reason === null) return;
    setBusyId(id);
    try {
      const r = await api.post('/autopatch/reject', { issue_id: id, reason });
      setActionMsg((m) => ({ ...m, [id]: r.data?.ok ? (lang === 'en' ? '✓ Rejected (logged)' : '✓ تم الرفض (مسجَّل)') : `✗ ${r.data?.error}` }));
      addLog?.(`AUTOPATCH: rejected ${id}`);
      await fetchHistory();
    } catch (e: any) {
      setActionMsg((m) => ({ ...m, [id]: `✗ ${e?.message}` }));
    }
    setBusyId(null);
  };

  const saveManual = async (id: string) => {
    const newLine = manualText[id];
    if (!newLine?.trim()) return;
    setBusyId(id);
    try {
      const r = await api.post('/autopatch/manual', { issue_id: id, new_line: newLine, reason: 'manual edit' });
      setActionMsg((m) => ({ ...m, [id]: r.data?.ok
        ? (lang === 'en' ? `✓ Saved · backup: ${r.data.backup}` : `✓ تم الحفظ · نسخة: ${r.data.backup}`)
        : `✗ ${r.data?.error || 'failed'}` }));
      if (r.data?.ok) addLog?.(`AUTOPATCH: manual ${id}`);
      await fetchScan(true); await fetchHistory();
    } catch (e: any) {
      setActionMsg((m) => ({ ...m, [id]: `✗ ${e?.message}` }));
    }
    setBusyId(null);
  };

  const askLLM = async (id: string) => {
    setBusyId(id);
    try {
      const r = await api.post('/autopatch/llm-suggest', { issue_id: id });
      if (r.data?.ok && r.data.suggestion) {
        setLlmSuggestion((m) => ({ ...m, [id]: r.data.suggestion }));
        setManualText((m) => ({ ...m, [id]: m[id] || r.data.suggestion }));
        setLlmModel((m) => ({ ...m, [id]: r.data.model || 'llm' }));
        setActionMsg((m) => ({ ...m, [id]: '' }));  // panel itself is the feedback
      } else {
        setActionMsg((m) => ({ ...m, [id]: `✗ ${r.data?.error || 'llm failed'}` }));
      }
      await fetchHistory();
    } catch (e: any) {
      setActionMsg((m) => ({ ...m, [id]: `✗ ${e?.message}` }));
    }
    setBusyId(null);
  };

  // Apply the LLM's suggestion as-is via the manual endpoint (which is
  // the only path the engine has for non-template fixes).
  const applyLLM = async (id: string) => {
    const text = llmSuggestion[id];
    if (!text) return;
    setBusyId(id);
    try {
      const r = await api.post('/autopatch/manual', {
        issue_id: id,
        new_line: text,
        reason: `LLM suggestion (${llmModel[id] || 'llm'})`,
      });
      setActionMsg((m) => ({ ...m, [id]: r.data?.ok
        ? (lang === 'en' ? `✓ Applied LLM patch · backup: ${r.data.backup}` : `✓ تم تطبيق اقتراح LLM · نسخة: ${r.data.backup}`)
        : `✗ ${r.data?.error || 'failed'}` }));
      if (r.data?.ok) {
        addLog?.(`AUTOPATCH: applied LLM patch ${id}`);
        // Clear the suggestion so the panel collapses
        setLlmSuggestion((m) => { const n = { ...m }; delete n[id]; return n; });
      }
      await fetchScan(true); await fetchHistory();
    } catch (e: any) {
      setActionMsg((m) => ({ ...m, [id]: `✗ ${e?.message}` }));
    }
    setBusyId(null);
  };

  const dismissLLM = (id: string) => {
    setLlmSuggestion((m) => { const n = { ...m }; delete n[id]; return n; });
    setActionMsg((m) => ({ ...m, [id]: '' }));
  };

  return (
    <div className="space-y-4">
      {/* ========== Top KPIs ========== */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <KpiTile
          label={lang === 'en' ? 'Issues found' : 'مشاكل مكتشفة'}
          value={String(resp?.issues_total ?? '—')}
          icon={<AlertCircle size={14}/>}
          highlight={(resp?.issues_total ?? 0) > 0}
        />
        {(['Critical', 'High', 'Medium', 'Low'] as const).map((s) => (
          <KpiTile key={s}
            label={s}
            value={String(resp?.by_severity?.[s] ?? 0)}
            icon={<Wrench size={14}/>}
            color={SEV_COLOR[s]}
            highlight={(resp?.by_severity?.[s] ?? 0) > 0 && (s === 'Critical' || s === 'High')}
          />
        ))}
      </div>

      {/* ========== Toolbar ========== */}
      <div className="husn-card p-4 flex flex-wrap items-center gap-3">
        <div className="flex-1 min-w-0">
          <div className="text-[12px] text-husn-text-2 flex items-center gap-2">
            <Activity size={12} className="text-husn-success animate-pulse"/>
            {resp ? (
              lang === 'en'
                ? <span>Last scan: <span className="text-white">{resp.scanned_at_iso}</span> · {resp.files_scanned ?? '—'} files · {resp.rules_loaded} rules · {resp.took_seconds ?? '—'}s</span>
                : <span>آخر فحص: <span className="text-white">{resp.scanned_at_iso}</span> · {resp.files_scanned ?? '—'} ملف · {resp.rules_loaded} قاعدة</span>
            ) : <span>{lang === 'en' ? 'Loading scan…' : 'جارٍ تحميل الفحص...'}</span>}
          </div>
        </div>
        {/* Severity filter */}
        <div className="flex items-center gap-1 text-[10px] uppercase tracking-[0.12em]">
          {(['all', 'Critical', 'High', 'Medium', 'Low', 'auto-fixable'] as const).map((f) => (
            <button key={f}
              onClick={() => setFilter(f)}
              className={`px-2.5 py-1 rounded border transition ${filter === f
                ? 'border-white/40 bg-white/[0.06] text-white'
                : 'border-husn-border text-husn-text-3 hover:text-white hover:border-husn-border-2'}`}>
              {f === 'auto-fixable' ? (lang === 'en' ? 'Auto-fixable' : 'قابل للإصلاح') : f}
            </button>
          ))}
        </div>
        {/* Create Backup — admin-only safety button */}
        {isAdmin && (
          <button onClick={createBackup} disabled={backupBusy || bulkBusy}
            title={lang === 'en' ? 'Snapshot the source tree to a tar.gz' : 'لقطة لشجرة المصدر إلى أرشيف'}
            className="text-sm flex items-center gap-2 px-3 py-2 rounded-lg uppercase tracking-[0.10em] font-medium border border-husn-border-2 text-white bg-white/[0.04] hover:bg-white/[0.08] transition disabled:opacity-50">
            {backupBusy ? <Activity size={14} className="animate-spin"/> : <Archive size={14}/>}
            {lang === 'en' ? 'Backup' : 'نسخ احتياطي'}
            {backups.length > 0 && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-black/30 tracking-normal">{backups.length}</span>
            )}
          </button>
        )}
        <button onClick={() => fetchScan(true)} disabled={scanning || bulkBusy}
          className="husn-btn-primary text-sm flex items-center gap-2">
          {scanning ? <Activity size={14} className="animate-spin"/> : <RefreshCw size={14}/>}
          {lang === 'en' ? 'Re-scan' : 'إعادة الفحص'}
        </button>
        {/* Bulk Fix With AI — primary action when any issues are selected */}
        {isAdmin && (
          <button
            onClick={() => setShowBulkConfirm(true)}
            disabled={selected.size === 0 || bulkBusy}
            className={`text-sm flex items-center gap-2 px-3 py-2 rounded-lg uppercase tracking-[0.10em] font-medium transition
              ${selected.size > 0 && !bulkBusy
                ? 'bg-husn-success text-black hover:brightness-110 shadow-[0_0_14px_rgba(16,185,129,0.30)]'
                : 'bg-white/[0.04] text-husn-text-3 border border-husn-border cursor-not-allowed'}`}
          >
            {bulkBusy ? <Activity size={14} className="animate-spin"/> : <Sparkles size={14}/>}
            {lang === 'en' ? 'Fix with AI' : 'إصلاح بالذكاء'}
            {selected.size > 0 && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-black/20 tracking-normal">{selected.size}</span>
            )}
          </button>
        )}
      </div>

      {/* Selection bar — appears when at least one issue is selected */}
      {isAdmin && selected.size > 0 && !bulkBusy && (
        <div className="husn-card px-4 py-2 flex items-center gap-3 text-[11px]">
          <span className="text-white">
            <strong>{selected.size}</strong> {lang === 'en' ? 'selected' : 'محدّد'}
          </span>
          <span className="text-husn-text-3">·</span>
          <button onClick={selectAllVisible} className="text-husn-text-2 hover:text-white uppercase tracking-[0.12em]">
            {lang === 'en' ? 'Select all visible' : 'تحديد المرئي'}
          </button>
          <button onClick={selectAutoFixable} className="text-husn-text-2 hover:text-white uppercase tracking-[0.12em]">
            {lang === 'en' ? 'Only auto-fixable' : 'القابل للإصلاح فقط'}
          </button>
          <button onClick={clearSelection} className="text-husn-text-3 hover:text-husn-danger uppercase tracking-[0.12em] ml-auto">
            {lang === 'en' ? 'Clear' : 'مسح'}
          </button>
        </div>
      )}

      {/* Bulk progress overlay */}
      {bulkProgress && (
        <div className="husn-card p-4 space-y-2">
          <div className="flex items-center justify-between text-[12px]">
            <span className="flex items-center gap-2 text-white">
              <Sparkles size={13} className="text-husn-success animate-pulse"/>
              {lang === 'en' ? 'AI is fixing issues...' : 'الذكاء يصلح المشاكل...'}
            </span>
            <span className="text-husn-text-3 tracking-normal">{bulkProgress.done}/{bulkProgress.total}</span>
          </div>
          <div className="h-1.5 bg-husn-border rounded-full overflow-hidden">
            <div className="h-full bg-husn-success transition-all"
              style={{ width: `${(bulkProgress.done / Math.max(1, bulkProgress.total)) * 100}%` }}/>
          </div>
          {bulkProgress.current && (
            <p className="text-[10px] text-husn-text-3 font-mono tracking-normal truncate">
              ↳ {bulkProgress.current}
            </p>
          )}
        </div>
      )}

      {/* ========== Backup status / panel ========== */}
      {isAdmin && (backupMsg || backups.length > 0) && (
        <div className="husn-card overflow-hidden">
          <button
            onClick={() => setShowBackups((s) => !s)}
            className="w-full px-4 py-2.5 flex items-center justify-between text-left hover:bg-white/[0.02] transition"
          >
            <span className="flex items-center gap-2">
              <Archive size={13} className="text-husn-text-2"/>
              <span className="text-[12px] uppercase tracking-[0.16em] text-white">
                {lang === 'en' ? 'Backups' : 'النسخ الاحتياطية'}
              </span>
              <span className="text-[10px] text-husn-text-3 tracking-normal">({backups.length})</span>
              {backupMsg && (
                <span className={`text-[11px] tracking-normal ml-2 font-mono
                  ${backupMsg.startsWith('✓') ? 'text-husn-success' : 'text-husn-danger'}`}>
                  {backupMsg}
                </span>
              )}
            </span>
            <ChevronRight size={12} className={`text-husn-text-3 transition-transform ${showBackups ? 'rotate-90' : ''}`}/>
          </button>
          <AnimatePresence>
            {showBackups && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.18 }}
                className="overflow-hidden"
              >
                {backups.length === 0 ? (
                  <p className="px-4 py-4 text-[12px] text-husn-text-3 italic">
                    {lang === 'en' ? 'No backups yet — click Backup to create one.' : 'لا توجد نسخ بعد — اضغط نسخ احتياطي للإنشاء.'}
                  </p>
                ) : (
                  <div className="max-h-72 overflow-y-auto divide-y divide-husn-border">
                    {backups.map((b) => (
                      <div key={b.filename} className="px-4 py-2 flex items-center gap-3 text-[11px]">
                        <Archive size={11} className="text-husn-text-3 shrink-0"/>
                        <span className="font-mono tracking-normal text-white truncate flex-1">{b.filename}</span>
                        <span className="text-husn-text-3 tracking-normal w-20 text-right shrink-0">{fmtSize(b.size_bytes)}</span>
                        <span className="text-husn-text-3 tracking-normal w-44 text-right shrink-0 hidden sm:block">{b.created_at_iso}</span>
                        <button onClick={() => downloadBackup(b.filename)}
                          title={lang === 'en' ? 'Download' : 'تنزيل'}
                          className="p-1.5 rounded text-husn-text-3 hover:text-white hover:bg-white/[0.05] transition">
                          <Download size={12}/>
                        </button>
                        <button onClick={() => deleteBackup(b.filename)}
                          title={lang === 'en' ? 'Delete' : 'حذف'}
                          className="p-1.5 rounded text-husn-text-3 hover:text-husn-danger hover:bg-husn-danger/10 transition">
                          <Trash2 size={12}/>
                        </button>
                      </div>
                    ))}
                  </div>
                )}
                <div className="px-4 py-2 border-t border-husn-border bg-black/30 text-[10px] text-husn-text-3 italic flex items-start gap-2">
                  <AlertCircle size={10} className="shrink-0 mt-0.5"/>
                  <span>{lang === 'en'
                    ? 'Stored at /etc/husn/backups/. Restore manually with `tar -xzf <file>` from the project root.'
                    : 'مخزّنة في /etc/husn/backups/. استعد يدوياً بـ tar -xzf من جذر المشروع.'}</span>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}

      {/* ========== Issue list ========== */}
      <div className="husn-card overflow-hidden">
        {filtered.length === 0 ? (
          <div className="p-12 flex flex-col items-center justify-center text-center text-husn-text-3 text-[12px] gap-2">
            <Check size={28} className="text-husn-success opacity-60"/>
            <p>{lang === 'en' ? 'No issues found in this filter. Run a re-scan if you just changed code.' : 'لا توجد مشاكل في هذا التصفية.'}</p>
          </div>
        ) : (
          <div className="divide-y divide-husn-border">
            {filtered.map((issue) => {
              const open = expanded === issue.id;
              const sev = SEV_COLOR[issue.severity] || '#a1a1aa';
              return (
                <div key={issue.id}>
                  <button
                    onClick={() => setExpanded(open ? null : issue.id)}
                    className="w-full px-4 py-3 flex items-center gap-3 text-left hover:bg-white/[0.02] transition"
                  >
                    {/* Selection checkbox — admin-only, doesn't toggle the row when clicked */}
                    {isAdmin && (
                      <span
                        onClick={(e) => toggleSelect(issue.id, e)}
                        role="checkbox"
                        aria-checked={selected.has(issue.id)}
                        className={`shrink-0 w-4 h-4 rounded border flex items-center justify-center cursor-pointer transition
                          ${selected.has(issue.id)
                            ? 'bg-husn-success border-husn-success'
                            : 'border-husn-border-2 hover:border-white'}`}
                      >
                        {selected.has(issue.id) && <Check size={10} className="text-black"/>}
                      </span>
                    )}
                    <ChevronRight size={12} className={`text-husn-text-3 shrink-0 transition-transform ${open ? 'rotate-90' : ''}`}/>
                    <span
                      className="text-[10px] font-semibold uppercase tracking-[0.14em] px-2 py-0.5 rounded shrink-0 w-[70px] text-center"
                      style={{ color: sev, background: `${sev}1a`, border: `1px solid ${sev}55` }}>
                      {issue.severity}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="text-[13px] text-white truncate">{issue.rule_name}</div>
                      <div className="text-[11px] text-husn-text-3 truncate font-mono tracking-normal">
                        {issue.file}:{issue.line_number}
                      </div>
                    </div>
                    <span className="text-[10px] text-husn-text-3 tracking-normal w-12 text-right shrink-0">
                      {(issue.confidence * 100).toFixed(0)}%
                    </span>
                    {issue.can_auto_fix && (
                      <span className="text-[9px] uppercase tracking-[0.14em] px-2 py-0.5 rounded border border-husn-success/40 text-husn-success bg-husn-success/10 shrink-0">
                        {lang === 'en' ? 'auto-fix' : 'تلقائي'}
                      </span>
                    )}
                  </button>

                  <AnimatePresence>
                    {open && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        transition={{ duration: 0.18 }}
                        className="overflow-hidden"
                      >
                        <div className="px-4 pb-4 pt-1 ml-[18px] space-y-3">
                          {/* Description + rationale */}
                          <div className="text-[12px] text-husn-text-2 leading-relaxed">
                            {issue.description}
                          </div>
                          <div className="text-[11px] text-husn-text-3 italic">
                            {lang === 'en' ? 'Why the suggested fix is safer:' : 'لماذا الإصلاح المقترح أكثر أماناً:'} {issue.rationale}
                          </div>

                          {/* Diff */}
                          <div className="rounded-lg border border-husn-border overflow-hidden">
                            <div className="px-3 py-1.5 bg-black/40 text-[9px] uppercase tracking-[0.16em] text-husn-text-3 border-b border-husn-border flex justify-between">
                              <span>{lang === 'en' ? `Line ${issue.line_number}` : `سطر ${issue.line_number}`}</span>
                              <span className="font-mono tracking-normal">{issue.file}</span>
                            </div>
                            <div className="bg-husn-danger/[0.06] border-l-2 border-husn-danger px-3 py-2 font-mono text-[12px] text-white whitespace-pre-wrap break-all">
                              <span className="text-husn-danger select-none">- </span>{issue.line_content}
                            </div>
                            {issue.suggested_fix ? (
                              <div className="bg-husn-success/[0.06] border-l-2 border-husn-success px-3 py-2 font-mono text-[12px] text-white whitespace-pre-wrap break-all">
                                <span className="text-husn-success select-none">+ </span>{issue.suggested_fix}
                              </div>
                            ) : (
                              <div className="px-3 py-2 text-[11px] text-husn-text-3 italic bg-black/30">
                                {lang === 'en'
                                  ? 'No safe one-line template fix. Use Manual Edit or LLM Suggest.'
                                  : 'لا يوجد إصلاح تلقائي بسطر واحد. استخدم تحرير يدوي أو اقتراح LLM.'}
                              </div>
                            )}
                          </div>

                          {/* LLM advisory panel — appears once LLM Suggest returns.
                              Three clear decision buttons: Apply / Customize / Dismiss. */}
                          {isAdmin && llmSuggestion[issue.id] && (
                            <div className="rounded-lg border border-white/30 bg-white/[0.04] p-3 space-y-3">
                              <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                  <Sparkles size={13} className="text-white"/>
                                  <span className="text-[11px] uppercase tracking-[0.14em] text-white font-semibold">
                                    {lang === 'en' ? 'LLM suggestion' : 'اقتراح الذكاء'}
                                  </span>
                                  {llmModel[issue.id] && (
                                    <span className="text-[9px] tracking-normal text-husn-text-3 font-mono">
                                      · {llmModel[issue.id]}
                                    </span>
                                  )}
                                </div>
                                <button onClick={() => dismissLLM(issue.id)}
                                  className="text-husn-text-3 hover:text-white p-1"
                                  title={lang === 'en' ? 'Dismiss' : 'تجاهل'}>
                                  <XClose size={12}/>
                                </button>
                              </div>

                              {/* Suggested-line diff */}
                              <div className="rounded-md border border-husn-border overflow-hidden">
                                <div className="bg-husn-danger/[0.06] border-l-2 border-husn-danger px-3 py-2 font-mono text-[12px] text-white whitespace-pre-wrap break-all">
                                  <span className="text-husn-danger select-none">- </span>{issue.line_content}
                                </div>
                                <div className="bg-husn-success/[0.06] border-l-2 border-husn-success px-3 py-2 font-mono text-[12px] text-white whitespace-pre-wrap break-all">
                                  <span className="text-husn-success select-none">+ </span>{llmSuggestion[issue.id]}
                                </div>
                              </div>

                              <p className="text-[10px] text-husn-text-3 italic">
                                {lang === 'en'
                                  ? 'You decide — apply as-is, edit it first, or dismiss this suggestion.'
                                  : 'القرار لك — طبّق كما هو، عدّل أولاً، أو تجاهل الاقتراح.'}
                              </p>

                              {/* Three big decision buttons */}
                              <div className="flex flex-wrap gap-2">
                                <button onClick={() => applyLLM(issue.id)} disabled={busyId === issue.id}
                                  className="text-[11px] uppercase tracking-[0.14em] px-3 py-2 rounded-md bg-husn-success text-black font-semibold hover:brightness-110 transition flex items-center gap-1.5 shadow-[0_0_12px_rgba(16,185,129,0.30)]">
                                  {busyId === issue.id ? <Activity size={11} className="animate-spin"/> : <Check size={11}/>}
                                  {lang === 'en' ? 'Apply LLM patch' : 'تطبيق الاقتراح'}
                                </button>
                                <button onClick={() => {
                                  setManualText((m) => ({ ...m, [issue.id]: llmSuggestion[issue.id] }));
                                  // Scroll the manual edit drawer open by toggling the details element
                                  const det = document.querySelector(`details[data-issue="${issue.id}"]`) as HTMLDetailsElement | null;
                                  if (det) det.open = true;
                                }}
                                  className="text-[11px] uppercase tracking-[0.14em] px-3 py-2 rounded-md bg-white/[0.04] text-white border border-husn-border-2 hover:bg-white/[0.08] transition flex items-center gap-1.5">
                                  <Edit3 size={11}/>
                                  {lang === 'en' ? 'Edit before apply' : 'عدّل قبل التطبيق'}
                                </button>
                                <button onClick={() => dismissLLM(issue.id)}
                                  className="text-[11px] uppercase tracking-[0.14em] px-3 py-2 rounded-md bg-husn-text-3/10 text-husn-text-3 border border-husn-border hover:text-white hover:border-husn-border-2 transition flex items-center gap-1.5">
                                  <XClose size={11}/>
                                  {lang === 'en' ? 'Dismiss' : 'تجاهل'}
                                </button>
                              </div>
                            </div>
                          )}

                          {/* Actions */}
                          {isAdmin ? (
                            <div className="flex flex-wrap gap-2">
                              {issue.can_auto_fix && (
                                <button onClick={() => apply(issue.id)} disabled={busyId === issue.id}
                                  className="text-[11px] uppercase tracking-[0.14em] px-3 py-1.5 rounded-md bg-husn-success/15 text-husn-success border border-husn-success/40 hover:bg-husn-success/25 transition flex items-center gap-1.5">
                                  {busyId === issue.id ? <Activity size={11} className="animate-spin"/> : <Check size={11}/>}
                                  {lang === 'en' ? 'Apply Auto Fix' : 'تطبيق تلقائي'}
                                </button>
                              )}
                              <button onClick={() => askLLM(issue.id)} disabled={busyId === issue.id}
                                className="text-[11px] uppercase tracking-[0.14em] px-3 py-1.5 rounded-md bg-white/[0.04] text-white border border-husn-border-2 hover:bg-white/[0.08] transition flex items-center gap-1.5">
                                {busyId === issue.id ? <Activity size={11} className="animate-spin"/> : <Sparkles size={11}/>}
                                {lang === 'en' ? 'Ask LLM' : 'اسأل الذكاء'}
                              </button>
                              <button onClick={() => reject(issue.id)} disabled={busyId === issue.id}
                                className="text-[11px] uppercase tracking-[0.14em] px-3 py-1.5 rounded-md bg-husn-danger/10 text-husn-danger border border-husn-danger/30 hover:bg-husn-danger/20 transition flex items-center gap-1.5">
                                <XClose size={11}/>
                                {lang === 'en' ? 'Reject' : 'رفض'}
                              </button>
                            </div>
                          ) : (
                            <p className="text-[11px] text-husn-text-3 italic">
                              {lang === 'en' ? 'Admin only — sign in as admin to apply or reject patches.' : 'للمسؤول فقط.'}
                            </p>
                          )}

                          {/* Manual edit drawer (always available for admin) */}
                          {isAdmin && (
                            <details data-issue={issue.id} className="rounded-lg border border-husn-border bg-black/20">
                              <summary className="cursor-pointer px-3 py-2 text-[10px] uppercase tracking-[0.14em] text-husn-text-3 flex items-center gap-1.5 hover:text-white">
                                <Edit3 size={11}/>
                                {lang === 'en' ? 'Manual edit' : 'تحرير يدوي'}
                              </summary>
                              <div className="p-3 space-y-2">
                                {llmSuggestion[issue.id] && (
                                  <p className="text-[10px] text-husn-text-3 italic">
                                    {lang === 'en' ? 'Pre-filled from LLM suggestion:' : 'مملوء مسبقاً من اقتراح LLM:'}
                                  </p>
                                )}
                                <textarea
                                  value={manualText[issue.id] ?? issue.suggested_fix ?? issue.line_content}
                                  onChange={(e) => setManualText((m) => ({ ...m, [issue.id]: e.target.value }))}
                                  rows={3}
                                  spellCheck={false}
                                  className="w-full bg-black/40 border border-husn-border rounded px-3 py-2 text-[12px] text-white font-mono tracking-normal"
                                />
                                <button onClick={() => saveManual(issue.id)} disabled={busyId === issue.id}
                                  className="text-[11px] uppercase tracking-[0.14em] px-3 py-1.5 rounded-md bg-white text-black hover:opacity-90 transition flex items-center gap-1.5">
                                  {busyId === issue.id ? <Activity size={11} className="animate-spin"/> : <Edit3 size={11}/>}
                                  {lang === 'en' ? 'Save manual edit' : 'حفظ التحرير'}
                                </button>
                              </div>
                            </details>
                          )}

                          {actionMsg[issue.id] && (
                            <div className={`text-[11px] px-3 py-1.5 rounded-md font-mono tracking-normal
                              ${actionMsg[issue.id].startsWith('✓')
                                ? 'text-husn-success bg-husn-success/10 border border-husn-success/30'
                                : 'text-husn-danger bg-husn-danger/10 border border-husn-danger/30'}`}>
                              {actionMsg[issue.id]}
                            </div>
                          )}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ========== History ========== */}
      <div className="husn-card overflow-hidden">
        <button
          onClick={() => setShowHistory((s) => !s)}
          className="w-full px-4 py-3 flex items-center justify-between text-left hover:bg-white/[0.02] transition"
        >
          <span className="flex items-center gap-2">
            <Clock size={13} className="text-husn-text-3"/>
            <span className="text-[12px] uppercase tracking-[0.16em] text-white">
              {lang === 'en' ? 'Patch history' : 'سجل التصحيحات'}
            </span>
            <span className="text-[10px] text-husn-text-3 tracking-normal">({history.length})</span>
          </span>
          <ChevronRight size={12} className={`text-husn-text-3 transition-transform ${showHistory ? 'rotate-90' : ''}`}/>
        </button>
        <AnimatePresence>
          {showHistory && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.18 }}
              className="overflow-hidden"
            >
              <div className="max-h-80 overflow-y-auto divide-y divide-husn-border">
                {history.length === 0 ? (
                  <p className="p-6 text-[12px] text-husn-text-3 italic text-center">
                    {lang === 'en' ? 'No actions logged yet.' : 'لا توجد إجراءات مسجَّلة بعد.'}
                  </p>
                ) : history.map((h, i) => {
                  const c = ACTION_COLOR[h.action] || '#a1a1aa';
                  return (
                    <div key={`${h.ts}-${i}`} className="px-4 py-2 flex items-center gap-3 text-[11px]">
                      <span className="text-husn-text-3 w-32 shrink-0 tracking-normal">{h.ts_iso}</span>
                      <span className="uppercase tracking-[0.12em] w-20 shrink-0" style={{ color: c }}>{h.action}</span>
                      <span className="text-white w-20 shrink-0 truncate">{h.actor}</span>
                      <span className="text-husn-text-2 truncate flex-1 font-mono tracking-normal">
                        {h.file}:{h.line_number} <span className="text-husn-text-3">[{h.rule_id}]</span>
                      </span>
                      <span className={`uppercase tracking-[0.12em] w-16 shrink-0 text-right
                        ${h.outcome === 'ok' ? 'text-husn-success' : h.outcome === 'failed' ? 'text-husn-danger' : 'text-husn-text-3'}`}>
                        {h.outcome}
                      </span>
                    </div>
                  );
                })}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* ========== Bulk-fix confirmation modal ========== */}
      {showBulkConfirm && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={() => setShowBulkConfirm(false)}>
          <div className="husn-card p-6 max-w-md w-full" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center gap-2 mb-2">
              <Sparkles size={16} className="text-husn-success"/>
              <h4 className="text-white text-[13px] uppercase tracking-[0.16em]">
                {lang === 'en' ? 'Fix selected with AI?' : 'إصلاح المحدد بالذكاء؟'}
              </h4>
            </div>
            <p className="text-[12px] text-husn-text-2 mb-3">
              {lang === 'en'
                ? <>The AI will be asked for a one-line patch for each of <strong className="text-white">{selected.size}</strong> selected issues. Each suggestion is applied immediately, with a backup file written before every change.</>
                : <>سيُطلب من الذكاء اقتراح إصلاح بسطر واحد لكل واحدة من <strong className="text-white">{selected.size}</strong> المشاكل المحددة. كل اقتراح يُطبَّق فوراً مع كتابة نسخة احتياطية.</>
              }
            </p>
            <div className="text-[11px] text-husn-warn bg-husn-warn/10 border border-husn-warn/30 rounded px-3 py-2 mb-4 flex items-start gap-2">
              <AlertCircle size={11} className="shrink-0 mt-0.5"/>
              <span>{lang === 'en'
                ? 'This applies LLM-generated code WITHOUT line-by-line review. Recover with the backup files (`.husn-bak.<ts>`) if anything breaks.'
                : 'يُطبَّق هذا كود من الذكاء بدون مراجعة سطر-بسطر. يمكن الاستعادة من ملفات النسخ.'}</span>
            </div>
            <div className="flex justify-end gap-2">
              <button onClick={() => setShowBulkConfirm(false)} className="husn-btn-ghost text-xs">
                {lang === 'en' ? 'Cancel' : 'إلغاء'}
              </button>
              <button onClick={bulkFixWithAI}
                className="text-xs uppercase tracking-[0.14em] px-4 py-2 rounded-lg bg-husn-success text-black font-semibold hover:brightness-110 transition flex items-center gap-2">
                <Sparkles size={12}/> {lang === 'en' ? `Fix ${selected.size} now` : `إصلاح ${selected.size} الآن`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========== Bulk results modal ========== */}
      {bulkResults && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={() => setBulkResults(null)}>
          <div className="husn-card p-6 max-w-2xl w-full max-h-[80vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-white text-[13px] uppercase tracking-[0.16em] flex items-center gap-2">
                <Sparkles size={14} className="text-husn-success"/>
                {lang === 'en' ? 'Bulk AI fix · results' : 'نتائج الإصلاح بالذكاء'}
              </h4>
              <button onClick={() => setBulkResults(null)} className="text-husn-text-3 hover:text-white p-1">
                <XClose size={14}/>
              </button>
            </div>
            <div className="grid grid-cols-3 gap-2 mb-3 text-center">
              <div className="rounded-md bg-husn-success/10 border border-husn-success/30 px-3 py-2">
                <div className="text-[10px] uppercase tracking-[0.14em] text-husn-success">{lang === 'en' ? 'Applied' : 'مُطبَّق'}</div>
                <div className="text-white text-[18px] font-light">{bulkResults.filter((r) => r.status === 'ok').length}</div>
              </div>
              <div className="rounded-md bg-husn-warn/10 border border-husn-warn/30 px-3 py-2">
                <div className="text-[10px] uppercase tracking-[0.14em] text-husn-warn">{lang === 'en' ? 'No suggestion' : 'لا اقتراح'}</div>
                <div className="text-white text-[18px] font-light">{bulkResults.filter((r) => r.status === 'no-suggestion').length}</div>
              </div>
              <div className="rounded-md bg-husn-danger/10 border border-husn-danger/30 px-3 py-2">
                <div className="text-[10px] uppercase tracking-[0.14em] text-husn-danger">{lang === 'en' ? 'Failed' : 'فشل'}</div>
                <div className="text-white text-[18px] font-light">{bulkResults.filter((r) => r.status === 'failed').length}</div>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto divide-y divide-husn-border border border-husn-border rounded-md">
              {bulkResults.map((r) => (
                <div key={r.id} className="px-3 py-2 flex items-center gap-3 text-[11px]">
                  <span className={`uppercase tracking-[0.12em] w-20 shrink-0 font-semibold
                    ${r.status === 'ok' ? 'text-husn-success' : r.status === 'failed' ? 'text-husn-danger' : 'text-husn-warn'}`}>
                    {r.status === 'ok' ? '✓ ok' : r.status === 'failed' ? '✗ fail' : '— skip'}
                  </span>
                  <span className="font-mono tracking-normal text-husn-text-2 truncate flex-1">
                    {r.file}:{r.line}
                  </span>
                  <span className="text-husn-text-3 truncate flex-1 hidden sm:block">{r.message}</span>
                </div>
              ))}
            </div>
            <div className="flex justify-end mt-3">
              <button onClick={() => setBulkResults(null)} className="husn-btn-primary text-xs">
                {lang === 'en' ? 'Close' : 'إغلاق'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function KpiTile({ label, value, icon, highlight, color }:
  { label: string; value: string; icon: any; highlight?: boolean; color?: string }) {
  const c = color || (highlight ? '#f43f5e' : '#ffffff');
  return (
    <div className={`husn-card p-4 flex items-start justify-between
      ${highlight ? 'border-husn-danger/40' : ''}`}>
      <div>
        <p className="text-[10px] text-husn-text-2 uppercase tracking-[0.14em]">{label}</p>
        <p className="text-[20px] font-light tracking-[0.08em] mt-1" style={{ color: c }}>
          {value}
        </p>
      </div>
      <div className={`w-8 h-8 rounded-lg border flex items-center justify-center
        ${highlight ? 'border-husn-danger/40 text-husn-danger' : 'border-husn-border text-husn-text-2'}`}>
        {icon}
      </div>
    </div>
  );
}
