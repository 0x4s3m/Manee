// AI Inspector — show exactly what HusnAI saw
// =============================================
// For every flow scored by the AI, the sniffer keeps a rich snapshot:
//   { ts, src, dst, sport, dport, proto, pkts, label, confidence,
//     is_anomaly, severity, payload_preview, payload_bytes,
//     features: { ...17 floats... } }
//
// This component renders that ring as a live table — one row per flow.
// Click a row to expand a detail card showing every one of the 17
// features the model consumed plus the full payload preview. That gives
// judges a "behind the curtain" view of the detection decision.

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity, ShieldAlert, Eye, ChevronRight } from 'lucide-react';

type FlowPacket = {
  ts: number;
  src: string;
  dst: string;
  sport: number;
  dport: number;
  proto: string;
  pkts: number;
  label: string;
  confidence: number;
  is_anomaly: boolean;
  severity?: string;
  signature?: string | null;
  payload_preview: string;
  payload_bytes: number;
  features: Record<string, number>;
};

const SEV_COLOR: Record<string, string> = {
  Critical: '#f43f5e',
  High:     '#f97316',
  Medium:   '#f59e0b',
  Low:      '#a1a1aa',
  BENIGN:   '#10b981',
};

function labelColor(label: string, anomaly: boolean): string {
  if (!anomaly || label === 'BENIGN') return '#10b981';
  if (label.toLowerCase().includes('ddos'))     return '#f43f5e';
  if (label.toLowerCase().includes('infiltr'))  return '#f97316';
  if (label.toLowerCase().includes('web'))      return '#f59e0b';
  if (label.toLowerCase().includes('brute'))    return '#f59e0b';
  if (label.toLowerCase().includes('port'))     return '#a1a1aa';
  return '#a1a1aa';
}

function timeAgo(ts: number): string {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60)    return `${s}s`;
  if (s < 3600)  return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

interface Props {
  packets: FlowPacket[];
  lang: 'en' | 'ar';
  T: any;
  onInvestigate?: (ip: string) => void;
}

export default function AIInspector({ packets, lang, T, onInvestigate }: Props) {
  // Track expanded row by a STABLE per-packet key, not by array index.
  // The backend prepends new entries to the deque every few seconds, so
  // any index would point at the wrong row after the next poll.
  const [expandedKey, setExpandedKey] = useState<string | null>(null);
  const rowKey = (p: FlowPacket) => `${p.ts}|${p.src}|${p.sport}|${p.dst}|${p.dport}|${p.proto}`;

  if (!packets.length) {
    return (
      <div className="husn-card p-12 flex flex-col items-center justify-center gap-3 min-h-[320px]">
        <Eye size={32} className="text-husn-text-3 opacity-60"/>
        <p className="text-husn-text-3 text-[13px] text-center max-w-md">
          {T.aiInspectorEmpty}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Mini KPIs */}
      <div className="grid grid-cols-3 gap-3">
        <KpiTile
          label={lang === 'en' ? 'Packets analysed' : 'حزم مفحوصة'}
          value={String(packets.length)}
          icon={<Activity size={14}/>}
        />
        <KpiTile
          label={lang === 'en' ? 'Anomalous flows' : 'تدفقات شاذة'}
          value={String(packets.filter((p) => p.is_anomaly && p.label !== 'BENIGN').length)}
          icon={<ShieldAlert size={14}/>}
          highlight
        />
        <KpiTile
          label={lang === 'en' ? 'Avg confidence' : 'متوسط الثقة'}
          value={`${(
            (packets.reduce((s, p) => s + p.confidence, 0) / packets.length) * 100
          ).toFixed(0)}%`}
          icon={<Eye size={14}/>}
        />
      </div>

      {/* Stream */}
      <div className="husn-card overflow-hidden">
        <div className="px-4 py-3 border-b border-husn-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-husn-success animate-pulse"/>
            <p className="text-[12px] text-white uppercase tracking-[0.16em]">
              {lang === 'en' ? 'Live AI feed' : 'البث المباشر للذكاء'}
            </p>
          </div>
          <p className="text-[10px] text-husn-text-3 tracking-normal">
            {lang === 'en' ? `${packets.length} flows` : `${packets.length} تدفق`}
          </p>
        </div>

        <div className="max-h-[58vh] overflow-y-auto divide-y divide-husn-border">
          {packets.map((p) => {
            const k = rowKey(p);
            const open = expandedKey === k;
            const lc = labelColor(p.label, p.is_anomaly);
            return (
              <div key={k} className="group">
                <button
                  onClick={() => setExpandedKey(open ? null : k)}
                  className="w-full px-4 py-3 flex items-center gap-3 text-left hover:bg-white/[0.02] transition"
                >
                  <ChevronRight
                    size={12}
                    className={`text-husn-text-3 shrink-0 transition-transform duration-150 ${open ? 'rotate-90' : ''}`}
                  />
                  <span className="text-[10px] text-husn-text-3 tracking-normal w-10 shrink-0">
                    {timeAgo(p.ts)}
                  </span>
                  <span className="font-mono text-[11px] text-white truncate min-w-0 flex-1">
                    <span className="text-husn-text-2">{p.src}</span>
                    <span className="text-husn-text-3 mx-1">→</span>
                    <span>{p.dst}:{p.dport}</span>
                  </span>
                  <span className="text-[9px] uppercase tracking-[0.14em] text-husn-text-3 w-10 shrink-0 text-center">
                    {p.proto}
                  </span>
                  <span className="text-[10px] text-husn-text-3 tracking-normal w-12 shrink-0 text-right">
                    {p.pkts} pkts
                  </span>
                  <span
                    className="text-[10px] font-semibold uppercase tracking-[0.14em] px-2 py-0.5 rounded shrink-0"
                    style={{
                      color: lc,
                      background: `${lc}1a`,
                      border: `1px solid ${lc}55`,
                    }}
                  >
                    {p.label}
                  </span>
                  <span className="text-[10px] text-white tracking-normal w-10 shrink-0 text-right font-mono">
                    {(p.confidence * 100).toFixed(0)}%
                  </span>
                </button>

                {/* Signature hit line + payload preview */}
                {(p.signature || p.payload_preview) && (
                  <div className="px-4 pb-3 -mt-1.5 ml-[58px] space-y-1.5">
                    {p.signature && (
                      <div className="inline-flex items-center gap-1.5 text-[10px] uppercase tracking-[0.14em] px-2 py-0.5 rounded border border-husn-warn/40 text-husn-warn bg-husn-warn/10">
                        <span className="w-1 h-1 rounded-full bg-husn-warn animate-pulse"/>
                        {lang === 'en' ? 'Signature:' : 'توقيع:'} {p.signature}
                      </div>
                    )}
                    {p.payload_preview && (
                      <code className="block text-[11px] text-husn-text-3 font-mono truncate bg-black/40 border border-husn-border rounded px-2 py-1">
                        {p.payload_preview.length > 120
                          ? p.payload_preview.slice(0, 120) + '…'
                          : p.payload_preview}
                      </code>
                    )}
                  </div>
                )}

                {/* Detail card */}
                <AnimatePresence>
                  {open && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ duration: 0.18 }}
                      className="overflow-hidden"
                    >
                      <ExpandedDetail packet={p} lang={lang} T={T} onInvestigate={onInvestigate}/>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function ExpandedDetail({ packet, lang, T, onInvestigate }: {
  packet: FlowPacket; lang: 'en' | 'ar'; T: any; onInvestigate?: (ip: string) => void;
}) {
  const lc = labelColor(packet.label, packet.is_anomaly);
  const sev = packet.severity || (packet.is_anomaly ? 'Medium' : 'Low');
  const sevColor = SEV_COLOR[sev] || '#a1a1aa';

  return (
    <div className="px-4 pb-5 pt-1 ml-[58px] space-y-4">
      {/* Top row: verdict + flow */}
      <div className="grid grid-cols-2 gap-3">
        <div className="rounded-lg border border-husn-border bg-black/30 p-3">
          <p className="text-[9px] text-husn-text-3 uppercase tracking-[0.16em]">{T.aiVerdict}</p>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="text-[15px] font-semibold uppercase tracking-[0.10em]" style={{ color: lc }}>
              {packet.label}
            </span>
            <span className="text-[10px] uppercase tracking-[0.12em]" style={{ color: sevColor }}>
              · {sev}
            </span>
          </div>
          <p className="text-[10px] text-husn-text-3 mt-1 tracking-normal">
            {lang === 'en' ? 'Confidence' : 'الثقة'} · {(packet.confidence * 100).toFixed(1)}%
          </p>
        </div>
        <div className="rounded-lg border border-husn-border bg-black/30 p-3">
          <p className="text-[9px] text-husn-text-3 uppercase tracking-[0.16em]">{T.flowSummary}</p>
          <p className="font-mono text-[11px] text-white mt-1.5 break-all">
            {packet.src}:{packet.sport} → {packet.dst}:{packet.dport}
          </p>
          <p className="text-[10px] text-husn-text-3 mt-1 tracking-normal">
            {packet.proto.toUpperCase()} · {packet.pkts} pkts · {packet.payload_bytes ? `${packet.payload_bytes} B payload` : 'no payload'}
          </p>
        </div>
      </div>

      {/* Payload + matched signature */}
      <div className="rounded-lg border border-husn-border bg-black/30 p-3 space-y-2">
        <div className="flex items-center justify-between">
          <p className="text-[9px] text-husn-text-3 uppercase tracking-[0.16em]">{T.payload}</p>
          {packet.signature && (
            <span className="inline-flex items-center gap-1.5 text-[10px] uppercase tracking-[0.14em] px-2 py-0.5 rounded border border-husn-warn/40 text-husn-warn bg-husn-warn/10">
              <span className="w-1 h-1 rounded-full bg-husn-warn animate-pulse"/>
              {lang === 'en' ? 'Rule match:' : 'مطابقة قاعدة:'} {packet.signature}
            </span>
          )}
        </div>
        {packet.payload_preview ? (
          <pre className="text-[11px] text-white font-mono whitespace-pre-wrap break-all">
            {packet.payload_preview}
          </pre>
        ) : (
          <p className="text-[11px] text-husn-text-3 italic">{T.noPayload}</p>
        )}
      </div>

      {/* 17 features */}
      <div className="rounded-lg border border-husn-border bg-black/30 p-3">
        <p className="text-[9px] text-husn-text-3 uppercase tracking-[0.16em] mb-2">{T.featuresExtracted}</p>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
          {Object.entries(packet.features).map(([k, v]) => (
            <div key={k} className="flex justify-between text-[11px] px-2 py-1 rounded bg-black/40 border border-husn-border">
              <span className="text-husn-text-3 tracking-normal truncate">{k}</span>
              <span className="text-white font-mono tracking-normal">{Number(v).toLocaleString(undefined, { maximumFractionDigits: 2 })}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Actions */}
      {onInvestigate && (
        <div className="flex justify-end">
          <button
            onClick={() => onInvestigate(packet.src)}
            className="text-[11px] uppercase tracking-[0.14em] px-3 py-1.5 rounded-md border border-husn-border text-husn-text-2 hover:text-white hover:border-husn-border-2 transition"
          >
            {T.investigate || 'Investigate'} {packet.src}
          </button>
        </div>
      )}
    </div>
  );
}

function KpiTile({ label, value, icon, highlight }:
  { label: string; value: string; icon: any; highlight?: boolean }) {
  return (
    <div className={`husn-card p-4 flex items-start justify-between
      ${highlight ? 'border-husn-danger/40' : ''}`}>
      <div>
        <p className="text-[10px] text-husn-text-2 uppercase tracking-[0.14em]">{label}</p>
        <p className={`text-[20px] font-light tracking-[0.08em] mt-1 ${highlight ? 'text-husn-danger' : 'text-white'}`}>
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
