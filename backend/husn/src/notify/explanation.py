"""Translate (label, confidence, feature_importance) into a one-sentence
explanation in English and Arabic.

Use cases:
  * email body — "Husn blocked X because…"
  * dashboard Defense tab — collapsible "why?" row
  * audit log

The mapping is deliberately template-based, not LLM-based: deterministic,
offline, no inference cost, no hallucination, instantly bilingual. Each
feature has a human-readable name and a "high/low" interpretation.
"""
from __future__ import annotations

from typing import Any


# ---------- feature → human name (per language) + "what high/low means"

_FEATURE_INFO: dict[str, dict[str, dict[str, str]]] = {
    "flow_pkts_s": {
        "en": {"name": "packets-per-second rate",        "high": "an abnormally high traffic rate"},
        "ar": {"name": "معدل الحزم في الثانية",          "high": "معدل حركة مرتفع غير طبيعي"},
    },
    "flow_byts_s": {
        "en": {"name": "bytes-per-second rate",          "high": "an abnormally high data-transfer rate"},
        "ar": {"name": "معدل البايتات في الثانية",       "high": "معدل نقل بيانات مرتفع غير طبيعي"},
    },
    "syn_flag_cnt": {
        "en": {"name": "SYN-flag count",                 "high": "many half-open TCP connections"},
        "ar": {"name": "عدد علامات SYN",                 "high": "العديد من اتصالات TCP المفتوحة جزئيًا"},
    },
    "ack_flag_cnt": {
        "en": {"name": "ACK-flag count",                 "high": "an unusual ACK pattern"},
        "ar": {"name": "عدد علامات ACK",                 "high": "نمط ACK غير معتاد"},
    },
    "pkt_len_mean": {
        "en": {"name": "average packet size",            "high": "abnormally large packets"},
        "ar": {"name": "متوسط حجم الحزمة",               "high": "حزم كبيرة غير طبيعية"},
    },
    "pkt_len_std": {
        "en": {"name": "packet-size variance",           "high": "highly inconsistent packet sizes"},
        "ar": {"name": "تباين حجم الحزم",                "high": "أحجام حزم متفاوتة جدًا"},
    },
    "fwd_pkt_len_max": {
        "en": {"name": "largest outbound packet",        "high": "an oversized outbound packet"},
        "ar": {"name": "أكبر حزمة صادرة",                "high": "حزمة صادرة بحجم مفرط"},
    },
    "fwd_pkt_len_mean": {
        "en": {"name": "average outbound packet size",   "high": "consistently large outbound packets"},
        "ar": {"name": "متوسط حجم الحزم الصادرة",        "high": "حزم صادرة كبيرة باستمرار"},
    },
    "bwd_pkt_len_max": {
        "en": {"name": "largest inbound packet",         "high": "an oversized server response"},
        "ar": {"name": "أكبر حزمة واردة",                "high": "استجابة خادم بحجم مفرط"},
    },
    "bwd_pkt_len_mean": {
        "en": {"name": "average inbound packet size",    "high": "consistently large server responses"},
        "ar": {"name": "متوسط حجم الحزم الواردة",        "high": "استجابات خادم كبيرة باستمرار"},
    },
    "flow_iat_mean": {
        "en": {"name": "inter-arrival time",             "high": "irregular packet timing"},
        "ar": {"name": "زمن الوصول بين الحزم",           "high": "توقيت حزم غير منتظم"},
    },
    "flow_iat_max": {
        "en": {"name": "max inter-arrival gap",          "high": "long pauses between packets"},
        "ar": {"name": "أقصى فجوة بين الحزم",            "high": "توقفات طويلة بين الحزم"},
    },
    "flow_duration": {
        "en": {"name": "flow duration",                  "high": "an unusually long-lived flow"},
        "ar": {"name": "مدة التدفق",                     "high": "تدفق طويل بشكل غير معتاد"},
    },
    "total_fwd_pkts": {
        "en": {"name": "outbound packet count",          "high": "a flood of outbound packets"},
        "ar": {"name": "عدد الحزم الصادرة",              "high": "فيضان من الحزم الصادرة"},
    },
    "total_bwd_pkts": {
        "en": {"name": "inbound packet count",           "high": "a flood of inbound packets"},
        "ar": {"name": "عدد الحزم الواردة",              "high": "فيضان من الحزم الواردة"},
    },
}


# ---------- attack-class human names

_LABEL_NAMES = {
    "DDoS":         {"en": "DDoS attack",                   "ar": "هجوم حجب الخدمة الموزع (DDoS)"},
    "PortScan":     {"en": "port-scan reconnaissance",      "ar": "استطلاع بفحص المنافذ"},
    "Brute Force":  {"en": "brute-force attack",            "ar": "هجوم تخمين كلمات المرور"},
    "Infiltration": {"en": "infiltration attempt",          "ar": "محاولة اختراق"},
    "Web Attack":   {"en": "web application attack",        "ar": "هجوم تطبيق ويب"},
    "BENIGN":       {"en": "benign traffic",                "ar": "حركة مرور مشروعة"},
}


def _feature_phrase(feat_name: str, lang: str) -> tuple[str, str]:
    info = _FEATURE_INFO.get(feat_name)
    if not info:
        return feat_name.replace("_", " "), "an unusual signature"
    return info[lang]["name"], info[lang]["high"]


def explain(
    label: str,
    confidence: float,
    feature_importance: list[dict[str, Any]] | None,
    source_ip: str = "",
) -> dict[str, str]:
    """Build {en, ar} sentences. `feature_importance` is the same list the
    /explain endpoint returns: [{name, value}, ...]."""
    feats = sorted(feature_importance or [], key=lambda r: abs(r.get("value", 0)), reverse=True)
    top3 = feats[:3]
    if not top3:
        en = f"Husn blocked {source_ip or 'this IP'} — classified as {_LABEL_NAMES.get(label, {}).get('en', label)} with {confidence*100:.0f}% confidence."
        ar = f"حظر حصن {source_ip or 'هذا العنوان'} — تم تصنيفه على أنه {_LABEL_NAMES.get(label, {}).get('ar', label)} بثقة {confidence*100:.0f}٪."
        return {"en": en, "ar": ar}

    top_name_en, top_desc_en = _feature_phrase(top3[0]["name"], "en")
    top_name_ar, top_desc_ar = _feature_phrase(top3[0]["name"], "ar")
    other_en = ", ".join(_feature_phrase(f["name"], "en")[0] for f in top3[1:])
    other_ar = "، ".join(_feature_phrase(f["name"], "ar")[0] for f in top3[1:])

    label_en = _LABEL_NAMES.get(label, {}).get("en", label)
    label_ar = _LABEL_NAMES.get(label, {}).get("ar", label)

    en = (f"Husn blocked {source_ip or 'this IP'} because the {top_name_en} "
          f"showed {top_desc_en}, combined with anomalies in {other_en} — "
          f"matching the {label_en} pattern with {confidence*100:.0f}% confidence.")
    ar = (f"حظر حصن {source_ip or 'هذا العنوان'} لأن {top_name_ar} "
          f"أظهر {top_desc_ar}، مع اضطرابات في {other_ar} — "
          f"وهذا يطابق نمط {label_ar} بثقة {confidence*100:.0f}٪.")
    return {"en": en, "ar": ar}
