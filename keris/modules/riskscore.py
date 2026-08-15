"""Risk score A-F untuk target, dari daftar temuan.

Skor dihitung dari severity + bobot jumlah temuan, mirip grading yang dipakai
penilai keamanan untuk menjelaskan kondisi ke klien dalam satu huruf.

Grade:
- A: bersih (tanpa HIGH/CRITICAL, sedikit LOW/INFO)
- B: risiko rendah (tanpa CRITICAL, sedikit HIGH)
- C: risiko sedang
- D: risiko tinggi
- F: kondisi kritis / banyak CRITICAL

Menghasilkan dict dengan grade, skor 0-100, breakdown per severity, dan
rekomendasi singkat.
"""

from typing import Dict, List

SEV_WEIGHTS = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1, "INFO": 0.2}

GRADE_DESC = {
    "A": "Profil keamanan baik. Perbaiki temuan INFO/LOW secara bertahap.",
    "B": "Profil keamanan cukup. Sebagian besar risiko rendah, tetapi tetap tindaklanjuti HIGH yang ada.",
    "C": "Profil keamanan sedang. Ada celah nyata yang perlu diperbaiki segera.",
    "D": "Profil keamanan buruk. Celah HIGH/CRITICAL membuka peluang kompromi.",
    "F": "Profil keamanan kritis. Sistem dalam kondisi berbahaya; perlu remediasi mendesak.",
}


def risk_score(findings: List[Dict]) -> Dict:
    """Hitung risk score dari daftar temuan dict."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s = (f.get("severity", "INFO") or "INFO").upper()
        counts[s] = counts.get(s, 0) + 1
    total = sum(counts.values()) or 1

    raw = sum(counts.get(s, 0) * SEV_WEIGHTS[s] for s in counts)
    # 10 CRITICAL atau ~17 HIGH = skor 0 (grade F)
    score = max(0.0, 100.0 - (raw / 16.0 * 100.0))
    score = round(min(score, 100.0), 1)

    if counts["CRITICAL"] >= 3:
        grade = "F"
    elif counts["CRITICAL"] >= 1 or counts["HIGH"] >= 4:
        grade = "D"
    elif counts["HIGH"] >= 1 or counts["MEDIUM"] >= 5:
        grade = "C"
    elif counts["MEDIUM"] >= 1 or counts["LOW"] >= 8:
        grade = "B"
    else:
        grade = "A"

    if counts["HIGH"] == 0 and counts["CRITICAL"] == 0:
        # tanpa HIGH/CRITICAL, skor dibatasi ke minimal B
        score = max(score, 75.0)
    if not findings:
        grade, score = "A", 100.0

    return {
        "grade": grade,
        "score": round(score, 1),
        "counts": counts,
        "total": total,
        "recommendation": GRADE_DESC.get(grade, ""),
    }