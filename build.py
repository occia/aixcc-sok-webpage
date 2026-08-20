#!/usr/bin/env python3
"""
Generate the AIxCC SoK companion website (`site/index.html`).

Reads the same CSV / table sources used by the LaTeX build so the website
content stays in lock-step with the paper:
    tbl/cp_details/appendix_cp.csv
    tbl/vuln_sarif_details/{cpvs,zerodays,sarif_broadcasts}.csv

Run from any directory:
    .venv/bin/python site/build.py
"""

from __future__ import annotations

import csv
import hashlib
import html
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
DATA = {
    "cp":          ROOT / "tbl" / "cp_details" / "appendix_cp.csv",
    "cpv":         ROOT / "tbl" / "vuln_sarif_details" / "cpvs.csv",
    "zd":          ROOT / "tbl" / "vuln_sarif_details" / "zerodays.csv",
    "sarif":       ROOT / "tbl" / "vuln_sarif_details" / "sarif_broadcasts.csv",
}

# ---------------------------------------------------------------------------
# CWE name lookup — pre-computed from the python-cwe2 database. Listing the
# names statically keeps the generator self-contained (no runtime dep on
# python-cwe2 inside the site/ build pipeline).
# ---------------------------------------------------------------------------
CWE_NAME = {
    "20":   "Improper Input Validation",
    "22":   "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "28":   "Path Traversal: '..filedir'",
    "29":   "Path Traversal: '..filename'",
    "35":   "Path Traversal: '.../...//'",
    "77":   "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
    "120":  "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
    "121":  "Stack-based Buffer Overflow",
    "122":  "Heap-based Buffer Overflow",
    "123":  "Write-what-where Condition",
    "125":  "Out-of-bounds Read",
    "126":  "Buffer Over-read",
    "129":  "Improper Validation of Array Index",
    "134":  "Use of Externally-Controlled Format String",
    "190":  "Integer Overflow or Wraparound",
    "193":  "Off-by-one Error",
    "382":  "J2EE Bad Practices: Use of System.exit()",
    "400":  "Uncontrolled Resource Consumption",
    "407":  "Inefficient Algorithmic Complexity",
    "415":  "Double Free",
    "416":  "Use After Free",
    "457":  "Use of Uninitialized Variable",
    "476":  "NULL Pointer Dereference",
    "611":  "Improper Restriction of XML External Entity Reference",
    "680":  "Integer Overflow to Buffer Overflow",
    "695":  "Use of Low-Level Functionality",
    "770":  "Allocation of Resources Without Limits or Throttling",
    "787":  "Out-of-bounds Write",
    "789":  "Memory Allocation with Excessive Size Value",
    "834":  "Excessive Iteration",
    "835":  "Loop with Unreachable Exit Condition ('Infinite Loop')",
    "917":  "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')",
    "918":  "Server-Side Request Forgery (SSRF)",
    "1333": "Inefficient Regular Expression Complexity",
}

LANG_LABEL = {"C": "C", "JVM": "Java", "Java": "Java"}

# Project → upstream URL (kept lightweight; used to link project names).
PROJECT_URL = {
    "curl": "https://github.com/curl/curl",
    "dav1d": "https://github.com/videolan/dav1d",
    "freerdp": "https://github.com/FreeRDP/FreeRDP",
    "libavif": "https://github.com/AOMediaCodec/libavif",
    "libexif": "https://github.com/libexif/libexif",
    "libxml2": "https://github.com/GNOME/libxml2",
    "little-cms": "https://github.com/mm2/Little-CMS",
    "mongoose": "https://github.com/cesanta/mongoose",
    "ndpi": "https://github.com/ntop/nDPI",
    "openssl": "https://github.com/openssl/openssl",
    "shadowsocks": "https://github.com/shadowsocks/shadowsocks-libev",
    "systemd": "https://github.com/systemd/systemd",
    "wireshark": "https://github.com/wireshark/wireshark",
    "xz": "https://github.com/tukaani-project/xz",
    "commons-compress": "https://github.com/apache/commons-compress",
    "dcm4che": "https://github.com/dcm4che/dcm4che",
    "dicoogle": "https://github.com/dicoogle/dicoogle",
    "healthcare-data-harmonization": "https://github.com/GoogleCloudPlatform/healthcare-data-harmonization",
    "hertzbeat": "https://github.com/apache/hertzbeat",
    "jsoup": "https://github.com/jhy/jsoup",
    "log4j2": "https://github.com/apache/logging-log4j2",
    "pdfbox": "https://github.com/apache/pdfbox",
    "poi": "https://github.com/apache/poi",
    "tika": "https://github.com/apache/tika",
}

# Project display tweaks (mirrors PROJECT_DISPLAY_NAMES in bin/csv2latex.py).
PROJECT_DISPLAY = {
    "Hertzbeat": "hertzbeat",
    "healthcare-data-harmonization": "healthcare-data-harmonization",
}

# Project → two-letter abbreviation. Sourced from the paper's
# tbl/cp_details/overview_table.tex (Abbr. column of t:cp-overview).
# This is the authoritative mapping for the CP-naming convention
# `<abbr><idx><mode>` (e.g. cu2▲, os1□, lj1▲).
PROJECT_ABBR = {
    "curl": "cu", "dav1d": "da", "freerdp": "fp", "little-cms": "cm",
    "libavif": "av", "libexif": "ex", "libxml2": "lx", "mongoose": "mg",
    "ndpi": "nd", "openssl": "os", "shadowsocks": "ss",
    "shadowsocks-libev": "ss", "systemd": "sd", "wireshark": "ws", "xz": "xz",
    "commons-compress": "cc", "dcm4che": "dc", "dicoogle": "dg",
    "healthcare-data-harmonization": "hc", "hertzbeat": "hb",
    "jsoup": "js", "log4j2": "lj", "logging-log4j2": "lj",
    "pdfbox": "pb", "poi": "po", "tika": "tk",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def esc(s: str | None) -> str:
    return html.escape("" if s is None else str(s))


def mode_mark(name: str) -> str:
    """Render the CPV name's mode mark (▲ or □) in a styled span."""
    s = esc(name)
    s = s.replace("▲", '<span class="mode-mark delta">▲</span>')
    s = s.replace("□", '<span class="mode-mark full">□</span>')
    s = s.replace("⊝", '<span class="mode-mark zd">⊝</span>')
    return s


def cpv_cell(name: str) -> str:
    return f'<span class="cpv-name">{mode_mark(name)}</span>'


def cwe_link(num: str) -> str:
    num = num.strip()
    name = CWE_NAME.get(num, "")
    title = f' title="{esc(name)}"' if name else ""
    return (
        f'<a class="cwe-link" href="https://cwe.mitre.org/data/definitions/{num}.html"'
        f'{title}>CWE-{num}</a>'
    )


def parse_cwes(field: str) -> list[str]:
    """Extract all CWE-XYZ numbers from either ['CWE-x' 'CWE-y'] or '121, 476'."""
    if not field:
        return []
    nums = re.findall(r"\b(\d+)\b", field)
    # csv2latex.py uses `re.findall(r'CWE-(\d+)', ...)` first; fall back to bare nums
    cwe_pattern = re.findall(r"CWE-(\d+)", field)
    return cwe_pattern if cwe_pattern else nums


def extract_error_type(desc: str) -> str:
    """Short error description from a sanitizer crash line.

    Mirrors bin/csv2latex.py:extract_error_type so the 0-day "Description"
    column reads identically to the paper (e.g. ASan/UBSan/Java mapping).
    """
    if not desc:
        return ""
    if "AddressSanitizer:" in desc:
        m = re.search(r"AddressSanitizer:\s*(\S+)", desc)
        if not m:
            return ""
        err = m.group(1).replace("-", " ")
        err = err[0].upper() + err[1:]
        return {"ABRT": "Abort signal", "SEGV": "Segmentation fault"}.get(err, err)
    if "LeakSanitizer:" in desc:
        return "Memory leak"
    if "runtime error:" in desc:
        m = re.search(r"runtime error:\s*(.+?)(?:\s*:|\s*$)", desc)
        if not m:
            return ""
        e = m.group(1).strip().replace("-", " ")
        return e[0].upper() + e[1:]
    if "Java Exception:" in desc and "Caused by:" in desc:
        m = re.search(r"Caused by:\s*java\.[.\w]+\.(\w+(?:Exception|Error))", desc)
        if m:
            err = m.group(1)
            return {
                "StackOverflowError": "Stack overflow",
                "OutOfMemoryError":   "Out of memory",
                "ClassNotFoundException": "Class not found",
            }.get(err, err)
    return ""


def zd_description(r: dict) -> str:
    """0-day description, exactly as the paper's Appendix H column.

    Reads the 'description' column (raw sanitizer error line), not 'crash_summary'.
    This matches bin/csv2latex.py:generate_zerodays_table → extract().
    """
    desc = extract_error_type(r.get("description", "") or "")
    if r.get("language") == "C":
        san = {"UNDEFINED": "UBSan", "ADDRESS": "ASan"}.get(r.get("sanitizer", ""),
                                                            r.get("sanitizer", ""))
        return f"{san}: {desc}"
    return desc


def truncate(s: str, n: int = 280) -> str:
    s = (s or "").strip().replace(" || ", "; ")
    if len(s) <= n:
        return s
    cut = s[:n].rsplit(" ", 1)[0]
    return cut + "…"


def read_csv(path: Path) -> list[dict]:
    with path.open() as f:
        return list(csv.DictReader(f))


def project_link(name: str) -> str:
    display = PROJECT_DISPLAY.get(name, name)
    url = PROJECT_URL.get(name)
    if url:
        return f'<a href="{url}">{esc(display)}</a>'
    return esc(display)


def get_project_name(repo_url: str) -> str:
    """Mirror bin/csv2latex.py — strip the `round-final-phaseN-` prefix."""
    if not repo_url:
        return ""
    m = re.search(r"-phase\d+-(.+)$", repo_url)
    return m.group(1) if m else repo_url.rsplit("/", 1)[-1]


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------
def render_cp_table(rows: list[dict]) -> str:
    out = [
        '<div class="table-wrap"><table class="data">',
        "<thead><tr>",
        "<th>Lang</th><th>Project</th><th>Category</th><th class='num'># Harn.</th>",
        "<th>CP</th><th class='num'># CPVs</th><th>CWEs</th><th class='num'>SLOC</th>",
        "<th>Commit</th><th>Cutoff</th><th class='num'>Δ Lines</th><th class='num'>Δ Files</th>",
        "<th class='num'>Build</th><th class='num'>Harn. Size</th>",
        "</tr></thead><tbody>",
    ]

    def fmt_chal(r: dict) -> str:
        """Render the CP id like cu2▲ / cm1□ / os1□ / lj1▲.

        Uses the paper's two-letter project abbreviation (PROJECT_ABBR) for
        the prefix and extracts the trailing integer of the challenge name
        for the index. Falls back to index 1 when the challenge name has no
        trailing digit (e.g. `openssl_analysis_raw` → `os1□`).
        Mode marker comes from the CSV `task_type` column.
        """
        abbr = PROJECT_ABBR.get(r["project"], r["project"])
        m = re.search(r"(\d+)\s*$", r["challenge"])
        idx = str(int(m.group(1))) if m else "1"
        mark = "▲" if r.get("task_type") == "DELTA" else "□"
        return f"{abbr}{idx}{mark}"

    def commit_link(r: dict) -> str:
        c = r["commit"]
        if not c:
            return ""
        url = PROJECT_URL.get(r["project"])
        short = c[:7]
        if url:
            return f'<a href="{url}/commit/{c}"><code>{short}</code></a>'
        return f"<code>{short}</code>"

    for r in rows:
        cwes_field = r.get("cwe_ids") or ""
        cwes_html = (
            ", ".join(cwe_link(n) for n in re.findall(r"\d+", cwes_field))
            if cwes_field
            else "—"
        )
        delta_lines = r.get("lines_of_delta") or "—"
        delta_files = r.get("files_changed") or "—"
        lang = LANG_LABEL.get(r["language"], r["language"])
        out.append("<tr>")
        out.append(f'<td><span class="lang-tag">{esc(lang)}</span></td>')
        out.append(f"<td>{project_link(r['project'])}</td>")
        out.append(f'<td>{esc(r["category"].replace("_", " ").title())}</td>')
        out.append(f"<td class='num'>{esc(r['harness_count'])}</td>")
        out.append(f"<td class='compact'><code>{esc(fmt_chal(r))}</code></td>")
        out.append(
            f"<td class='num'>{esc(r['cpv_count'])}</td>"
        )
        out.append(f"<td>{cwes_html}</td>")
        out.append(f"<td class='num'>{esc(r['total_sloc'])}</td>")
        out.append(f"<td class='compact'>{commit_link(r)}</td>")
        out.append(f"<td class='compact'>{esc(r['cutoff_date'])}</td>")
        out.append(f"<td class='num'>{esc(delta_lines)}</td>")
        out.append(f"<td class='num'>{esc(delta_files)}</td>")
        out.append(f"<td class='num'>{esc(r['build_time'])}</td>")
        out.append(f"<td class='num'>{esc(r['harness_size'])}</td>")
        out.append("</tr>")
    out.append("</tbody></table></div>")
    out.append(
        '<p class="footnotes">'
        '<span class="mode-mark delta">▲</span> delta-mode &nbsp; '
        '<span class="mode-mark full">□</span> full-mode. '
        "Cutoff: date of the latest upstream commit incorporated into the organizer's CP repository. "
        "Build time measured on AMD EPYC 7452 (128 cores), 512 GB RAM, Ubuntu 22.04.</p>"
    )
    return "\n".join(out)


def render_cpv_table(rows: list[dict]) -> str:
    """Mirror the paper's Appendix G table: Lang | Ph | Project | ID | Vuln | CWE | CWE Name.

    Each CPV is expanded into one row per CWE (matches the LaTeX longtblr layout)."""
    out = [
        '<div class="table-wrap"><table class="data">',
        "<thead><tr>",
        "<th>Lang</th><th>Ph</th><th>Project</th><th>ID</th><th>Vuln</th>",
        "<th>CWE</th><th>CWE Name</th>",
        "</tr></thead><tbody>",
    ]
    for r in rows:
        cwes = parse_cwes(r.get("cwes", "")) or [""]
        lang = LANG_LABEL.get(r["language"], r["language"])
        proj_name = get_project_name(r.get("repo_url", ""))
        rowspan = len(cwes)
        for i, cwe in enumerate(cwes):
            out.append("<tr>")
            if i == 0:
                rs = f' rowspan="{rowspan}"' if rowspan > 1 else ""
                out.append(f'<td{rs}><span class="lang-tag">{esc(lang)}</span></td>')
                out.append(f"<td{rs} class='center'>{esc(r['phase'])}</td>")
                out.append(
                    f"<td{rs}><a href='{esc(r['repo_url'])}'>{esc(proj_name)}</a></td>"
                )
                out.append(f"<td{rs} class='compact'>{cpv_cell(r['cpv'])}</td>")
                out.append(f"<td{rs} class='compact'><code>{esc(r['vuln_id'])}</code></td>")
            out.append(
                f"<td class='compact'>{cwe_link(cwe) if cwe else '—'}</td>"
            )
            out.append(
                f"<td>{esc(CWE_NAME.get(cwe, '—'))}</td>"
            )
            out.append("</tr>")
    out.append("</tbody></table></div>")
    out.append(
        '<p class="footnotes">'
        '<span class="mode-mark delta">▲</span> delta-mode &nbsp; '
        '<span class="mode-mark full">□</span> full-mode. '
        "Multi-CWE CPVs span multiple rows.</p>"
    )
    return "\n".join(out)


def render_zd_table(rows: list[dict]) -> str:
    """Mirror the paper's Appendix H table: Lang | Ph | Project | ID | Description."""
    out = [
        '<div class="table-wrap"><table class="data">',
        "<thead><tr>",
        "<th>Lang</th><th>Ph</th><th>Project</th><th>ID</th><th>Description</th>",
        "</tr></thead><tbody>",
    ]
    for r in rows:
        proj = get_project_name(r.get("repository_url", ""))
        lang = LANG_LABEL.get(r["language"], r["language"])
        out.append("<tr>")
        out.append(f'<td><span class="lang-tag">{esc(lang)}</span></td>')
        out.append(f"<td class='center'>{esc(r['phase'])}</td>")
        out.append(
            f"<td><a href='{esc(r['repository_url'])}'>{esc(proj)}</a></td>"
        )
        out.append(f"<td class='compact'>{cpv_cell(r['cpv'])}</td>")
        out.append(f"<td>{esc(zd_description(r))}</td>")
        out.append("</tr>")
    out.append("</tbody></table></div>")
    out.append(
        '<p class="footnotes">'
        '<span class="mode-mark delta">▲</span> delta-mode &nbsp; '
        '<span class="mode-mark full">□</span> full-mode.</p>'
    )
    return "\n".join(out)


def render_sarif_table(rows: list[dict]) -> str:
    """Mirror the paper's Appendix I table: Ph | Project | Lang | Label | Answer."""
    out = [
        '<div class="table-wrap"><table class="data">',
        "<thead><tr>",
        "<th>Ph</th><th>Project</th><th>Lang</th><th>Label</th><th>Answer</th>",
        "</tr></thead><tbody>",
    ]
    for r in rows:
        proj = get_project_name(r.get("repo_url", ""))
        lang = LANG_LABEL.get(r["language"], r["language"])
        answer = r.get("correct_answer", "")
        cls = "good" if answer == "CORRECT" else "bad"
        out.append("<tr>")
        out.append(f"<td class='center'>{esc(r['phase'])}</td>")
        out.append(f"<td><a href='{esc(r['repo_url'])}'>{esc(proj)}</a></td>")
        out.append(f'<td><span class="lang-tag">{esc(lang)}</span></td>')
        out.append(f"<td class='compact'>{cpv_cell(r['sarif_label'])}</td>")
        out.append(f"<td class='compact'><span class='{cls}'>{esc(answer)}</span></td>")
        out.append("</tr>")
    out.append("</tbody></table></div>")
    out.append(
        '<p class="footnotes">'
        '<span class="mode-mark delta">▲</span> delta-mode &nbsp; '
        '<span class="mode-mark full">□</span> full-mode &nbsp; '
        '<span class="mode-mark zd">⊝</span> false-positive broadcast (no underlying CPV).</p>'
    )
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Static section blocks (text-heavy parts of the appendix)
# ---------------------------------------------------------------------------
SECTION_TOKEN = """
<section id="token-consumption">
<h2>Token Consumption Details<a class="anchor-link" href="#token-consumption">¶</a></h2>

<p>
The figures below show the per-model token consumption and the input-to-output token ratio per model.
Token data is derived from OpenTelemetry (OTEL) logs collected by the organizers.
As the collected data was incomplete due to the competition environment,
the figures do not present full usage but serve as a lower-bound reference.
</p>

<div class="figure">
  <img src="assets/figures/model_usage_by_team.png" alt="Per-model token consumption by team">
  <p class="figure-caption"><span class="caption-label">Figure C1.</span>
  Token consumption (input + output) per model by team.</p>
</div>

<div class="figure">
  <img src="assets/figures/io_token_ratio_by_model_team.png" alt="Input-to-output token ratio per model by team">
  <p class="figure-caption"><span class="caption-label">Figure C2.</span>
  I/O token ratio per model by team.</p>
</div>
</section>
"""


SECTION_SCORING = r"""
<section id="scoring">
<h2>Scoring Rules Explanation<a class="anchor-link" href="#scoring">¶</a></h2>

<p>
The scoring system is centered around a developer-centric principle:
reward outcomes that benefit project developers
and penalize behaviors that would burden them.
Organizers use this principle to determine
when and to what extent should reward be given for each capability:
</p>
<ul>
  <li>A single PoV is not highly rewarded since it only demonstrates the vulnerability;</li>
  <li>Patches score highest as they directly solve security issues;</li>
  <li>SARIF assessments are useful but only offer non-core, semi-subjective report validation, therefore scoring lowest;</li>
  <li>Bundling saves developer investigation time when correct (rewarded), but largely wastes their efforts and emotions when incorrect (penalized).</li>
</ul>
<p>
Based on those weights,
organizers introduce additional scoring mechanisms, like accuracy penalty and time-decay, to
ensure competition fairness and balance research incentives with practicality.
</p>

<h3>Team Score Hierarchy</h3>
<p>
A team's total score is the sum of individual challenge scores:
</p>
\[
S_{\text{Team}} \;=\; \sum S_{\text{Challenge}}
\]
<p>Each challenge score equals the accuracy multiplier times the sum of four capability scores:</p>
\[
S_{\text{Challenge}} \;=\; AM \,\times\,
\bigl(S_{\text{PoV}} + S_{\text{Patch}} + S_{\text{SARIF}} + S_{\text{Bundle}}\bigr)
\]

<h3>Accuracy Multiplier</h3>
<p>
The accuracy multiplier <em>AM</em> serves as a global button to
encourage teams to balance effectiveness with reliability.
Teams with 100% accurate submissions receive no penalty (AM = 1),
while lower accuracy results in a reduced multiplier:
</p>
\[
AM \;=\; 1 - (1-r)^4, \qquad r \;=\; \frac{n_{\text{acc}}}{n_{\text{acc}} + n_{\text{inacc}}}
\]
<p>
The quartic formula strongly penalizes low accuracy to discourage impractical strategies,
while tolerating reasonable error rates to enable research innovation.
For instance, at 90% accuracy AM ≈ 0.9999 (nearly no penalty),
while at 50% AM = 0.9375 and at 40% AM = 0.8704 (significant score reduction).
</p>

<p>
Each submission is classified as accurate, inaccurate, or neutral, where neutral submissions
do not affect accuracy calculations.
For a given capability, the classification rationale is to
reward correct, non-duplicate submissions,
penalize incorrect ones,
and not penalize partially correct or duplicate submissions that provide real-world value:
</p>
<ul>
  <li><strong>PoV.</strong> One reproducible PoV per vulnerability is accurate; irreproducible PoVs are inaccurate; reproducible but duplicate PoVs are neutral, since collecting diverse PoVs can benefit patch validation in practice.</li>
  <li><strong>Patch.</strong> First, patches that fail to apply, build, or remediate any PoV are inaccurate. Then, the patches that fail functionality tests are neutral. This considers that CRSs may not have access to full testing functionality in practice and a CI system can help catch such issues. Finally, among passing patches, a minimal covering set is selected as accurate while the rest are inaccurate.</li>
  <li><strong>SARIF and Bundle.</strong> Only fully correct submissions are accurate; others are inaccurate.</li>
  <li><strong>Server errors and schema mismatches.</strong> neutral.</li>
</ul>

<h3>Time-Decayed Scoring Design</h3>
<p>
Teams' submissions earn fewer points over time, with up to 50% reduction at the deadline.
\(\mathit{Score}_{\text{PoV}}\), \(\mathit{Score}_{\text{Patch}}\), and \(\mathit{Score}_{\text{SARIF}}\) share a common time-decay formula:
</p>
\[
\mathit{Score} \;=\; \mathit{weight} \times \tau, \qquad
\tau \;=\; 0.5 \;+\; \frac{\text{remaining time}}{2 \times \text{total duration}}
\]
<p>
where <em>remaining time</em> is from submission to deadline,
and <em>total duration</em> is the challenge window.
\(\tau\) ranges from 1.0 (immediate) to 0.5 (at deadline).
The <em>weight</em> for PoV, Patch, and SARIF are 2, 6, and 1, respectively.
For total duration, PoV and Patch submissions are measured from challenge start to deadline
(full-mode for 12 hours while delta-mode for 6 hours), while SARIF is from broadcast time.
</p>
<p>
Note that for each vulnerability, only the last submission is scored,
so earlier submissions can be superseded by later ones,
allowing teams to revise their submissions with a certain penalty.
</p>

<h3>Bundle Scoring</h3>
<p>
A bundle reports pairings among PoV, Patch, and broadcast SARIF
that a team identifies as addressing the same vulnerability.
Unlike other capabilities, bundles can yield negative scores:
</p>
\[
S_{\text{Bundle}} \;=\; \pm \Bigl(
  \underbrace{0.5\,(S_{\text{PoV}} + S_{\text{Patch}})}_{\text{PoV–Patch}}
  + \underbrace{\,1\,}_{\text{PoV–SARIF}}
  + \underbrace{\,2\,}_{\text{Patch–SARIF}}
\Bigr)
\]
<p>
The sign is positive if all claimed pairings are correct, negative if any is incorrect.
The more correct pairings, the higher the score (up to 7 points for vulnerabilities that have a SARIF broadcast,
4 for those without). CRS-generated SARIF may be included in bundles but does not affect scoring.
Bundle scoring is indirectly affected by time-decay through the underlying PoV and Patch scores.
</p>

<h3>Patch Selection and Validation</h3>
<p>
Since a single patch may remediate multiple vulnerabilities,
organizers must select which patches to credit.
The selection algorithm identifies a minimal covering set: the
smallest number of patches that collectively fix all validated vulnerabilities.
When multiple patches cover the same vulnerability, specificity is preferred:
patches fixing fewer vulnerabilities are chosen over broader ones,
rewarding precise, targeted fixes. Patches not selected into this minimal set count as inaccurate.
</p>
<p>
To validate whether a patch truly remediates a vulnerability,
organizers use all PoVs submitted by all teams,
plus organizer-created ones, as test cases.
A patch must remediate every PoV targeting its claimed vulnerability to be considered valid.
This cross-team validation also reflects one collaboration approach among CRSs in practice.
</p>
</section>
"""


SECTION_SARIF_TECHNIQUES = """
<section id="sarif-techniques">
<h2>SARIF Validation Techniques<a class="anchor-link" href="#sarif-techniques">¶</a></h2>

<p>The table below summarizes how each finalist team validates broadcast SARIF reports.</p>

<div class="table-wrap"><table class="data">
<thead>
<tr>
  <th rowspan="2">Aspect</th>
  <th colspan="7" class="center">Teams (high → low score)</th>
</tr>
<tr>
  <th class="center">AT</th><th class="center">TB</th><th class="center">TI</th>
  <th class="center">FB</th><th class="center">SP</th><th class="center">42</th><th class="center">LC</th>
</tr>
</thead>
<tbody>
<tr>
  <td><strong>Validation Strategy — Category</strong></td>
  <td>PoV-centric</td><td>PoV-centric</td><td>Bug-cand-centric</td>
  <td>PoV-centric</td><td>LLM-judge-centric</td><td>LLM-judge-centric</td><td>LLM-judge-centric</td>
</tr>
<tr>
  <td><strong>Validation Strategy — Implementation<sup>*</sup></strong></td>
  <td>LLM-Based</td><td>Heuristic-Based</td><td>LLM-Based</td>
  <td>Heuristic-Based; LLM-Based</td><td>LLM-Based</td><td>LLM-Based</td><td>LLM-Based</td>
</tr>
<tr>
  <td><strong>Pre-validation Sanity Check<sup>†</sup></strong></td>
  <td>Format; File; Function; Line no.</td>
  <td>Format</td>
  <td>Format</td>
  <td>Format</td>
  <td>Format; File; Function</td>
  <td>File; Function; Line no.</td>
  <td>—</td>
</tr>
<tr>
  <td><strong>Used Inputs — SARIF Report</strong></td>
  <td>Full Report</td>
  <td>File; Function; StartLine; EndLine</td>
  <td>Function; File; Description; Rule</td>
  <td>File; StartLine; EndLine; Rule; Message</td>
  <td>Function; File; StartLine; Rule; Message</td>
  <td>Full Report</td>
  <td>Full Report</td>
</tr>
<tr>
  <td><strong>Used Inputs — PoV / Bug Cand Info</strong></td>
  <td>Crash Log; Patch Diff (if available)</td>
  <td>StackTrace (File; Function; Line)</td>
  <td>Function; File; Description; Condition</td>
  <td>Partial Crash Log (StackTrace; Error Message)</td>
  <td>N/A</td>
  <td>Crash Log</td>
  <td>N/A</td>
</tr>
<tr>
  <td><strong>Used Inputs — Code Context</strong></td>
  <td>Surrounding Context; Dynamic Retrieval<sup>‡</sup></td>
  <td>—</td>
  <td>—</td>
  <td>Enclosing Function</td>
  <td>Dynamic Retrieval</td>
  <td>Dynamic Retrieval</td>
  <td>Surrounding Context</td>
</tr>
</tbody>
</table></div>

<p class="footnotes">
<sup>*</sup> Heuristic-based follows developer-defined workflows; LLM-based relies on LLM queries.<br>
<sup>†</sup> Verifies SARIF report format and checks whether referenced artifacts (files, functions or lines) exist before main validation.<br>
<sup>‡</sup> Additional code context dynamically requested by LLM.
</p>
</section>
"""


SECTION_SUBMISSION_TIMING = """
<section id="submission-timing">
<h2>Submission Timing<a class="anchor-link" href="#submission-timing">¶</a></h2>

<p>
The figures below show per-team submission timing.
Most teams front-load within the first quarter, consistent with time-decay scoring.
SARIF is the fastest (avg 5.6%) as it triggers upon broadcast;
bundles are the latest (avg 35.8%) as they depend on prior submissions and are scored at the end.
<span class="cpv-name">Artiphishell</span> is a notable outlier, spreading submissions across the entire window.
</p>

<div class="figure-grid-2">
  <div class="figure">
    <img src="assets/figures/submission-timing-pov.png" alt="PoV submission timing">
    <p class="figure-caption"><span class="caption-label">(a) PoV.</span> n = 2519, avg = 25.0%</p>
  </div>
  <div class="figure">
    <img src="assets/figures/submission-timing-patch.png" alt="Patch submission timing">
    <p class="figure-caption"><span class="caption-label">(b) Patch.</span> n = 283, avg = 23.8%</p>
  </div>
  <div class="figure">
    <img src="assets/figures/submission-timing-sarif.png" alt="SARIF submission timing">
    <p class="figure-caption"><span class="caption-label">(c) SARIF.</span> n = 48, avg = 5.6%</p>
  </div>
  <div class="figure">
    <img src="assets/figures/submission-timing-bundle.png" alt="Bundle submission timing">
    <p class="figure-caption"><span class="caption-label">(d) Bundle.</span> n = 99, avg = 35.8%</p>
  </div>
</div>

<p class="footnotes">
Each task has a fixed time window (12h for full-mode, 6h for delta-mode);
0% is when the task opens, 100% is the deadline.
</p>
</section>
"""


SECTION_CWE_HEATMAPS = """
<section id="cwe-analysis">
<h2>CWE-Wise Performance Analysis<a class="anchor-link" href="#cwe-analysis">¶</a></h2>

<p>
The heatmaps below show CWE-wise team performance for PoV generation and patch generation, respectively.
</p>

<div class="callout">
<strong>Note.</strong>
0-day CPVs are excluded as they are still under procedural review
and do not yet have confirmed CWE classifications. The figures will be updated once available.
</div>

<div class="figure">
  <object data="assets/figures/cwe-pov-gen.svg" type="image/svg+xml" width="100%"></object>
  <p class="figure-caption"><span class="caption-label">Figure K1.</span>
  CWE-wise PoV generation performance heatmap.</p>
</div>

<div class="figure">
  <object data="assets/figures/cwe-patch-gen.svg" type="image/svg+xml" width="100%"></object>
  <p class="figure-caption"><span class="caption-label">Figure K2.</span>
  CWE-wise patch generation performance heatmap.</p>
</div>
</section>
"""


SECTION_HERO = """
<header class="hero">
  <h1>SoK: DARPA's AI Cyber Challenge (AIxCC) — Competition Design, Architectures, and Lessons Learned</h1>
  <p class="lead">
    Companion site for the AIxCC SoK study —
    a single entry point that compiles all of the study's references, artifacts,
    supplemental analysis, and the participating teams' public materials.
  </p>
  <p class="meta">
    <a href="https://www.usenix.org/system/files/usenixsecurity26-zhang-cen.pdf">Paper</a>
    <a class="pending" href="https://www.usenix.org/conference/usenixsecurity26/presentation/zhang-cen">Slides &amp; Video (coming soon)</a>
    <a href="assets/materials/aixcc-sok-poster.pdf">Poster</a>
    <a href="#open-science">SoK Artifact</a>
    <a href="#team-materials">Teams' Public References</a>
    <a href="#oss-crs-crsbench">OSS-CRS &amp; CRSBench</a>
    <a href="#scoring">Supplemental Analysis</a>
  </p>
</header>
"""


# ---------------------------------------------------------------------------
# Open Science section: team materials collection. Populated with what is
# already in p.bib + p.tex; extra slots are placeholders for blogs / posts to
# add later as they are released.
# ---------------------------------------------------------------------------
TEAMS = [
    {
        "key": "AT", "name": "Atlantis", "org": "Team Atlanta",
        "rank": "1st",
        "links": [
            ("CRS source code (GitHub: Team-Atlanta/aixcc-afc-atlantis)",
             "https://github.com/Team-Atlanta/aixcc-afc-atlantis"),
            ("ATLANTIS: AI-driven Threat Localization, Analysis, and Triage Intelligence System (arXiv 2509.14589)",
             "https://arxiv.org/abs/2509.14589"),
            ("Team Atlanta blog — technical write-ups on ATLANTIS internals",
             "https://team-atlanta.github.io/blog/"),
        ],
    },
    {
        "key": "TB", "name": "Buttercup", "org": "Trail of Bits",
        "rank": "2nd",
        "links": [
            ("CRS source code — AFC submission (GitHub: trailofbits/afc-buttercup)",
             "https://github.com/trailofbits/afc-buttercup"),
            ("CRS source code — continued development (GitHub: trailofbits/buttercup)",
             "https://github.com/trailofbits/buttercup"),
            ("Trail of Bits blog: AIxCC posts",
             "https://blog.trailofbits.com/categories/aixcc/"),
            ("DEF CON stage talk (slides PDF)",
             "https://www.trailofbits.com/documents/DEFCON_AIxCC_Stage_Talk.pdf"),
        ],
    },
    {
        "key": "TI", "name": "RoboDuck", "org": "Theori",
        "rank": "3rd",
        "links": [
            ("CRS source code (GitHub: theori-io/aixcc-afc-archive)",
             "https://github.com/theori-io/aixcc-afc-archive"),
            ("Theori AIxCC public materials (theori-io.github.io/aixcc-public)",
             "https://theori-io.github.io/aixcc-public/"),
            ("Branch Flipper: Unlocking Fuzz Blockers with Coverage-Grounded LLMs",
             "https://theori-io.github.io/aixcc-public/afc/Branch%20Flipper.pdf"),
            ("Theori company blog — AIxCC category",
             "https://theori.io/blog/category/aixcc"),
        ],
    },
    {
        "key": "FB", "name": "FuzzingBrain", "org": "FuzzingBrain",
        "rank": "4th",
        "links": [
            ("CRS source code (GitHub: fuzzingbrain/afc-crs-all-you-need-is-a-fuzzing-brain)",
             "https://github.com/fuzzingbrain/afc-crs-all-you-need-is-a-fuzzing-brain"),
            ("FuzzingBrain project page",
             "https://fuzzingbrain.github.io/"),
            ("All You Need Is a Fuzzing Brain (CRS whitepaper, arXiv 2509.07225)",
             "https://arxiv.org/abs/2509.07225"),
            ("FuzzingBrain v2 — post-competition whitepaper (arXiv 2605.21779)",
             "https://arxiv.org/abs/2605.21779"),
        ],
    },
    {
        "key": "SP", "name": "Artiphishell", "org": "Shellphish",
        "rank": "5th",
        "links": [
            ("CRS source code (GitHub: shellphish/artiphishell)",
             "https://github.com/shellphish/artiphishell"),
            ("Shellphish × AIxCC Post-Mortem",
             "https://support.shellphish.net/blog/2025/08/22/shellphish-x-aixcc-pm/"),
        ],
    },
    {
        "key": "42", "name": "BugBuster", "org": "42-b3yond-6ug",
        "rank": "6th",
        "links": [
            ("CRS source code (GitHub: 42-b3yond-6ug/42-b3yond-6ug-crs)",
             "https://github.com/42-b3yond-6ug/42-b3yond-6ug-crs"),
            ("42-b3yond-6ug blog (b3yond.org/crs)",
             "https://b3yond.org/crs"),
            ("Two-year AIxCC recap by lkmidas",
             "https://lkmidas.github.io/posts/20250808-aixcc-recap/"),
            ("42-b3yond-6ug Open Letter (Google Doc)",
             "https://docs.google.com/document/d/1-1TexnOwQGj2KJ8rrLtk-Vgl-PqO5MZe7k0qrHQPC_0/"),
        ],
    },
    {
        "key": "LC", "name": "Lacrosse", "org": "Lacrosse",
        "rank": "7th",
        "links": [
            ("CRS source code (GitHub: siftech/afc-crs-lacrosse)",
             "https://github.com/siftech/afc-crs-lacrosse"),
        ],
    },
]


def render_open_science() -> str:
    blocks = []
    for t in TEAMS:
        links_html = []
        if t["links"]:
            for label, url in t["links"]:
                links_html.append(f'<li><a href="{esc(url)}">{esc(label)}</a></li>')
        else:
            links_html.append(
                '<li class="placeholder">No public blog or post available yet.</li>'
            )
        blocks.append(
            f'<div class="team-entry">'
            f'  <h4 class="team-name">'
            f'    <code>{esc(t["key"])}</code> '
            f'    <span class="team-name-text">{esc(t["name"])}</span> '
            f'    <span class="team-org">— {esc(t["org"])}</span>'
            f'  </h4>'
            f'  <ul class="team-links">{"".join(links_html)}</ul>'
            f'</div>'
        )
    cards_html = "\n".join(blocks)
    return f"""
<section id="open-science">
<h2><span class="appendix-tag">Open Science</span>SoK Artifact<a class="anchor-link" href="#open-science">¶</a></h2>

<p>
Some materials respect DARPA's official release timeline and are not yet public.
</p>

<h3>Currently available</h3>
<ul>
  <li>Questionnaires, meeting notes, sanitized experiment data (PF / MR / CC), and analysis scripts —
      Zenodo bundle at <a href="https://zenodo.org/records/20367274">zenodo.org/records/20367274</a>.</li>
  <li>AIxCC Final Challenge Set, official release at
      <a href="https://archive.aicyberchallenge.com/challenges/">archive.aicyberchallenge.com/challenges</a>.</li>
</ul>

<h3>Pending release</h3>
<ul>
  <li>Raw competition data (submission logs, OTEL traces, scoring breakdowns).</li>
  <li><strong>CRUMBS</strong> — the organizers' competition data analysis framework.</li>
</ul>
</section>

<section id="team-materials">
<h2><span class="appendix-tag">Open Science</span>Collection of Teams' Public References<a class="anchor-link" href="#team-materials">¶</a></h2>

<div class="team-list">
{cards_html}
</div>
</section>

<section id="oss-crs-crsbench">
<h2><span class="appendix-tag">Open Science</span>OSS-CRS &amp; CRSBench<a class="anchor-link" href="#oss-crs-crsbench">¶</a></h2>

<h3>OSS-CRS</h3>
<p>
OpenSSF CRS orchestration platform which integrates the bug-finding and
patch components from every AIxCC finalist CRS into a single open-source
pipeline.
</p>
<ul>
  <li>Official website: <a href="https://oss-crs.openssf.org/">oss-crs.openssf.org</a></li>
  <li>GitHub: <a href="https://github.com/ossf/oss-crs">ossf/oss-crs</a></li>
</ul>

<h3>CRSBench</h3>
<p>
The matching benchmark suite for OSS-CRS, bundling the AIxCC Final
Challenge Set, the AIxCC Exhibition Round challenge set, and Team
Atlanta's n-day-derived challenges.
</p>
<ul>
  <li>Official website: <a href="https://oss-crs.openssf.org/crsbench">oss-crs.openssf.org/crsbench</a></li>
  <li>GitHub: <a href="https://github.com/sslab-gatech/CRSBench">sslab-gatech/CRSBench</a></li>
  <li>HuggingFace dataset: <a href="https://huggingface.co/datasets/sslab-gatech/crsbench-dataset">sslab-gatech/crsbench-dataset</a></li>
</ul>
</section>
"""


# ---------------------------------------------------------------------------
# Top-level page assembly
# ---------------------------------------------------------------------------
NAV_ITEMS = [
    ("nav-label", "Open Science", []),
    ("link", "SoK Artifact", "#open-science"),
    ("link", "Collection of Teams' Public References", "#team-materials"),
    ("link", "OSS-CRS & CRSBench", "#oss-crs-crsbench"),
    ("nav-label", "Supplemental Analysis", []),
    ("link", "Scoring Rules Explanation", "#scoring"),
    ("link", "Challenge Project (CP) Details", "#cp-details"),
    ("link", "Challenge Project Vulnerability (CPV) Details", "#cpv-details"),
    ("link", "SARIF Validation Techniques", "#sarif-techniques"),
    ("link", "SARIF Broadcast Details", "#sarif-broadcasts"),
    ("link", "0-Day Details", "#zeroday-details"),
    ("link", "Token Consumption", "#token-consumption"),
    ("link", "Submission Timing", "#submission-timing"),
    ("link", "CWE-Wise Performance", "#cwe-analysis"),
]


def render_nav() -> str:
    parts = []
    parts.append('<nav><ol>')
    for kind, *rest in NAV_ITEMS:
        if kind == "nav-label":
            label = rest[0]
            parts.append(f'<li class="nav-section-label">{label}</li>')
        else:
            label, href = rest
            parts.append(f'<li><a href="{href}">{label}</a></li>')
    parts.append("</ol></nav>")
    return "\n".join(parts)


def asset_hash(path: Path) -> str:
    """8-char hash for cache-busting query strings."""
    return hashlib.md5(path.read_bytes()).hexdigest()[:8]


def render_page() -> str:
    cp_rows    = read_csv(DATA["cp"])
    cpv_rows   = read_csv(DATA["cpv"])
    zd_rows    = read_csv(DATA["zd"])
    sarif_rows = read_csv(DATA["sarif"])

    css_ver = asset_hash(SITE / "css" / "style.css")
    js_ver  = asset_hash(SITE / "js"  / "main.js")

    # Mirror bin/csv2latex.py ordering exactly:
    #   - cpvs / zerodays: language first (C before Java), then sort_order
    #   - sarif broadcasts: by sort_order only (global, no language group)
    def lang_then_order(r):
        return (0 if r.get("language") == "C" else 1,
                int(r.get("sort_order", 0) or 0))

    def order_only(r):
        return int(r.get("sort_order", 0) or 0)

    cpv_rows.sort(key=lang_then_order)
    zd_rows.sort(key=lang_then_order)
    sarif_rows.sort(key=order_only)

    cp_table    = render_cp_table(cp_rows)
    cpv_table   = render_cpv_table(cpv_rows)
    zd_table    = render_zd_table(zd_rows)
    sarif_table = render_sarif_table(sarif_rows)

    sections = [
        SECTION_HERO,
        render_open_science(),
        # New supplemental-analysis order (per user spec):
        SECTION_SCORING,                                # 1
        f"""                                            <!-- 2 -->
<section id="cp-details">
<h2>Challenge Project (CP) Details<a class="anchor-link" href="#cp-details">¶</a></h2>

<p>
Detailed information about each Challenge Project (CP) in the AIxCC final round.
</p>

{cp_table}
</section>
""",
        f"""                                            <!-- 3 -->
<section id="cpv-details">
<h2>Challenge Project Vulnerability (CPV) Details<a class="anchor-link" href="#cpv-details">¶</a></h2>

<p>
Detailed information about each Challenge Project Vulnerability (CPV) in the AIxCC final round.
</p>

{cpv_table}
</section>
""",
        SECTION_SARIF_TECHNIQUES,                       # 4
        f"""                                            <!-- 5 -->
<section id="sarif-broadcasts">
<h2>SARIF Broadcast Details<a class="anchor-link" href="#sarif-broadcasts">¶</a></h2>

<p>
Detailed information about each SARIF broadcast in the AIxCC final round.
</p>

{sarif_table}
</section>
""",
        f"""                                            <!-- 6 -->
<section id="zeroday-details">
<h2>0-Day Details<a class="anchor-link" href="#zeroday-details">¶</a></h2>

<p>
Detailed information about 0-day vulnerabilities discovered during the competition.
</p>

{zd_table}
</section>
""",
        SECTION_TOKEN,                                  # 7
        SECTION_SUBMISSION_TIMING,                      # 8
        SECTION_CWE_HEATMAPS,                           # 9
    ]

    body = "\n".join(sections)
    nav  = render_nav()

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AIxCC SoK — Companion Site</title>
<meta name="description" content="Companion site for the AIxCC SoK study — references, artifacts, supplemental analysis, and the finalist teams' public materials.">
<link rel="stylesheet" href="css/style.css?v={css_ver}">  <!-- v={css_ver} -->
<script>
window.MathJax = {{
  tex: {{ inlineMath: [['\\\\(', '\\\\)']], displayMath: [['\\\\[', '\\\\]']] }},
  options: {{ skipHtmlTags: ['script','noscript','style','textarea','pre','code'] }},
  startup: {{ typeset: true }}
}};
</script>
<script async src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js"></script>
</head>
<body>
<div class="layout">
  <aside class="sidebar" id="toc">
    <h1><a href="#top">AIxCC SoK<br><span style="font-weight:500">Companion Site</span></a></h1>
    {nav}
  </aside>
  <div class="toc-backdrop" aria-hidden="true"></div>
  <button class="toc-toggle" type="button" aria-label="Open table of contents" aria-controls="toc" aria-expanded="false">☰</button>
  <main class="content" id="top">
{body}
  </main>
</div>
<script src="js/main.js?v={js_ver}"></script>
</body>
</html>
"""


def main() -> None:
    out = SITE / "index.html"
    out.write_text(render_page())
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
