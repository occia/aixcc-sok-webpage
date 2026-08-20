# AIxCC SoK — Companion Website

Static companion site for the USENIX Security '26 paper
*SoK: DARPA's AI Cyber Challenge (AIxCC) — Competition Design, Architectures, and Lessons Learned*.

Hosts the appendix sections that don't fit in the 20-page paper limit,
plus an open-science index of finalist team materials.


## Quick start

```bash
# Local preview
python3 -m http.server 8765      # then open http://localhost:8765/

# Regenerate index.html after the source CSVs change
../.venv/bin/python build.py
```

The site is fully static — no build step is required for hosting.
`build.py` exists only so the tables stay in sync with the paper's data files.


## File map

```
site/
├── index.html              # generated; the entire site
├── build.py                # regenerates index.html from the paper's CSVs
├── css/style.css           # all styling
├── js/main.js              # ~50 lines: scroll-spy + mobile TOC drawer
├── assets/materials/       # paper presentation materials hosted by the site
│   └── aixcc-sok-poster.pdf
├── assets/figures/         # PNG + SVG copies of paper figures
│   ├── model_usage_by_team.png
│   ├── io_token_ratio_by_model_team.png
│   ├── submission-timing-{pov,patch,sarif,bundle}.png
│   └── cwe-{pov,patch}-gen.svg
├── .gitignore              # OS / editor / Python noise only
└── README.md               # this file
```


## How content is produced

`index.html` is **generated**, not hand-edited.
`build.py` reads four CSV files from the paper repo and assembles every
table in the appendix:

| CSV path (repo root) | Renders into |
|---|---|
| `tbl/cp_details/appendix_cp.csv`            | Appendix F (CP Details)    |
| `tbl/vuln_sarif_details/cpvs.csv`           | Appendix G (CPV Details)   |
| `tbl/vuln_sarif_details/zerodays.csv`       | Appendix H (0-Day Details) |
| `tbl/vuln_sarif_details/sarif_broadcasts.csv` | Appendix I (SARIF Broadcasts) |

Text-only sections (C Token, D Scoring, E SARIF techniques, J Submission
Timing, K CWE heatmaps, Open Science) live as plain string literals
inside `build.py` — search for `SECTION_*` to find them.

The generator mirrors the exact column schemas used by
`bin/csv2latex.py` in the paper repo. If the LaTeX tables change, mirror
the column changes in `build.py` so the website stays consistent with
the published PDF.


## Section structure (must match paper)

| Site appendix | Columns / content                                   |
|---|---|
| C  Token Consumption     | 2 figures (model usage, I/O ratio)              |
| D  Scoring Details       | prose + 5 formulas (MathJax)                    |
| E  SARIF Techniques      | 6-row × 7-team matrix                           |
| F  CP Details            | Lang, Project, Category, #Harn, CP, #CPVs, CWEs, SLOC, Commit, Cutoff, ΔLines, ΔFiles, Build, Harn.Size |
| G  CPV Details           | Lang, Ph, Project, ID, Vuln, CWE, CWE Name (multi-CWE → multi-row) |
| H  0-Day Details         | Lang, Ph, Project, ID, Description              |
| I  SARIF Broadcasts      | Ph, Project, Lang, Label, Answer                |
| J  Submission Timing     | 4 figures (PoV / Patch / SARIF / Bundle)        |
| K  CWE-Wise Performance  | 2 SVG heatmaps                                  |

`build.py` reproduces the 0-day "Description" column with the same
`extract_error_type()` mapping the LaTeX generator uses (UBSan / ASan /
StackOverflowError / OutOfMemoryError / etc).


## Open-science / team-materials section

Curated by hand in `build.py` → `TEAMS` list near the top.
Each entry is `(key, name, org, rank, links=[(label, url), ...])`.
Teams with no public material yet display a placeholder line — update
them as new blogs / postmortems come out.


## Layout architecture (CSS notes)

`css/style.css` is intentionally one flat file. Key invariants:

* **Fixed sidebar at left** (`position: fixed`, `z-index: 30`).
  `main.content { margin-left: var(--sidebar-width) }` gives the
  content area the right gutter.
  **Don't** set `width: 100%` on `main.content` — combined with the
  margin it would push the box past the viewport.

* **Never use the `margin: a b c` shorthand on centered blocks.**
  `margin: 1rem 0` looks like "vertical only" but it expands to
  `margin: 1rem 0 1rem 0` — **left/right are set to 0**, silently
  defeating `margin-left/right: auto`. Always write `margin-block: 1rem`
  for vertical-only spacing on any element that should be centered.
  This bug has been re-introduced at least three times during
  development — guard against it in code review.

* **Unified content column** — every block-level child of `<section>`
  shares the same `max-width: 1300px` and `margin-inline: auto`. Prose,
  titles, tables, formulas all align to the same left/right edges at
  every viewport.

* **Figures are the one exception** — capped at `max-width: 900px`
  (close to the intrinsic resolution of the PDF→PNG conversions at
  200 DPI). They still shrink fluidly when the viewport is narrower;
  they just stop growing past 900px on wide monitors so PNG/SVG don't
  render pixelated or sparse. The figure container is still centered
  inside the broader 1300px column.

* **Z-index layering** (mobile drawer):
  ```
  toggle button   40   ← always on top
  sidebar         30   ← above backdrop so TOC is clickable + bright
  backdrop        20   ← dims content only
  content       (auto)
  ```
  If you change `aside.sidebar` or `.toc-backdrop` z-index, keep
  `sidebar > backdrop` or the TOC will look dimmed and clicks will be
  intercepted.

* **Responsive breakpoints**:
  - `>1000px`: sidebar fixed at left
  - `≤1000px`: sidebar slides in from left, opened by a floating ☰
    button at bottom-right (`.toc-toggle`)
  - `≤640px`: smaller table fonts, tighter padding

* **Cache busting**: `index.html` links to
  `css/style.css?v=<md5-hash>` and `js/main.js?v=<md5-hash>`. The hash
  is recomputed every time `build.py` runs, so changes propagate to
  users on the next normal refresh — no need for hard refresh.


## JS behaviour (`js/main.js`)

Two small IIFEs:

1. **TOC drawer toggle** — opens / closes `body.toc-open` from the
   floating ☰ button. Closes on backdrop click, ESC, or link click.
2. **Scroll-spy** — adds `.active` to the sidebar link matching the
   currently visible section (uses `IntersectionObserver`).


## Deploying to GitHub Pages

Two options:

1. **Move `site/` into its own repo** (cleanest):
   ```bash
   # in a new empty repo
   cp -r /path/to/site/{index.html,css,js,assets,.gitignore,README.md} .
   git add -A && git commit -m "Initial publish" && git push
   # Repo Settings → Pages → Source: main / (root)
   ```
   Note: drop the `site/` directory level so `index.html` is at the repo
   root. `build.py` doesn't need to be deployed (only used locally), but
   nothing breaks if you include it.

2. **Keep `site/` as a subdir of the paper repo**:
   ```
   Settings → Pages → Source: main / /site
   ```
   The site will be served from `https://<user>.github.io/aixcc-sok/`.

After deploying, update `p.bib` in the paper repo: replace
`\TODO{add website URL}` in the `@misc{sok-website,...}` entry with
the real URL. Also update the placeholder `https://example.com/aixcc-sok.pdf`
in `build.py` (search for "TODO") to the published paper URL.


## Common edits

| Change | File | Rebuild? |
|---|---|---|
| Table data (CPVs, 0-days, CP, SARIF) | `tbl/*.csv` in paper repo | `python build.py` |
| Text in C / D / E / J / K sections   | `build.py` (`SECTION_*` strings) | `python build.py` |
| Team links / blog list                | `build.py` (`TEAMS = [...]`)     | `python build.py` |
| Styling / layout                      | `css/style.css` | no rebuild needed; just bump cache by rerunning `build.py` so `?v=` hash refreshes |
| Drawer / scroll-spy JS                | `js/main.js`    | no rebuild; same caveat |


## Known limitations

* MathJax is loaded from `cdn.jsdelivr.net`. Offline viewers won't see
  rendered formulas. To fully self-host, drop a copy of `mathjax@3` into
  `assets/mathjax/` and point the `<script src=…>` at it.

* `assets/figures/*.png` are PDF→PNG conversions at 200 DPI. If the
  paper figures change, regenerate via `pdftoppm -png -r 200 fig/X.pdf
  assets/figures/X -singlefile` (the SVGs are copied straight from
  `fig/*.svg`).

* `build.py` reads CSVs by relative path (`../tbl/...`), so it has to
  run from inside `site/` while the paper repo is the parent. If you
  detach `site/` into its own repo, either commit the generated
  `index.html` and stop running `build.py`, or copy / symlink the four
  CSVs into the new repo.
