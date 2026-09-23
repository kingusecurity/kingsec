# Third-Party Licenses

This document lists every package KingSec's **runtime** — the deployed
product, not the development toolchain — actually depends on, with its
license, across both ecosystems the product ships in: the Python backend
and the React frontend.

**Scope and methodology, stated precisely:**
- **Python backend:** scanned from a *clean* virtual environment built
  with `pip install .` against `pyproject.toml`'s `[project.dependencies]`
  only — no `[dev]` extras (ruff, mypy, pytest, pip-licenses,
  cyclonedx-py, etc. are excluded; they never ship). **51 packages**
  (50 third-party + KingSec itself), generated with `pip-licenses` against
  that clean environment.
- **React frontend:** scanned from `frontend/package.json`'s production
  `dependencies` only (`npm ls --omit dev` / `cyclonedx-npm --omit dev`)
  — devDependencies (build tooling, test frameworks, linters, the SBOM
  generator itself) are excluded; they never ship in the built bundle.
  **64 packages.**
- **The real surface is larger than what ships.** The frontend's full
  dependency tree, including devDependencies, is **439 packages** — the
  production subset above (64) is the honest "what actually ships"
  number; 439 is reported here so the difference isn't hidden. The
  gap is almost entirely build tooling (Vite, TypeScript, Vitest,
  Playwright, oxlint, and their own transitive trees).
- Both scans are the direct source for `sbom.cdx.json` (repo root) — the
  same 51 + 64 = **115 components**, not a separately-curated list that
  could drift from the SBOM.

**No copyleft in what KingSec redistributes**, with one specific,
correctly-scoped exception — see "Copyleft and weak-copyleft packages,"
below, before assuming a blanket "all clear."

---

## Copyleft and weak-copyleft packages — read this first

| Package | Ecosystem | License | Where it comes from | Assessment |
|---|---|---|---|---|
| `pyphen` 0.18.1 | pypi | GPLv2+ **OR** LGPLv2+ **OR** MPL-1.1 (recipient's choice) | Transitive dependency of `weasyprint` (PDF report rendering — hyphenation) | **Multi-licensed, not GPL-only.** `pyphen` offers three license options; a recipient may elect to use it under **LGPLv2+** or **MPL-1.1** instead of GPL. Both of those options are compatible with inclusion in a proprietary product without triggering copyleft obligations on KingSec's own code (LGPL's copyleft applies only to `pyphen` itself, not to code that merely links/imports it; MPL-1.1's copyleft applies only to modified MPL-covered files). **No blocking issue, provided the LGPLv2+ or MPL-1.1 option is the one relied upon** — do not represent `pyphen`'s inclusion as being under GPL terms. |
| `certifi` 2026.7.22 | pypi | MPL-2.0 | Direct transitive dependency (`httpx` → `certifi`, CA bundle) | **Weak copyleft, low risk.** MPL-2.0's copyleft is file-level: it only requires source disclosure for files that are themselves modified. KingSec does not modify `certifi`. No obligation triggered by using it as-is. |

**Everything else (49 of 51 Python packages, all 64 npm packages) is
permissive** (MIT, BSD-2/3-Clause, Apache-2.0, ISC, 0BSD, PSF-2.0,
MIT-0, MIT AND PSF-2.0, MIT OR Apache-2.0, OFL-1.1 for the two bundled
web fonts) — no copyleft obligations at all.

**This is the report the CI license gate's allowlist is written against —
see below.** `pyphen` and `certifi` are both allowed explicitly, with the
reasoning above, not silently permitted by an overly broad rule.

---

## Python backend (51 packages, runtime only)

Generated with `pip-licenses` against a clean `pip install .` environment
(no dev extras). Sorted by license, then name.

| Package | Version | License |
|---|---|---|
| zopfli | 0.4.3 | Apache Software License |
| python-multipart | 0.0.32 | Apache-2.0 |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause |
| cssselect2 | 0.10.1 | BSD License |
| httpx | 0.28.1 | BSD License |
| pydyf | 0.12.1 | BSD License |
| reportlab | 5.0.1 | BSD License |
| tinycss2 | 1.5.1 | BSD License |
| weasyprint | 69.0 | BSD License |
| webencodings | 0.6.1 | BSD License |
| MarkupSafe | 3.0.3 | BSD-3-Clause |
| click | 8.5.0 | BSD-3-Clause |
| httpcore | 1.0.9 | BSD-3-Clause |
| idna | 3.20 | BSD-3-Clause |
| pycparser | 3.0 | BSD-3-Clause |
| python-dotenv | 1.2.3 | BSD-3-Clause |
| starlette | 1.7.0 | BSD-3-Clause |
| uvicorn | 0.53.0 | BSD-3-Clause |
| websockets | 17.1 | BSD-3-Clause |
| **pyphen** | **0.18.1** | **GPLv2+ / LGPLv2+ / MPL-1.1 — see Copyleft section above** |
| Mako | 1.4.3 | MIT |
| PyJWT | 2.14.0 | MIT |
| SQLAlchemy | 2.0.54 | MIT |
| alembic | 1.20.0 | MIT |
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| argon2-cffi | 25.1.0 | MIT |
| argon2-cffi-bindings | 26.1.0 | MIT |
| brotli | 1.2.0 | MIT |
| charset-normalizer | 3.5.1 | MIT |
| fastapi | 0.141.1 | MIT |
| fonttools | 4.65.0 | MIT |
| httptools | 0.8.0 | MIT |
| pydantic | 2.13.5 | MIT |
| pydantic-settings | 2.15.0 | MIT |
| pydantic_core | 2.46.5 | MIT |
| typing-inspection | 0.4.4 | MIT |
| greenlet | 3.5.6 | MIT AND PSF-2.0 |
| PyYAML | 6.0.3 | MIT License |
| h11 | 0.16.0 | MIT License |
| tinyhtml5 | 2.1.0 | MIT License |
| watchfiles | 1.3.0 | MIT License |
| structlog | 26.1.0 | MIT OR Apache-2.0 |
| cffi | 2.1.1 | MIT-0 |
| pillow | 12.3.0 | MIT-CMU |
| **certifi** | **2026.7.22** | **MPL-2.0 — see Copyleft section above** |
| typing_extensions | 4.16.0 | PSF-2.0 |
| defusedxml | 0.7.1 | Python Software Foundation License |
| kingsec | 2.0.0 | Proprietary (this project) |

---

## React frontend (64 packages, production only)

Generated with `@cyclonedx/cyclonedx-npm --omit dev` against
`frontend/package.json`. Sorted by license, then name. Scoped package
names are given in full (e.g. `@hookform/resolvers`, not `resolvers`).

| Package | Version | License |
|---|---|---|
| tslib | 2.8.1 | 0BSD |
| class-variance-authority | 0.7.1 | Apache-2.0 |
| d3-ease | 3.0.1 | BSD-3-Clause |
| d3-array | 3.2.4 | ISC |
| d3-color | 3.1.0 | ISC |
| d3-format | 3.1.2 | ISC |
| d3-interpolate | 3.0.1 | ISC |
| d3-path | 3.1.0 | ISC |
| d3-scale | 4.0.2 | ISC |
| d3-shape | 3.2.0 | ISC |
| d3-time | 3.1.0 | ISC |
| d3-time-format | 4.1.0 | ISC |
| d3-timer | 3.0.1 | ISC |
| internmap | 2.0.3 | ISC |
| lucide-react | 1.26.0 | ISC |
| @hookform/resolvers | 5.4.0 | MIT |
| @reduxjs/toolkit | 2.12.0 | MIT |
| @remix-run/router | 1.23.3 | MIT |
| @standard-schema/spec | 1.1.0 | MIT |
| @standard-schema/utils | 0.3.0 | MIT |
| @tanstack/query-core | 5.101.4 | MIT |
| @tanstack/react-query | 5.101.4 | MIT |
| @tanstack/react-table | 8.21.3 | MIT |
| @tanstack/table-core | 8.21.3 | MIT |
| @types/d3-array | 3.2.2 | MIT |
| @types/d3-color | 3.1.3 | MIT |
| @types/d3-ease | 3.0.2 | MIT |
| @types/d3-interpolate | 3.0.4 | MIT |
| @types/d3-path | 3.1.1 | MIT |
| @types/d3-scale | 4.0.9 | MIT |
| @types/d3-shape | 3.1.8 | MIT |
| @types/d3-time | 3.0.4 | MIT |
| @types/d3-timer | 3.0.2 | MIT |
| @types/react | 19.2.17 | MIT |
| @types/use-sync-external-store | 0.0.6 | MIT |
| clsx | 2.1.1 | MIT |
| csstype | 3.2.3 | MIT |
| decimal.js-light | 2.5.1 | MIT |
| es-toolkit | 1.50.0 | MIT |
| eventemitter3 | 5.0.4 | MIT |
| framer-motion | 12.42.2 | MIT |
| immer | 11.1.15 | MIT |
| motion-dom | 12.42.2 | MIT |
| motion-utils | 12.39.0 | MIT |
| react | 19.2.7 | MIT |
| react-dom | 19.2.7 | MIT |
| react-hook-form | 7.82.0 | MIT |
| react-is | 19.2.8 | MIT |
| react-redux | 9.3.0 | MIT |
| react-router | 6.30.4 | MIT |
| react-router-dom | 6.30.4 | MIT |
| recharts | 3.10.0 | MIT |
| redux | 5.0.1 | MIT |
| redux-thunk | 3.1.0 | MIT |
| reselect | 5.2.0 | MIT |
| scheduler | 0.27.0 | MIT |
| tailwind-merge | 3.6.0 | MIT |
| tiny-invariant | 1.3.3 | MIT |
| use-sync-external-store | 1.6.0 | MIT |
| zod | 4.4.3 | MIT |
| zustand | 5.0.14 | MIT |
| victory-vendor | 37.3.6 | MIT AND ISC |
| @fontsource-variable/inter | 5.3.0 | OFL-1.1 |
| @fontsource-variable/jetbrains-mono | 5.3.0 | OFL-1.1 |

No GPL, LGPL, or AGPL packages in the frontend's production dependency
tree.

---

## External scanner binaries — documented separately

KingSec shells out to six external scanner binaries (Nmap, Nuclei,
Nikto, FFUF, Gobuster, OWASP ZAP) as operator-installed, arm's-length
subprocesses — **none are redistributed, bundled, or vendored** by
KingSec itself. Their individual licenses (including nmap's NPSL, which
carries an open "needs legal review" item, and nikto's GPLv3 code +
separately-licensed database files) are analyzed in full in
[`docs/LICENSING-RISK.md`](LICENSING-RISK.md) — that document is the
source of truth for scanner-binary licensing; it is deliberately kept
separate from this dependency list because the redistribution/use
analysis for an externally-invoked binary is a different kind of
question than "what license covers a package this build links against."

---

## SBOM

A machine-readable CycloneDX 1.6 SBOM covering both ecosystems above —
the same 51 Python + 64 npm = 115 components, generated by the same
scans this document is built from — is committed at
[`sbom.cdx.json`](../sbom.cdx.json) (repo root). It validates cleanly
against the CycloneDX 1.6 JSON schema (`cyclonedx-python-lib`'s
`JsonStrictValidator`, run this phase — zero validation errors).

## Dev-time tooling used to produce this document

These are **development dependencies only** — they generate this report
and the SBOM; none of them ship in the product. Pinned to exact versions
for reproducibility of this specific audit, recorded here rather than as
a permanent runtime or even always-on dev dependency, since they're
invoked occasionally (this audit, and future re-audits), not on every
build:

| Tool | Version | Purpose |
|---|---|---|
| `pip-licenses` | 5.5.5 | Python dependency license table |
| `cyclonedx-py` | 1.0.1 (pulls in `cyclonedx-bom` 7.4.0) | Python CycloneDX SBOM generation |
| `@cyclonedx/cyclonedx-npm` | 6.0.1 | npm CycloneDX SBOM generation (chosen over a plain license-checker specifically so both ecosystems produce CycloneDX and merge into one document) |

`pip-licenses` and `cyclonedx-py` were installed into the project's main
venv for this audit (not added to `[project.optional-dependencies].dev`
— they're audit-time tools, not needed for every `pip install -e ".[dev]"`).
`@cyclonedx/cyclonedx-npm` **is** pinned as an exact-version entry in
`frontend/package.json`'s `devDependencies`, since the CI license gate
(below) needs to regenerate the npm SBOM on every run.

## Re-generating this report

```bash
# Python (from a clean, dev-extras-free venv):
python -m venv .sbom-runtime-venv
.sbom-runtime-venv/Scripts/pip install .   # or bin/pip on Linux/macOS
python -m piplicenses --python .sbom-runtime-venv/Scripts/python.exe --format=markdown
python -m cyclonedx_py environment --spec-version 1.6 .sbom-runtime-venv -o sbom-python.json

# npm (production dependencies only):
cd frontend
npx @cyclonedx/cyclonedx-npm --omit dev --spec-version 1.6 -o ../sbom-npm.json
```

The merge into `sbom.cdx.json` is a small, direct concatenation of both
`components` arrays (each tagged with a `kingsec:ecosystem` property) and
`dependencies` graphs under one `kingsec-app` root component — not
scripted as a repo tool today, since this document is refreshed
periodically, not on every build. If re-audits become routine, promoting
that merge step to a checked-in script is a reasonable next step.
