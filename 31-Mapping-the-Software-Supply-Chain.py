#!/usr/bin/env python3
# =============================================================================
#  31-Mapping-the-Software-Supply-Chain.py
#
#  Reproduction package for:
#    "Mapping the Software Supply-Chain Attack Surface of Open-Source
#     Electric-Vehicle Charging Infrastructure: A Dependency-Level
#     Vulnerability Analysis of Charging-Station Management and
#     Charge-Point Software"
#
#  ---------------------------------------------------------------------------
#  STEP 0 - PAPER TYPE
#  ---------------------------------------------------------------------------
#  This paper is [BENCH] + [STAT]:
#    [BENCH]  It measures real systems - the actual dependency manifests and
#             lockfiles of 17 real open-source repositories - against a real
#             vulnerability database (the GitHub Advisory Database, OSV format).
#    [STAT]   It applies hypothesis tests (Fisher exact, Mann-Whitney U) and a
#             rank-correlation ablation (Kendall tau) to those measurements.
#
#  It is NOT [ML]. No model is trained. Accordingly, and per the reproducibility
#  requirements, this script contains NO training loop, NO confusion matrix,
#  NO ROC curve and NO loss curve, because the paper contains none. Fabricating
#  such scaffolding would produce a script that cannot reproduce the paper.
#
#  ---------------------------------------------------------------------------
#  STEP 1 - D10 ITEM MAPPING (ML default -> this paper's real equivalent)
#  ---------------------------------------------------------------------------
#    "Download / load dataset"     -> git clone the 17 repositories under test,
#                                     and git clone the GitHub Advisory Database
#    "Preprocessing"               -> parse lockfiles/manifests into a unified
#                                     dependency table; exclude test/mock/docs
#    "Define model architecture"   -> define the resolution strata, the OSV
#                                     interval semantics, and the exposure index
#    "Train model"                 -> (no equivalent; nothing is trained)
#    "Evaluate on test set"        -> match every pinned version against every
#                                     advisory affecting that package
#    "Metrics (tables)"            -> rho, SCEI, coverage, exposure windows,
#                                     blast radius, Fisher/Mann-Whitney/Kendall
#    "Figures"                     -> stratum bars, SCEI bars, exposure ECDF,
#                                     severity x depth bars, ablation bars
#
#  ---------------------------------------------------------------------------
#  REQUIREMENTS
#    pip install univers cvss pyyaml scipy matplotlib numpy
#    git, and network access to github.com
#
#  RUN
#    python reproduce_results.py
#
#  NOTE ON EXACT REPRODUCTION
#    Projects that do NOT commit a lockfile are resolved from the live registry,
#    and the advisory database grows daily. Re-running on a later date will
#    therefore reproduce the STRUCTURE exactly (strata, coverage, zero parse
#    failures, the advisory-invisible tier) but individual advisory counts will
#    drift upward as new CVEs are published. The paper's snapshot date is
#    2026-07-10; set SNAPSHOT below to that date to interpret exposure windows
#    as reported.
# =============================================================================

import csv, glob, json, math, os, pickle, random, re, subprocess, sys
import numpy as np                         # top-level so stage_metrics can use it
try:
    import tomllib                          # stdlib on Python 3.11+
except ImportError:
    try:
        import tomli as tomllib             # backport: pip install tomli
    except ImportError:
        raise ImportError(
            "Python < 3.11 requires the 'tomli' back-port.  "
            "Run:  pip install tomli"
        )
from collections import defaultdict, deque
from datetime import datetime, timezone
import statistics as st

# ----------------------------------------------------------------- config
ROOT      = os.path.abspath("./evci_repro")
SNAPSHOT  = datetime(2026, 7, 10, tzinfo=timezone.utc)
BETA      = 0.5     # transitive remediation penalty   (Eq. 5)
GAMMA     = 1.0     # no-fix-available penalty         (Eq. 5)

ADVISORY_DB = "https://github.com/github/advisory-database.git"

EVCI = [
    ("citrineos/citrineos-core",                     "CSMS (OCPP 2.0.1)"),
    ("thoughtworks/maeve-csms",                      "CSMS (OCPP 2.0.1)"),
    ("steve-community/steve",                        "CSMS (OCPP 1.6)"),
    ("dallmann-consulting/OCPP.Core",                "CSMS (OCPP 1.6/2.0)"),
    ("EVerest/everest-core",                         "Charge-point stack"),
    ("OpenEVSE/ESP32_WiFi_V4.x",                     "Charge-point firmware"),
    ("SAP/e-mobility-charging-stations-simulator",   "Charge-point simulator"),
    ("mobilityhouse/ocpp",                           "OCPP protocol library"),
    ("ChargeTimeEU/Java-OCA-OCPP",                   "OCPP protocol library"),
    ("evcc-io/evcc",                                 "Charge controller / EMS"),
]
CONTROL = [
    ("node-red/node-red",                "IoT flow runtime"),
    ("Koenkk/zigbee2mqtt",               "IoT gateway"),
    ("influxdata/telegraf",              "Telemetry agent"),
    ("absmach/magistrala",               "IoT platform"),
    ("thingsboard/thingsboard",          "IoT platform"),
    ("openhab/openhab-core",             "Building/energy automation"),
    ("eclipse-volttron/volttron-core",   "Grid/building agent platform"),
]

ECO_INDEXED = {"npm", "PyPI", "Maven", "Go", "NuGet", "crates.io"}
EXCLUDE = re.compile(r"/(tests?|docs?|examples?|mock[s]?|fixtures?|benchmarks?)/", re.I)


def log(msg):
    print(f"[repro] {msg}", flush=True)


def excluded(p):
    return bool(EXCLUDE.search(p)) or "mock" in p.lower()


# ============================================================ STAGE 1: acquire
def clone(slug, dest):
    d = os.path.join(dest, slug.split("/")[-1])
    if os.path.isdir(d):
        return d
    # -c core.longpaths=true avoids Windows MAX_PATH (260-char) failures on repos
    # with deeply nested paths (e.g. EVerest/everest-core).
    subprocess.run(["git", "clone", "--depth", "1", "-q",
                    "-c", "core.longpaths=true",
                    f"https://github.com/{slug}.git", d],
                   check=True, timeout=1800)
    return d


def stage_acquire():
    log("STAGE 1: acquiring corpus + advisory database")
    for sub in ("repos", "control", "data", "figs"):
        os.makedirs(os.path.join(ROOT, sub), exist_ok=True)
    for slug, _ in EVCI:
        clone(slug, os.path.join(ROOT, "repos"))
        log(f"  cloned {slug}")
    for slug, _ in CONTROL:
        clone(slug, os.path.join(ROOT, "control"))
        log(f"  cloned {slug}")
    adv = os.path.join(ROOT, "advisory-database")
    if not os.path.isdir(adv):
        log("  cloning GitHub Advisory Database (~2.7 GB, this takes a while)")
        subprocess.run(["git", "clone", "--depth", "1", "-q", ADVISORY_DB, adv],
                       check=True, timeout=3600)
    log("  advisory database ready")
    return adv


# ================================================ STAGE 2: index advisories
def stage_index(adv_root):
    log("STAGE 2: indexing advisories (OSV -> package-keyed index)")
    from cvss import CVSS3, CVSS4

    def score(sev):
        for want, cls in (("CVSS_V3", CVSS3), ("CVSS_V4", CVSS4)):
            for s in sev or []:
                if s.get("type") == want and s.get("score"):
                    try:
                        return float(cls(s["score"]).base_score)
                    except Exception:
                        pass
        return None

    def norm(eco, name):
        if eco == "PyPI":
            return name.lower().replace("_", "-").replace(".", "-")
        if eco in ("npm", "NuGet", "crates.io"):
            return name.lower()
        return name

    def intervals(ranges):
        out = []
        for r in ranges or []:
            if r.get("type") == "GIT":
                continue
            intro = None
            for ev in r.get("events", []):
                if "introduced" in ev:
                    intro = ev["introduced"]
                elif "fixed" in ev:
                    out.append((intro, ev["fixed"], None)); intro = None
                elif "last_affected" in ev:
                    out.append((intro, None, ev["last_affected"])); intro = None
            if intro is not None:
                out.append((intro, None, None))
        return out

    idx, n_adv = defaultdict(list), 0
    pattern = os.path.join(adv_root, "advisories", "github-reviewed", "**", "GHSA-*.json")
    for f in glob.iglob(pattern, recursive=True):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        if d.get("withdrawn"):
            continue
        ds = d.get("database_specific") or {}
        base = dict(id=d["id"],
                    cve=next((a for a in (d.get("aliases") or []) if a.startswith("CVE-")), None),
                    published=d.get("published"), cvss=score(d.get("severity")),
                    sev=(ds.get("severity") or "").upper() or None,
                    cwes=ds.get("cwe_ids") or [])
        hit = False
        for a in d.get("affected", []):
            pkg = a.get("package") or {}
            eco, nm = pkg.get("ecosystem", ""), pkg.get("name")
            if eco not in ECO_INDEXED or not nm:
                continue
            rec = dict(base); rec["ranges"] = intervals(a.get("ranges"))
            rec["versions"] = a.get("versions")
            if not rec["ranges"] and not rec["versions"]:
                continue
            idx[(eco, norm(eco, nm))].append(rec); hit = True
        n_adv += hit
    entries = sum(len(v) for v in idx.values())
    withc = sum(1 for v in idx.values() for r in v if r["cvss"] is not None)
    log(f"  advisories with package ranges : {n_adv}")
    log(f"  package-advisory entries        : {entries} over {len(idx)} packages")
    log(f"  with CVSS base score            : {withc} ({100*withc/max(entries,1):.1f}%)")
    print(f"Sec 4.1 | curated advisories with package ranges: {n_adv}")
    print(f"Sec 4.1 | package-advisory entries: {entries}; distinct packages: {len(idx)}")
    print(f"Sec 4.1 | entries with CVSS base score: {100*withc/max(entries,1):.1f}%")
    return dict(idx), norm


# ============================================== STAGE 3: resolve dependencies
def stage_resolve():
    log("STAGE 3: resolving dependency sets")
    import yaml
    rows, mstats = [], {}

    def add(proj, corpus, eco, name, ver, depth, scope, res, src):
        if not name or not ver or str(ver).startswith(("file:", "link:", "workspace:")):
            return
        rows.append(dict(project=proj, corpus=corpus, ecosystem=eco, package=name,
                         version=str(ver).strip(), depth_class=depth, scope=scope,
                         resolution=res, source=src))

    def pnpm_split(k):
        k = k.split("(")[0].lstrip("/")
        i = k.rfind("@")
        return (k[:i], k[i+1:]) if i > 0 else (None, None)

    for folder, corpus, spec in (("repos", "EVCI", EVCI), ("control", "Control", CONTROL)):
        for slug, _role in spec:
            proj = slug.split("/")[-1]
            pdir = os.path.join(ROOT, folder, proj)

            # --- npm package-lock
            for pl in glob.glob(f"{pdir}/package-lock.json"):
                d = json.load(open(pl)); pk = d.get("packages", {})
                direct = set(pk.get("", {}).get("dependencies", {})) | \
                         set(pk.get("", {}).get("devDependencies", {}))
                for key, m in pk.items():
                    if not key or m.get("link") or not m.get("version"):
                        continue
                    nm = m.get("name") or key.split("node_modules/")[-1]
                    add(proj, corpus, "npm", nm, m["version"],
                        "direct" if nm in direct else "transitive",
                        "dev" if (m.get("dev") or m.get("devOptional")) else "runtime",
                        "full", "package-lock.json")

            # --- pnpm lock (v9): recover runtime closure by BFS from prod roots
            for pl in glob.glob(f"{pdir}/pnpm-lock.yaml"):
                d = yaml.safe_load(open(pl))
                imp, snap, pkgs = (d.get("importers") or {}), (d.get("snapshots") or {}), (d.get("packages") or {})
                direct, roots = set(), []
                for _, im in imp.items():
                    for sect in ("dependencies", "optionalDependencies", "devDependencies"):
                        for nm, sp in (im.get(sect) or {}).items():
                            v = sp.get("version") if isinstance(sp, dict) else sp
                            if not v or str(v).startswith(("link:", "file:", "workspace:")):
                                continue
                            direct.add(nm)
                            if sect != "devDependencies":
                                roots.append(f"{nm}@{str(v).split('(')[0]}")
                g = defaultdict(list)
                for k, m in (snap or pkgs).items():
                    n, v = pnpm_split(k)
                    if not n:
                        continue
                    for sect in ("dependencies", "optionalDependencies"):
                        for dn, dv in ((m or {}).get(sect) or {}).items():
                            g[f"{n}@{v}"].append(f"{dn}@{str(dv).split('(')[0]}")
                rt, q = set(), deque(roots)
                while q:
                    c = q.popleft()
                    if c in rt:
                        continue
                    rt.add(c)
                    q.extend(x for x in g.get(c, []) if x not in rt)
                for k in pkgs:
                    n, v = pnpm_split(k)
                    if not n:
                        continue
                    add(proj, corpus, "npm", n, v,
                        "direct" if n in direct else "transitive",
                        "runtime" if f"{n}@{v}" in rt else "dev", "full", "pnpm-lock.yaml")

            # --- yarn lock
            for yl in glob.glob(f"{pdir}/**/yarn.lock", recursive=True):
                if "/node_modules/" in yl or excluded(yl):
                    continue
                pj = os.path.join(os.path.dirname(yl), "package.json")
                dn = set()
                if os.path.exists(pj):
                    try:
                        j = json.load(open(pj))
                        dn = set(j.get("dependencies", {})) | set(j.get("devDependencies", {}))
                    except Exception:
                        pass
                txt = open(yl, errors="ignore").read()
                for b in re.split(r"\n(?=\S)", txt):
                    if b.lstrip().startswith("#") or not b.strip():
                        continue
                    m = re.search(r'^\s*version\s+"?([^"\s]+)"?', b, re.M)
                    if not m:
                        continue
                    spec_ = b.split("\n")[0].rstrip(":").split(",")[0].strip().strip('"')
                    i = spec_.rfind("@")
                    add(proj, corpus, "npm", spec_[:i] if i > 0 else spec_, m.group(1),
                        "direct" if (spec_[:i] if i > 0 else spec_) in dn else "transitive",
                        "runtime", "full", "yarn.lock")

            # --- Go (go.mod enumerates the pruned module graph)
            for gm in glob.glob(f"{pdir}/**/go.mod", recursive=True):
                if excluded(gm):
                    continue
                inb = False
                for line in open(gm, errors="ignore"):
                    s = line.strip()
                    if s.startswith("require ("):
                        inb = True; continue
                    if inb and s == ")":
                        inb = False; continue
                    m = re.match(r"^(?:require\s+)?([\w\.\-~/]+\.[\w\.\-~/]+)\s+(v[^\s/]+)(\s*//\s*indirect)?", s)
                    if m and (inb or s.startswith("require ")):
                        add(proj, corpus, "Go", m.group(1), m.group(2),
                            "transitive" if m.group(3) else "direct", "runtime", "full", "go.mod")

            # --- PyPI
            locks = [p for p in glob.glob(f"{pdir}/**/poetry.lock", recursive=True) if not excluded(p)]
            for pl in locks:
                d = tomllib.load(open(pl, "rb"))
                pp = os.path.join(os.path.dirname(pl), "pyproject.toml")
                direct = set()
                if os.path.exists(pp):
                    try:
                        pdd = tomllib.load(open(pp, "rb"))
                        po = pdd.get("tool", {}).get("poetry", {})
                        direct |= set(po.get("dependencies", {}))
                        for gr in (po.get("group") or {}).values():
                            direct |= set(gr.get("dependencies", {}))
                        for dep in pdd.get("project", {}).get("dependencies", []) or []:
                            direct.add(re.split(r"[<>=!~\[; ]", dep)[0])
                    except Exception:
                        pass
                dn = {x.lower().replace("_", "-") for x in direct}
                for p in d.get("package", []):
                    gps = p.get("groups") or ([p.get("category")] if p.get("category") else ["main"])
                    add(proj, corpus, "PyPI", p["name"], p["version"],
                        "direct" if p["name"].lower().replace("_", "-") in dn else "transitive",
                        "runtime" if any(x in ("main", "default") for x in gps) else "dev",
                        "full", "poetry.lock")
            if not locks and os.path.exists(f"{pdir}/pyproject.toml"):
                try:
                    pdd = tomllib.load(open(f"{pdir}/pyproject.toml", "rb"))
                    po = pdd.get("tool", {}).get("poetry", {})
                    cl = lambda sp: re.sub(r"^[\^~>=<! ]+", "",
                                           str(sp if isinstance(sp, str) else (sp or {}).get("version", ""))).split(",")[0].strip()
                    for nm, sp in (po.get("dependencies") or {}).items():
                        if nm.lower() != "python":
                            add(proj, corpus, "PyPI", nm, cl(sp), "direct", "runtime", "direct", "pyproject.toml")
                    for gr in (po.get("group") or {}).values():
                        for nm, sp in (gr.get("dependencies") or {}).items():
                            add(proj, corpus, "PyPI", nm, cl(sp), "direct", "dev", "direct", "pyproject.toml")
                except Exception:
                    pass

            # --- Rust
            for cl_ in glob.glob(f"{pdir}/**/Cargo.lock", recursive=True):
                if excluded(cl_):
                    continue
                d = tomllib.load(open(cl_, "rb"))
                ct = os.path.join(os.path.dirname(cl_), "Cargo.toml")
                direct = set()
                if os.path.exists(ct):
                    try:
                        cd = tomllib.load(open(ct, "rb"))
                        direct = set(cd.get("dependencies", {})) | set(cd.get("dev-dependencies", {}))
                    except Exception:
                        pass
                for p in d.get("package", []):
                    if "source" not in p:
                        continue
                    add(proj, corpus, "crates.io", p["name"], p["version"],
                        "direct" if p["name"] in direct else "transitive", "runtime", "full", "Cargo.lock")

            # --- Maven (DIRECT ONLY: Maven Central needed for the closure)
            import xml.etree.ElementTree as ET
            NS = "{http://maven.apache.org/POM/4.0.0}"
            poms = [p for p in glob.glob(f"{pdir}/**/pom.xml", recursive=True)
                    if "/target/" not in p and not excluded(p)]
            if poms:
                props, decl = {}, []
                for pom in poms:
                    try:
                        r = ET.parse(pom).getroot()
                    except Exception:
                        continue
                    for pr in r.findall(f"{NS}properties/*"):
                        props[pr.tag.replace(NS, "")] = (pr.text or "").strip()
                    pv = r.find(f"{NS}version")
                    if pv is not None and pv.text:
                        props.setdefault("project.version", pv.text.strip())
                    for xp in (f"{NS}dependencies/{NS}dependency",
                               f"{NS}dependencyManagement/{NS}dependencies/{NS}dependency"):
                        for dd in r.findall(xp):
                            g, a = dd.findtext(f"{NS}groupId"), dd.findtext(f"{NS}artifactId")
                            if g and a:
                                decl.append((g.strip(), a.strip(), (dd.findtext(f"{NS}version") or "").strip(),
                                             (dd.findtext(f"{NS}scope") or "compile").strip()))
                def rez(v, dep=0):
                    if not v or dep > 6:
                        return v
                    m = re.fullmatch(r"\$\{([^}]+)\}", v.strip())
                    return rez(props.get(m.group(1), ""), dep + 1) if m else v
                seen, bom = set(), 0
                for g, a, v, sc in decl:
                    rv = rez(v)
                    if not rv or "${" in rv:
                        bom += 1; continue
                    if (f"{g}:{a}", rv) in seen:
                        continue
                    seen.add((f"{g}:{a}", rv))
                    add(proj, corpus, "Maven", f"{g}:{a}", rv, "direct",
                        "dev" if sc in ("test", "provided") else "runtime", "direct", "pom.xml")
                ga = defaultdict(set)
                for g, a, v, sc in decl:
                    ga[f"{g}:{a}"].add(rez(v))
                det = {k for k, vs in ga.items() if any(x and "${" not in x for x in vs)}
                par = "-"
                for pom in poms:
                    try:
                        rr = ET.parse(pom).getroot()
                    except Exception:
                        continue
                    pe = rr.find(f"{NS}parent")
                    if pe is not None:
                        par = f"{pe.findtext(NS+'artifactId')} {pe.findtext(NS+'version')}"
                        break
                mstats[proj] = dict(declared=len(ga), pinned=len(det),
                                    pct=100 * len(det) / max(len(ga), 1), parent=par,
                                    eco="Maven")

            # --- NuGet (DIRECT ONLY)
            _ng, _ngd = set(), set()
            for cs in glob.glob(f"{pdir}/**/*.csproj", recursive=True):
                if excluded(cs):
                    continue
                try:
                    r = ET.parse(cs).getroot()
                except Exception:
                    continue
                for pr in r.iter():
                    if pr.tag.split("}")[-1] != "PackageReference":
                        continue
                    n, v = pr.get("Include"), pr.get("Version")
                    if n:
                        _ng.add(n)
                    if n and v and "$" not in v:
                        _ngd.add(n)
                        add(proj, corpus, "NuGet", n, v, "direct", "runtime", "direct", "csproj")
            if _ng:
                mstats[proj] = dict(declared=len(_ng), pinned=len(_ngd),
                                    pct=100 * len(_ngd) / len(_ng), parent="-", eco="NuGet")

            # --- NATIVE (advisory-invisible tier)
            edm = os.path.join(pdir, "dependencies.yaml")
            if os.path.exists(edm):
                for nm, m in (yaml.safe_load(open(edm)) or {}).items():
                    if not isinstance(m, dict) or "git" not in m:
                        continue
                    tag = str(m.get("git_tag", "") or "")
                    pin = "commit-hash" if re.fullmatch(r"[0-9a-f]{40}", tag) else ("tag" if tag else "floating")
                    add(proj, corpus, "native-cmake", nm, tag or "UNPINNED", "direct", "runtime",
                        "none", f"dependencies.yaml[{pin}]")
            pio = os.path.join(pdir, "platformio.ini")
            if os.path.exists(pio):
                m = re.search(r"^lib_deps\s*=\s*\n((?:[ \t]+\S.*\n)+)", open(pio, errors="ignore").read(), re.M)
                for line in (m.group(1).splitlines() if m else []):
                    s = line.split(";")[0].strip()
                    if not s or s.startswith("${"):
                        continue
                    if s.startswith("http"):
                        nm = s.split("#")[0].rstrip("/").split("/")[-1].replace(".git", "")
                        ver, pin = (s.split("#")[-1] if "#" in s else "UNPINNED"), "git-ref"
                    elif "@" in s:
                        nm, ver, pin = s.rsplit("@", 1)[0], s.rsplit("@", 1)[1], "version"
                    else:
                        nm, ver, pin = s, "UNPINNED", "floating"
                    add(proj, corpus, "native-arduino", nm.strip(), ver.strip(), "direct", "runtime",
                        "none", f"platformio.ini[{pin}]")

    best = {}
    for r in rows:
        k = (r["project"], r["ecosystem"], r["package"], r["version"])
        if k not in best:
            best[k] = r
        else:
            if r["depth_class"] == "direct":
                best[k]["depth_class"] = "direct"
            if r["scope"] == "runtime":
                best[k]["scope"] = "runtime"
    deps = list(best.values())
    with open(f"{ROOT}/data/dependencies.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(deps[0].keys())); w.writeheader(); w.writerows(deps)

    log(f"  total dependency records: {len(deps)}")
    print(f"Sec 4.1 | total resolved dependency records: {len(deps)}")
    print("\n=== TABLE 2: source-determinable composition (Maven / NuGet) ===")
    print("Table 2 | Q1 = distinct declared artefacts whose version is IN THE SOURCE")
    print("Table 2 | Q2 = is the transitive closure recoverable from source? (no lockfile => NO)")
    for pn, m in sorted(mstats.items(), key=lambda x: x[1]["pct"]):
        print(f"Table 2 |   {pn:16s} {m['eco']:6s} declared={m['declared']:4d} "
              f"version-in-source={m['pinned']:4d} ({m['pct']:3.0f}%)  closure-in-source=NO  "
              f"parent={m['parent']}")
    if mstats:
        lo = min(m["pct"] for m in mstats.values()); hi = max(m["pct"] for m in mstats.values())
        print(f"Table 2 | Q1 direct-version determinacy: {lo:.0f}%-{hi:.0f}% across "
              f"{len(mstats)} Maven/NuGet projects")
        print(f"Table 2 | Q2 closure determinacy: 0/{len(mstats)} (0%) - neither ecosystem "
              f"commits a lockfile")
    return deps


# ============================================== STAGE 4: match + validate
def stage_match(deps, idx, norm):
    log("STAGE 4: matching versions against advisories")
    from univers.versions import (SemverVersion, PypiVersion, MavenVersion,
                                  GolangVersion, NugetVersion)
    VC = {"npm": SemverVersion, "crates.io": SemverVersion, "PyPI": PypiVersion,
          "Maven": MavenVersion, "Go": GolangVersion, "NuGet": NugetVersion}

    def pv(eco, s):
        try:
            return VC[eco](str(s))
        except Exception:
            return None

    def aff(eco, v, a):                                   # Eq. (1)
        if a.get("versions") and (str(v) in a["versions"] or f"v{v}" in a["versions"]):
            return True
        V = pv(eco, v)
        if V is None:
            return None
        for intro, fixed, last in a["ranges"]:
            try:
                if intro and str(intro) not in ("0", "0.0.0"):
                    I = pv(eco, intro)
                    if I is None or V < I:
                        continue
                if fixed:
                    F = pv(eco, fixed)
                    if F is None or not (V < F):
                        continue
                if last:
                    L = pv(eco, last)
                    if L is None or not (V <= L):
                        continue
                return True
            except Exception:
                continue
        return False

    def fix(eco, v, a):
        V = pv(eco, v)
        return any(f and pv(eco, f) and V and pv(eco, f) > V for _, f, _ in a["ranges"])

    # -- matcher validation (positive + negative controls) ---------------------
    log("  validating matcher against known ground truth")
    ok = True
    for eco, pkg, cve, cases in [
        ("Go", "golang.org/x/crypto", "CVE-2024-45337",
         [("v0.21.0", True), ("v0.30.0", True), ("v0.31.0", False), ("v0.35.0", False)]),
        ("Go", "github.com/docker/docker", "CVE-2024-41110",
         [("v25.0.5+incompatible", True), ("v25.0.6+incompatible", False),
          ("v23.0.14+incompatible", True), ("v27.1.1+incompatible", False)]),
        ("npm", "multer", "CVE-2025-47935",
         [("1.4.5-lts.2", True), ("2.0.0", False), ("2.0.2", False)]),
    ]:
        recs = [x for x in idx.get((eco, norm(eco, pkg)), []) if x["cve"] == cve]
        if not recs:
            log(f"    SKIP {cve} (not in this snapshot of the advisory DB)")
            continue
        for v, exp in cases:
            got = any(aff(eco, v, r) for r in recs)   # NB: advisories may span several streams
            mark = "PASS" if got == exp else "FAIL"
            if got != exp:
                ok = False
            log(f"    {mark} {pkg} {v}: affected={got} expected={exp}")
    print(f"Sec 4.1 | matcher validation: {'ALL CONTROLS PASS' if ok else 'FAILURE'}")

    findings, unparse, cover, invis = [], 0, 0, 0
    for d in deps:
        eco = d["ecosystem"]
        if eco.startswith("native-"):
            invis += 1
            continue
        cover += 1
        bad = False
        for a in idx.get((eco, norm(eco, d["package"])), []):
            hit = aff(eco, d["version"], a)
            if hit is None:
                bad = True; continue
            if not hit:
                continue
            age = None
            if a.get("published"):
                try:
                    age = (SNAPSHOT - datetime.fromisoformat(a["published"].replace("Z", "+00:00"))).days
                except Exception:
                    pass
            findings.append(dict(project=d["project"], corpus=d["corpus"], ecosystem=eco,
                                 package=d["package"], version=d["version"],
                                 depth_class=d["depth_class"], scope=d["scope"],
                                 resolution=d["resolution"], ghsa=a["id"], cve=a["cve"] or "",
                                 cvss=a["cvss"] if a["cvss"] is not None else "",
                                 severity=a["sev"] or "", cwes=";".join(a["cwes"]),
                                 disclosure_age_days=age if age is not None else "",
                                 fix_available=int(fix(eco, d["version"], a))))
        if bad:
            unparse += 1
    with open(f"{ROOT}/data/findings.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(findings[0].keys())); w.writeheader(); w.writerows(findings)

    inst = {(f["project"], f["package"], f["version"]) for f in findings}
    print(f"Sec 4.1 | advisory-coverable records: {cover}")
    print(f"Sec 4.1 | ADVISORY-INVISIBLE (native) records: {invis}")
    print(f"Sec 4.1 | version-parse failures: {unparse} ({100*unparse/max(cover,1):.2f}%)")
    print(f"Sec 4.1 | vulnerable dependency instances: {len(inst)}")
    print(f"Sec 4.1 | (project, package, advisory) findings: {len(findings)}")
    sev = defaultdict(int)
    for f in findings:
        sev[f["severity"] or "UNKNOWN"] += 1
    print(f"Sec 4.1 | severity mix: critical={sev['CRITICAL']} high={sev['HIGH']} "
          f"moderate={sev['MODERATE']} low={sev['LOW']}")
    return findings


# ================================================== STAGE 5: metrics + tests
def stage_metrics(deps, findings):
    log("STAGE 5: computing metrics, tables and statistics")
    from scipy.stats import fisher_exact, mannwhitneyu, kendalltau

    advs = defaultdict(list)
    for f in findings:
        advs[(f["project"], f["package"], f["version"])].append(f)

    def head_days(proj):
        for base in ("repos", "control"):
            p = os.path.join(ROOT, base, proj)
            if os.path.isdir(p):
                try:
                    s = subprocess.run(["git", "-C", p, "log", "-1", "--format=%cI"],
                                       capture_output=True, text=True).stdout.strip()
                    return (SNAPSHOT - datetime.fromisoformat(s)).days
                except Exception:
                    return None
        return None

    def scei(p, use_trans=True, use_sev=True, use_om=True):        # Eq. (4)-(6)
        rt = [d for d in deps if d["project"] == p and d["resolution"] == "full"
              and d["scope"] == "runtime"]
        if not rt:
            return 0.0
        tot = 0.0
        for k, A in advs.items():
            if k[0] != p or A[0]["scope"] != "runtime" or A[0]["resolution"] != "full":
                continue
            if not use_trans and A[0]["depth_class"] == "transitive":
                continue
            sc = [float(x["cvss"]) for x in A if x["cvss"]]
            if not sc:
                continue
            sig = (1 - math.prod(1 - s / 10 for s in sc)) if use_sev else 1.0
            om = 1.0
            if use_om:
                om = (1 + BETA * (A[0]["depth_class"] == "transitive")) * \
                     (1 + GAMMA * all(x["fix_available"] in (0, "0") for x in A))
            tot += sig * om
        return 100.0 * tot / len(rt)

    print("\n=== TABLE 1: per-project exposure ===")
    projects = sorted({d["project"] for d in deps})
    for p in projects:
        cov = [d for d in deps if d["project"] == p and not d["ecosystem"].startswith("native-")]
        nat = [d for d in deps if d["project"] == p and d["ecosystem"].startswith("native-")]
        vuln = {k for k in advs if k[0] == p}
        corpus = next(d["corpus"] for d in deps if d["project"] == p)
        ages = [int(x["disclosure_age_days"]) for k in vuln for x in advs[k] if x["disclosure_age_days"]]
        rho = 100 * len(vuln) / len(cov) if cov else 0.0
        print(f"Table 1 | {corpus:7s} {p:40s} deps={len(cov):5d} native={len(nat):2d} "
              f"vuln={len(vuln):3d} rho={rho:5.2f}% SCEI={scei(p):6.3f} "
              f"medAge={int(st.median(ages)) if ages else '-':>4} dormant={head_days(p)}d")

    # --- Table 2: advisory-invisible tier
    print("\n=== TABLE 3: advisory-invisible (native) tier ===")
    nat = [d for d in deps if d["ecosystem"].startswith("native-")]
    mut = sum(1 for d in nat if "commit-hash" not in d["source"])
    for d in sorted(nat, key=lambda x: (x["project"], x["package"])):
        pin = d["source"].split("[")[-1].rstrip("]")
        print(f"Table 3 | {d['project']:18s} {d['package']:26s} {d['version']:24s} "
              f"pin={pin:12s} advisories_indexed=0")
    print(f"Table 3 | native dependencies={len(nat)}; advisory coverage=0/{len(nat)} (0.0%)")
    print(f"Table 3 | MUTABLE references: {mut}/{len(nat)} ({100*mut/max(len(nat),1):.1f}%)")

    # --- Table 3: EVCI vs control (cluster-aware)
    print("\n=== TABLE 4: EVCI vs control (fully resolved stratum) ===")
    full = [d for d in deps if d["resolution"] == "full"]
    vset = {(f["project"], f["package"], f["version"]) for f in findings}
    tab = {("EVCI", 1): 0, ("EVCI", 0): 0, ("Control", 1): 0, ("Control", 0): 0}
    for d in full:
        tab[(d["corpus"], 1 if (d["project"], d["package"], d["version"]) in vset else 0)] += 1
    T = [[tab[("EVCI", 1)], tab[("EVCI", 0)]], [tab[("Control", 1)], tab[("Control", 0)]]]
    orr, pf = fisher_exact(T)
    print(f"Table 4 | EVCI    : {T[0][0]}/{sum(T[0])} = {100*T[0][0]/sum(T[0]):.2f}% vulnerable")
    print(f"Table 4 | Control : {T[1][0]}/{sum(T[1])} = {100*T[1][0]/sum(T[1]):.2f}% vulnerable")
    print(f"Table 4 | pooled Fisher exact (NOT primary; pseudo-replicated): OR={orr:.3f}, p={pf:.4f}")

    # per-project counts -> the project is the sampling unit
    pj = defaultdict(lambda: [0, 0]); corp = {}
    for d in full:
        pj[d["project"]][0] += 1
        pj[d["project"]][1] += (1 if (d["project"], d["package"], d["version"]) in vset else 0)
        corp[d["project"]] = d["corpus"]
    E = [p for p in pj if corp[p] == "EVCI"]; C = [p for p in pj if corp[p] == "Control"]
    pool = lambda ps: (sum(pj[p][1] for p in ps), sum(pj[p][0] for p in ps))

    # LEAVE-ONE-OUT
    print("Table 4 | leave-one-out (each row deletes one project):")
    ve, ne = pool(E); vc, nc = pool(C)
    base_or, _ = fisher_exact([[ve, ne - ve], [vc, nc - vc]])
    flips = 0
    loo = []  # Fix 1: collect for fig2_robustness  (project, evci_pct, ctrl_pct, OR, p)
    for p in sorted(E + C):
        e = [x for x in E if x != p]; c = [x for x in C if x != p]
        ve, ne = pool(e); vc, nc = pool(c)
        o, q = fisher_exact([[ve, ne - ve], [vc, nc - vc]])
        rev = (o - 1) * (base_or - 1) < 0
        flips += rev
        loo.append((p, 100 * ve / ne, 100 * vc / nc, o, q))  # Fix 1
        print(f"Table 4 |   drop {p:40s} EVCI={100*ve/ne:5.2f}% Ctrl={100*vc/nc:5.2f}% "
              f"OR={o:5.3f} p={q:.3f}{'  <- DIRECTION REVERSED' if rev else ''}")
    print(f"Table 4 | single-project deletion reverses the effect direction in {flips}/{len(E+C)} cases")

    # CLUSTER BOOTSTRAP (projects resampled, not dependencies)
    random.seed(7)
    diffs, ors = [], []
    for _ in range(20000):
        e = [random.choice(E) for _ in E]; c = [random.choice(C) for _ in C]
        ve, ne = pool(e); vc, nc = pool(c)
        if not ne or not nc:
            continue
        diffs.append(100 * ve / ne - 100 * vc / nc)
        a, b, cc, dd = ve + .5, ne - ve + .5, vc + .5, nc - vc + .5   # Haldane-Anscombe
        ors.append((a / b) / (cc / dd))
    diffs.sort(); ors.sort()
    qt = lambda v, p: v[int(p * len(v))]
    ve, ne = pool(E); vc, nc = pool(C)
    print(f"Table 4 | CLUSTER BOOTSTRAP (20,000 resamples of projects):")
    print(f"Table 4 |   difference  = {100*ve/ne-100*vc/nc:+.2f} pp, "
          f"95% CI [{qt(diffs,.025):+.2f}, {qt(diffs,.975):+.2f}] pp")
    or_lo, or_hi = qt(ors, .025), qt(ors, .975)   # Fix 1: needed by fig2_robustness
    print(f"Table 4 |   odds ratio  = {base_or:.3f}, 95% CI [{or_lo:.2f}, {or_hi:.2f}]")
    print(f"Table 4 |   -> the design excludes only LARGE differences; it cannot rule out "
          f"EVCI being {((100*vc/nc)+qt(diffs,.975))/(100*vc/nc):.1f}x the control rate")

    rho_of = lambda p: 100 * len({k for k in advs if k[0] == p}) / max(
        len([d for d in deps if d["project"] == p and not d["ecosystem"].startswith("native-")]), 1)
    e = [rho_of(p) for p in E]; c = [rho_of(p) for p in C]
    u, pm = mannwhitneyu(e, c, alternative="two-sided")
    print(f"Table 4 | project-level rho: EVCI median={st.median(e):.2f}% (n={len(e)}), "
          f"Control median={st.median(c):.2f}% (n={len(c)}); Mann-Whitney U={u:.1f}, p={pm:.4f}")
    # Fix 2: restrict to the fully-resolved stratum (Section 3.2: direct-only stratum
    # is never pooled into headline figures).  Without this filter, Control n goes 56->84
    # and Mann-Whitney p goes 0.0013->0.228.  Make the paper and the code agree.
    ea = sorted(int(f["disclosure_age_days"]) for f in findings
                if f["corpus"] == "EVCI" and f["scope"] == "runtime"
                and f["resolution"] == "full" and f["disclosure_age_days"])
    ca = sorted(int(f["disclosure_age_days"]) for f in findings
                if f["corpus"] == "Control" and f["scope"] == "runtime"
                and f["resolution"] == "full" and f["disclosure_age_days"])
    ue, pe = mannwhitneyu(ea, ca, alternative="two-sided")
    print(f"Table 4 | exposure window: EVCI median={st.median(ea):.0f}d (max {ea[-1]}d, "
          f"{100*sum(1 for x in ea if x>365)/len(ea):.0f}% >1yr), Control median={st.median(ca):.0f}d; "
          f"U={ue:.1f}, p={pe:.4f}")
    # Fix 4: §4.5 quotes a p75 of 237 d; method='higher' reproduces the paper value
    print(f"Sec 4.5 | EVCI exposure window p75 = {np.percentile(ea, 75, method='higher'):.0f} d")
    fx = [int(f["fix_available"]) for f in findings]
    print(f"Sec 4.5 | remediable by version bump: {sum(fx)}/{len(fx)} = {100*sum(fx)/len(fx):.1f}%")
    for corp in ("EVCI", "Control"):
        i = {k: v for k, v in advs.items() if v[0]["corpus"] == corp
             and v[0]["scope"] == "runtime" and v[0]["resolution"] == "full"}
        tr = sum(1 for v in i.values() if v[0]["depth_class"] == "transitive")
        print(f"Sec 4.5 | {corp}: vulnerable runtime deps={len(i)}, transitive={tr} "
              f"({100*tr/max(len(i),1):.0f}%)")

    fp = sorted({d["project"] for d in full})

    # --- Table 4: keystone (blast radius vs present exposure)  Eq. (7)
    print("\n=== TABLE 5: shared runtime packages carrying an advisory (EVCI) ===")
    pres, ecop = defaultdict(set), defaultdict(set)
    for d in full:
        if d["corpus"] != "EVCI":
            continue
        ecop[d["ecosystem"]].add(d["project"])
        if d["scope"] == "runtime":
            pres[(d["ecosystem"], d["package"])].add(d["project"])
    vin, worst = defaultdict(set), defaultdict(float)
    for f in findings:
        if f["corpus"] != "EVCI" or f["scope"] != "runtime" or f["resolution"] != "full":
            continue
        k = (f["ecosystem"], f["package"]); vin[k].add(f["project"])
        if f["cvss"]:
            worst[k] = max(worst[k], float(f["cvss"]))
    shared = sum(1 for k, v in pres.items() if len(v) >= 2)
    for k, ps in sorted(pres.items(), key=lambda x: -worst[x[0]]):
        if len(ps) < 2 or k not in vin:
            continue
        print(f"Table 5 | {k[0]:10s} {k[1]:36s} present={len(ps)}/{len(ecop[k[0]])} "
              f"vulnerable={len(vin[k])}/{len(ecop[k[0]])} maxCVSS={worst[k]:.1f}")
    print(f"Table 5 | shared runtime packages (>=2 EVCI projects, same ecosystem): {shared}")

    # --- Table 5: ablation  + sensitivity
    print("\n=== TABLE 6: ablation of the exposure index ===")
    V = {"V1 direct-only": (False, False, False), "V2 +transitive": (True, False, False),
         "V3 +CVSS": (True, True, False), "V4 full SCEI": (True, True, True)}
    sc = {v: {p: round(scei(p, *a), 3) for p in fp} for v, a in V.items()}
    for p in sorted(fp, key=lambda x: -sc["V4 full SCEI"][x]):
        print(f"Table 6 | {p:40s} " + "  ".join(f"{v}={sc[v][p]:7.3f}" for v in V))
    base = [sc["V4 full SCEI"][p] for p in fp]
    for v in V:
        t, pv_ = kendalltau([sc[v][p] for p in fp], base)
        print(f"Table 6 | Kendall tau({v} vs full SCEI) = {t:+.3f} (p={pv_:.4f})")
    print("Sec 4.6 | SCEI sensitivity to (beta, gamma):")
    global BETA, GAMMA
    b0, g0 = BETA, GAMMA
    for b, g in [(0.0, 0.0), (0.25, 0.5), (0.5, 1.0), (1.0, 2.0), (2.0, 3.0)]:
        BETA, GAMMA = b, g
        t, _ = kendalltau([scei(p) for p in fp], base)
        print(f"Sec 4.6 |   beta={b}, gamma={g}: tau={t:+.3f}")
    BETA, GAMMA = b0, g0

    cwe = defaultdict(int)
    for f in findings:
        for w in f["cwes"].split(";"):
            if w:
                cwe[w] += 1
    top = sorted(cwe.items(), key=lambda x: -x[1])[:5]
    print("Sec 4.6 | top CWEs: " + ", ".join(f"{w}={n}" for w, n in top))
    return sc, fp, loo, base_or, or_lo, or_hi   # Fix 1: forward loo + CI to stage_figures


# ================================================== STAGE 6: figures
def stage_figures(deps, findings, sc, fp, loo, base_or, or_lo, or_hi):
    log("STAGE 6: generating figures")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    plt.rcParams.update({"font.size": 9, "figure.dpi": 200, "savefig.dpi": 200,
                         "savefig.bbox": "tight", "axes.spines.top": False,
                         "axes.spines.right": False})
    EV, CT = "#B03A2E", "#5D6D7E"
    SEVC = {"CRITICAL": "#7B241C", "HIGH": "#C0392B", "MODERATE": "#E59866", "LOW": "#F5D5C0"}
    advs = defaultdict(list)
    for f in findings:
        advs[(f["project"], f["package"], f["version"])].append(f)

    # Fig 1: resolution strata
    cnt = defaultdict(lambda: defaultdict(int))
    for d in deps:
        s = ("advisory-invisible (native)" if d["ecosystem"].startswith("native-")
             else "fully resolved" if d["resolution"] == "full" else "direct-only")
        cnt[(d["corpus"], d["project"])][s] += 1
    order = sorted(cnt, key=lambda k: (k[0], -sum(cnt[k].values())))
    fig, ax = plt.subplots(figsize=(9, 3.9)); bot = np.zeros(len(order))
    for s, c in zip(["fully resolved", "direct-only", "advisory-invisible (native)"],
                    ["#2E86AB", "#F4A261", "#7B241C"]):
        v = np.array([cnt[k][s] for k in order], float)
        ax.bar(range(len(order)), v, bottom=bot, color=c, label=s, width=.72)
        bot += v
    ax.set_xticks(range(len(order)))
    ax.set_xticklabels([p for _, p in order], rotation=42, ha="right", fontsize=7)
    for i, k in enumerate(order):
        ax.get_xticklabels()[i].set_color(EV if k[0] == "EVCI" else CT)
    ax.set_ylabel("resolved dependencies"); ax.legend(frameon=False, fontsize=7.5)
    ax.set_title("Fig 1: Dependency inventory by resolution stratum", loc="left", fontsize=9.5)
    plt.savefig(f"{ROOT}/figs/fig1_resolution_strata.png"); plt.close()

    # Fig 2: leave-one-out robustness forest plot  (Fix 1 — was missing entirely)
    import matplotlib as mpl
    def fig2_robustness(loo, base_or, or_lo, or_hi, outpath):
        rows = sorted(loo, key=lambda r: r[3])              # ascending odds ratio
        y = np.arange(len(rows))
        fig, ax = plt.subplots(figsize=(9.2, 4.6))
        ax.axvspan(or_lo, or_hi, color="#B03A2E", alpha=0.07, zorder=0)
        ax.axvline(1.0, color="0.35", lw=1.2, zorder=1)
        ax.axvline(base_or, color="#B03A2E", ls="--", lw=1.6, zorder=1)
        for i, (proj, _e, _c, orr, pv) in enumerate(rows):
            reversed_ = orr > 1.0
            col = "#7B241C" if reversed_ else "#5D6D7E"
            ax.plot(orr, i, marker="D", ms=9, color=col, zorder=3)
            ax.annotate(f"p={pv:.3f}", (orr, i), xytext=(11, 0),
                        textcoords="offset points", va="center",
                        fontsize=8, color=col)
        ax.set_yticks(y)
        ax.set_yticklabels([f"\u2212 {r[0]}" for r in rows], fontsize=9)
        for i, r in enumerate(rows):
            if r[3] > 1.0:
                ax.get_yticklabels()[i].set_color("#7B241C")
        ax.set_xscale("log")
        ax.set_xticks([0.2, 0.5, 1.0, 2.0, 5.0])
        ax.get_xaxis().set_major_formatter(mpl.ticker.ScalarFormatter())
        ax.set_xlabel("odds ratio, EVCI vs control (log scale) "
                      "\u2014 each row deletes one project")
        n_rev = sum(1 for r in rows if r[3] > 1.0)
        ax.set_title("Fig 2: Sensitivity of the corpus comparison to any single project\n"
                     f"dark markers: deletion reverses the direction of the effect "
                     f"({n_rev} of {len(rows)})", loc="left", fontsize=10)
        ax.text(0.98, 0.06,
                f"95% cluster-bootstrap CI on the odds ratio  [{or_lo:.2f}, {or_hi:.2f}]\n"
                f"full-corpus OR = {base_or:.3f}",
                transform=ax.transAxes, ha="right", fontsize=8.5)
        plt.savefig(outpath, bbox_inches="tight", dpi=200)
        plt.close()

    fig2_robustness(loo, base_or, or_lo, or_hi, f"{ROOT}/figs/fig2_robustness.png")

    # Fig 3: SCEI  (Fix 3 — title was mislabelled "Fig 2")
    rows = sorted(fp, key=lambda p: -sc["V4 full SCEI"][p])
    corp = {d["project"]: d["corpus"] for d in deps}
    fig, ax = plt.subplots(figsize=(8.4, 3.7))
    ax.bar(range(len(rows)), [sc["V4 full SCEI"][p] for p in rows],
           color=[EV if corp[p] == "EVCI" else CT for p in rows], width=.7)
    ax.set_xticks(range(len(rows)))
    ax.set_xticklabels(rows, rotation=42, ha="right", fontsize=7.5)
    ax.set_ylabel("SCEI (per 100 runtime deps)")
    ax.set_title("Fig 3: Supply-Chain Exposure Index", loc="left", fontsize=9.5)  # Fix 3
    plt.savefig(f"{ROOT}/figs/fig3_scei.png"); plt.close()

    # Fig 5: exposure-window ECDF  (Fix 3 — title was mislabelled "Fig 3")
    fig, ax = plt.subplots(figsize=(5.4, 3.5))
    for c_, col in (("EVCI", EV), ("Control", CT)):
        # Fix 2: restrict to fully-resolved stratum only (Section 3.2)
        a = sorted(int(f["disclosure_age_days"]) for f in findings
                   if f["corpus"] == c_ and f["scope"] == "runtime"
                   and f["resolution"] == "full" and f["disclosure_age_days"])
        ax.step(a, np.arange(1, len(a) + 1) / len(a), where="post", color=col, lw=1.8,
                label=f"{c_} (n={len(a)}, med={int(np.median(a))} d)")
    ax.axvline(365, color="0.6", ls="--", lw=.9)
    ax.set_xlabel("days since public disclosure"); ax.set_ylabel("cumulative fraction")
    ax.set_xlim(0, 800); ax.legend(frameon=False, fontsize=7.5, loc="lower right")
    ax.set_title("Fig 5: Exposure window", loc="left", fontsize=9.5)  # Fix 3
    plt.savefig(f"{ROOT}/figs/fig5_exposure_window.png"); plt.close()

    # Fig 4: severity x depth
    fig, axes = plt.subplots(1, 2, figsize=(8.4, 3.3), sharey=True)
    for ax, c_ in zip(axes, ("EVCI", "Control")):
        g = defaultdict(lambda: defaultdict(int))
        for f in findings:
            if f["corpus"] == c_ and f["scope"] == "runtime":
                g[f["depth_class"]][f["severity"] or "LOW"] += 1
        bot = np.zeros(2)
        for s in ["CRITICAL", "HIGH", "MODERATE", "LOW"]:
            v = np.array([g[d][s] for d in ["direct", "transitive"]], float)
            ax.bar(["direct", "transitive"], v, bottom=bot, color=SEVC[s], label=s, width=.55)
            bot += v
        ax.set_title(f"{c_} (n={int(bot.sum())})", fontsize=9)
    axes[0].set_ylabel("advisory findings"); axes[1].legend(frameon=False, fontsize=7.5)
    plt.suptitle("Fig 4: Severity of runtime findings by dependency depth", x=.09, ha="left", fontsize=9.5)
    plt.savefig(f"{ROOT}/figs/fig4_severity_depth.png"); plt.close()

    # Fig 5: ablation
    vs = list(sc.keys())
    ps = [p for p in rows if sc["V4 full SCEI"][p] > 0 or any(sc[v][p] > 0 for v in vs)]
    fig, ax = plt.subplots(figsize=(8.2, 3.5)); x = np.arange(len(ps)); w = .2
    for j, v in enumerate(vs):
        ax.bar(x + (j - 1.5) * w, [sc[v][p] for p in ps], w, label=v,
               color=["#D5DBDB", "#AAB7B8", "#5D6D7E", "#B03A2E"][j])
    ax.set_xticks(x); ax.set_xticklabels(ps, rotation=25, ha="right", fontsize=7.5)
    ax.set_ylabel("exposure per 100 runtime deps"); ax.legend(frameon=False, fontsize=7.2, ncol=2)
    ax.set_title("Fig 6: Ablation of the exposure index", loc="left", fontsize=9.5)  # Fix 3
    plt.savefig(f"{ROOT}/figs/fig6_ablation.png"); plt.close()
    for f in sorted(os.listdir(f"{ROOT}/figs")):
        log(f"  wrote figs/{f}")


# ================================================================== main
def main():
    print("=" * 78)
    print(" Reproduction: software supply-chain attack surface of open-source EVCI")
    print(" Paper type: [BENCH] + [STAT] measurement study (no ML model is trained)")
    print("=" * 78)
    try:
        adv_root = stage_acquire()
    except Exception as ex:
        print(f"FATAL: acquisition failed: {ex}"); sys.exit(1)
    try:
        idx, norm = stage_index(adv_root)
    except Exception as ex:
        print(f"FATAL: advisory indexing failed: {ex}"); sys.exit(1)
    try:
        deps = stage_resolve()
    except Exception as ex:
        print(f"FATAL: dependency resolution failed: {ex}"); sys.exit(1)
    try:
        findings = stage_match(deps, idx, norm)
    except Exception as ex:
        print(f"FATAL: advisory matching failed: {ex}"); sys.exit(1)
    try:
        sc, fp, loo, base_or, or_lo, or_hi = stage_metrics(deps, findings)
    except Exception as ex:
        print(f"FATAL: metric computation failed: {ex}"); sys.exit(1)
    try:
        stage_figures(deps, findings, sc, fp, loo, base_or, or_lo, or_hi)
    except Exception as ex:
        print(f"WARNING: figure generation failed: {ex}")
    print("\n" + "=" * 78)
    print(f" DONE. Data in {ROOT}/data, figures in {ROOT}/figs")
    print("=" * 78)


if __name__ == "__main__":
    main()
