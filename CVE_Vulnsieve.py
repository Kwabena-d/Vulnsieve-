#!/usr/bin/env python3
"""
cve_program.py

4 functionalities:
1) download: Fetch CVEs from NVD in pages (batches) and store RAW in a JSON dict file.
2) optimize: Optimize CVEs from downloaded RAW DB using Anthropic in batches; store OPTIMIZED in a separate JSON dict file.
3) one: Optimize a single CVE. Local RAW first; if missing, fetch from NVD on-demand, save raw, then optimize.
4) auto: Auto-run download and optimization every 24 hours.

Files (default):
- RAW_DB:       cve_raw.json
- OPT_DB:       cve_optimized.json
- SCHEMA_DB:    cve_schema.json (optional; can disable with --schema-db none)

Env:
- ANTHROPIC_API_KEY=...
- (optional) ANTHROPIC_MODEL=claude-sonnet-4-20250514  (default)
- (optional) NVD_API_KEY=...

Examples:
  # 1) Download raw CVEs (incremental by lastModified)
  python cve_program.py download --start-date 2026-01-24 --end-date 2026-01-25

  # 2) Optimize all unoptimized CVEs from local RAW DB
  python cve_program.py optimize --batch-size 10

  # 3) Optimize one CVE (local-first, else fetch from NVD)
  python cve_program.py one --cve CVE-2026-24635

  # 4) Auto-update every 24 hours
  python cve_program.py auto --days-back 7
"""

import os
import re
import json
import time
import argparse
import requests
import threading
import schedule
from typing import Dict, Optional, List, Tuple
from datetime import datetime, timezone, timedelta

from langchain_anthropic import ChatAnthropic

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0/"


# ----------------------------- Utilities -----------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def safe_sleep(seconds: float) -> None:
    if seconds and seconds > 0:
        time.sleep(seconds)

def parse_date(date_str: str) -> datetime:
    return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)

def iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def iso_to_dt(s: str):
    """Parse ISO timestamp into timezone-aware UTC datetime. Returns None if invalid/missing."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None

def needs_reoptimize(cid: str, raw_db: Dict, opt_db: Dict) -> bool:
    """
    Return True if RAW lastModified is newer than OPT timestamp, meaning OPT is stale.
    If missing/unparseable timestamps, returns False (conservative).
    """
    raw_lm = iso_to_dt(raw_db.get(cid, {}).get("lastModified"))
    opt_ts = iso_to_dt(opt_db.get(cid, {}).get("timestamp"))
    return bool(raw_lm and opt_ts and raw_lm > opt_ts)


def approx_tokens(text: str) -> int:
    return max(1, len(text) // 4) if text else 0

def strip_code_fences(s: str) -> str:
    s = (s or "").strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s, flags=re.IGNORECASE).strip()
        s = re.sub(r"\s*```$", "", s).strip()
    return s

def load_json_dict(path: str) -> Dict:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                obj = json.load(f)
                return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}
    return {}

def save_json_dict(path: str, data: Dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)

def load_checkpoint(path: str) -> Dict:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_checkpoint(path: str, data: Dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)

def parse_cves_from_text(s: str) -> List[str]:
    return [c.upper() for c in re.findall(r"\bCVE-\d{4}-\d{4,}\b", s, flags=re.IGNORECASE)]

def nvd_headers(nvd_api_key: Optional[str]) -> Dict[str, str]:
    h = {"User-Agent": "CVE-Program/1.0"}
    if nvd_api_key:
        h["apiKey"] = nvd_api_key
    return h


# ----------------------------- NVD API -----------------------------

def nvd_list_window(
    start_dt: datetime,
    end_dt: datetime,
    start_index: int,
    results_per_page: int,
    use_last_mod: bool,
    nvd_api_key: Optional[str],
    timeout: int = 30,
    max_retries: int = 10,
) -> Tuple[List[Dict], int, int]:
    params = {"startIndex": start_index, "resultsPerPage": results_per_page}
    if use_last_mod:
        params["lastModStartDate"] = iso_z(start_dt)
        params["lastModEndDate"] = iso_z(end_dt)
    else:
        params["pubStartDate"] = iso_z(start_dt)
        params["pubEndDate"] = iso_z(end_dt)

    attempt = 0
    backoff = 2.0
    while True:
        attempt += 1
        try:
            r = requests.get(NVD_API_BASE, params=params, headers=nvd_headers(nvd_api_key), timeout=timeout)

            if r.status_code in (429, 500, 502, 503):
                if attempt <= max_retries:
                    retry_after = r.headers.get("Retry-After")
                    wait = float(retry_after) if retry_after else backoff
                    backoff = min(backoff * 1.8, 60.0)
                    print(f"[!] NVD {r.status_code}. Retry {attempt}/{max_retries} after {wait:.1f}s")
                    safe_sleep(wait)
                    continue
                r.raise_for_status()

            r.raise_for_status()
            data = r.json()
            vulns = data.get("vulnerabilities", []) or []
            total = int(data.get("totalResults", 0) or 0)
            returned = len(vulns)
            return vulns, total, returned

        except Exception as e:
            if attempt <= max_retries:
                print(f"[!] NVD error (attempt {attempt}/{max_retries}): {e}")
                safe_sleep(backoff)
                backoff = min(backoff * 1.8, 60.0)
                continue
            raise


def extract_minimal_raw(v: Dict) -> Optional[Dict]:
    try:
        cve = v.get("cve", {}) or {}
        cve_id = (cve.get("id") or "").strip().upper()
        if not cve_id:
            return None

        desc_en = None
        for d in cve.get("descriptions", []) or []:
            if d.get("lang") == "en":
                desc_en = d.get("value")
                break

        weaknesses = []
        for w in cve.get("weaknesses", []) or []:
            for d in w.get("description", []) or []:
                val = d.get("value")
                if val and val not in weaknesses:
                    weaknesses.append(val)

        metrics = cve.get("metrics", {}) or {}

        return {
            "cve_id": cve_id,
            "description_en": desc_en,
            "published": cve.get("published"),
            "lastModified": cve.get("lastModified"),
            "weaknesses": weaknesses,
            "metrics": metrics,
            "source": "nvd",
        }
    except Exception:
        return None


def nvd_fetch_by_id(cve_id: str, nvd_api_key: Optional[str], timeout: int = 30, max_retries: int = 8) -> Optional[Dict]:
    cve_id = cve_id.strip().upper()
    params = {"cveId": cve_id}

    attempt = 0
    backoff = 2.0
    while True:
        attempt += 1
        try:
            r = requests.get(NVD_API_BASE, params=params, headers=nvd_headers(nvd_api_key), timeout=timeout)

            if r.status_code in (429, 500, 502, 503):
                if attempt <= max_retries:
                    retry_after = r.headers.get("Retry-After")
                    wait = float(retry_after) if retry_after else backoff
                    backoff = min(backoff * 1.8, 60.0)
                    print(f"[!] NVD {r.status_code}. Retry {attempt}/{max_retries} after {wait:.1f}s")
                    safe_sleep(wait)
                    continue
                r.raise_for_status()

            r.raise_for_status()
            data = r.json()
            vulns = data.get("vulnerabilities", []) or []
            if not vulns:
                return None

            rec = extract_minimal_raw(vulns[0])
            if rec:
                rec["fetched_at"] = utc_now_iso()
            return rec

        except Exception as e:
            if attempt <= max_retries:
                print(f"[!] NVD fetch error (attempt {attempt}/{max_retries}): {e}")
                safe_sleep(backoff)
                backoff = min(backoff * 1.8, 60.0)
                continue
            raise


# ----------------------------- Anthropic Optimizer -----------------------------

class BatchOptimizer:
    def __init__(self, api_key: str, model: str):
        self.llm = ChatAnthropic(model=model, api_key=api_key, temperature=0)

    def invoke_retry(self, prompt: str, max_retries: int = 7) -> str:
        attempt = 0
        backoff = 2.0
        while True:
            attempt += 1
            try:
                resp = self.llm.invoke(prompt)
                return (resp.content or "").strip()
            except Exception as e:
                if attempt <= max_retries:
                    print(f"[!] Anthropic error (attempt {attempt}/{max_retries}): {e}")
                    safe_sleep(backoff)
                    backoff = min(backoff * 1.7, 45.0)
                    continue
                raise

    def optimize_batch(self, items: List[Dict]) -> List[Dict]:
        # items: [{"cve_id":..., "description_en":...}]
        payload = [{"cve_id": it["cve_id"], "description": it["description_en"]} for it in items]

        prompt = f"""You are processing CVE records for an exploit-focused security dataset.

TASK (for EACH item):
1) optimized_description: shorter description preserving ALL essential technical details.
2) exploit_schema: structured fields strictly extracted from the description (do NOT guess).

RULES for optimized_description:
- Preserve product/component, affected versions, vulnerability type, attack vector/prereqs, and impact if present.
- Remove filler/repetition. Keep it concise.
- Output ONLY the optimized description (no quotes, no headings).

RULES for exploit_schema:
Return STRICT JSON with exactly these keys:
product, component, version_range, vulnerability_type,
vulnerable_surface, root_cause, attacker_prerequisites,
exploit_primitive, impact, confidence

- If not explicitly stated, set value to "unknown"
- Do NOT infer
- confidence must be "explicit" or "partial"

OUTPUT FORMAT:
Return ONE JSON array only. Each element must be:
{{
  "cve_id": "...",
  "optimized_description": "...",
  "exploit_schema": {{
    "product": "...",
    "component": "...",
    "version_range": "...",
    "vulnerability_type": "...",
    "vulnerable_surface": "...",
    "root_cause": "...",
    "attacker_prerequisites": "...",
    "exploit_primitive": "...",
    "impact": "...",
    "confidence": "explicit|partial"
  }}
}}

INPUT ARRAY:
{json.dumps(payload, ensure_ascii=False)}
"""
        raw = strip_code_fences(self.invoke_retry(prompt))

        try:
            out = json.loads(raw)
            if isinstance(out, list):
                return out
        except Exception:
            pass

        # Fallback: extract [...]
        s = raw.find("[")
        e = raw.rfind("]")
        if s != -1 and e != -1 and e > s:
            try:
                out = json.loads(raw[s:e+1])
                if isinstance(out, list):
                    return out
            except Exception:
                pass

        # Malformed output fallback
        return [{
            "cve_id": it["cve_id"],
            "optimized_description": (it.get("description_en") or "")[:400],
            "exploit_schema": {
                "product": "unknown",
                "component": "unknown",
                "version_range": "unknown",
                "vulnerability_type": "unknown",
                "vulnerable_surface": "unknown",
                "root_cause": "unknown",
                "attacker_prerequisites": "unknown",
                "exploit_primitive": "unknown",
                "impact": "unknown",
                "confidence": "partial",
                "_raw_model_output": raw[:800],
            }
        } for it in items]


# ----------------------------- Functionality 1: DOWNLOAD -----------------------------

def cmd_download(args) -> None:
    raw_db = load_json_dict(args.raw_db)
    nvd_api_key = os.environ.get("NVD_API_KEY")

    use_last_mod = not args.use_pubdate

    start_dt = parse_date(args.start_date)
    end_dt = parse_date(args.end_date).replace(hour=23, minute=59, second=59)

    ckpt = load_checkpoint(args.checkpoint)
    resume_ok = (
        ckpt.get("start_date") == args.start_date and
        ckpt.get("end_date") == args.end_date and
        ckpt.get("use_last_mod") == use_last_mod
    )
    start_index = int(ckpt.get("start_index", 0)) if resume_ok else 0

    mode_label = "lastMod" if use_last_mod else "pubDate"
    print(f"\n[DOWNLOAD] Window: {args.start_date} -> {args.end_date} | mode={mode_label}")
    print(f"[DOWNLOAD] RAW DB: {args.raw_db}")
    print(f"[DOWNLOAD] Resume: {'YES' if resume_ok else 'NO'} | startIndex={start_index}\n")

    added = 0
    total_seen = int(ckpt.get("total_results", 0)) if resume_ok else 0

    while True:
        vulns, total, returned = nvd_list_window(
            start_dt=start_dt,
            end_dt=end_dt,
            start_index=start_index,
            results_per_page=args.results_per_page,
            use_last_mod=use_last_mod,
            nvd_api_key=nvd_api_key,
        )

        if total_seen == 0:
            total_seen = total

        if returned == 0:
            print("[DOWNLOAD] Done (no more results).")
            save_checkpoint(args.checkpoint, {
                "start_date": args.start_date,
                "end_date": args.end_date,
                "use_last_mod": use_last_mod,
                "start_index": start_index,
                "total_results": total_seen,
                "added": added,
                "done": True,
                "timestamp": utc_now_iso(),
            })
            break

        print(f"[DOWNLOAD] Page startIndex={start_index} returned={returned} total={total_seen}")

        for v in vulns:
            rec = extract_minimal_raw(v)
            if not rec:
                continue
            cid = rec["cve_id"]
            # Update or insert
            if cid not in raw_db:
                added += 1
            rec["stored_at"] = utc_now_iso()
            raw_db[cid] = rec

        # Save periodically per page (safe + resumable)
        save_json_dict(args.raw_db, raw_db)

        start_index += returned
        save_checkpoint(args.checkpoint, {
            "start_date": args.start_date,
            "end_date": args.end_date,
            "use_last_mod": use_last_mod,
            "start_index": start_index,
            "total_results": total_seen,
            "added": added,
            "done": False,
            "timestamp": utc_now_iso(),
        })

        safe_sleep(args.page_delay)


# ----------------------------- Functionality 2: OPTIMIZE (from RAW DB) -----------------------------

def cmd_optimize(args) -> None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not set.\nPowerShell: $env:ANTHROPIC_API_KEY='sk-ant-...'\n")
        return

    model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

    raw_db = load_json_dict(args.raw_db)
    opt_db = load_json_dict(args.opt_db)
    schema_db = {} if str(args.schema_db).lower() == "none" else load_json_dict(args.schema_db)

    optimizer = BatchOptimizer(api_key=api_key, model=model)

    # Determine target set
    target_ids: List[str]
    if args.cve:
        # explicit CVEs
        target_ids = []
        for token in args.cve:
            target_ids.extend(parse_cves_from_text(token))
        target_ids = sorted(set(target_ids))
    else:
        # default: optimize all raw CVEs (or only unoptimized if not --force)
        target_ids = sorted(raw_db.keys())

    
# Default behavior (no --force):
#   - optimize new CVEs not in opt_db
#   - ALSO refresh stale CVEs whose RAW lastModified is newer than OPT timestamp
# With --force:
#   - optimize everything in target_ids
    if not args.force:
       target_ids = [
           cid for cid in target_ids
           if (cid not in opt_db) or needs_reoptimize(cid, raw_db, opt_db)
    ]

    # optional filter: require description
    target_ids = [cid for cid in target_ids if raw_db.get(cid, {}).get("description_en")]

    print(f"\n[OPTIMIZE] RAW DB: {args.raw_db} ({len(raw_db)} CVEs)")
    print(f"[OPTIMIZE] OPT DB: {args.opt_db} ({len(opt_db)} optimized)")
    print(f"[OPTIMIZE] Model: {model}")
    print(f"[OPTIMIZE] Batch size: {args.batch_size}")
    print(f"[OPTIMIZE] Targets: {len(target_ids)}\n")


    stale_ids = [cid for cid in target_ids if cid in opt_db and needs_reoptimize(cid, raw_db, opt_db)]
    if stale_ids:
     print(f"[OPTIMIZE] Refreshing stale optimized CVEs: {len(stale_ids)}")


    ckpt = load_checkpoint(args.checkpoint)
    resume_ok = ckpt.get("mode") == "optimize" and ckpt.get("raw_db") == args.raw_db and ckpt.get("opt_db") == args.opt_db
    idx = int(ckpt.get("index", 0)) if resume_ok else 0

    processed = int(ckpt.get("processed", 0)) if resume_ok else 0

    while idx < len(target_ids):
        batch_ids = target_ids[idx: idx + args.batch_size]
        items = []
        for cid in batch_ids:
            desc = raw_db[cid].get("description_en")
            if not desc or len(desc.strip()) < args.min_desc_len:
                continue
            items.append({"cve_id": cid, "description_en": desc})

        if not items:
            idx += args.batch_size
            continue

        out = optimizer.optimize_batch(items)
        now = utc_now_iso()
        by_id = {o.get("cve_id", "").strip().upper(): o for o in out if isinstance(o, dict)}

        for it in items:
            cid = it["cve_id"]
            o = by_id.get(cid, {})
            opt_desc = (o.get("optimized_description") or "").strip()
            schema = o.get("exploit_schema") if isinstance(o.get("exploit_schema"), dict) else {}

            opt_db[cid] = {
                "optimized_description": opt_desc,
                "original_tokens": approx_tokens(it["description_en"]),
                "optimized_tokens": approx_tokens(opt_desc),
                "timestamp": now,
                "model": model,
            }
            processed += 1

            if schema_db is not None:
                schema["timestamp"] = now
                schema["model"] = model
                schema_db[cid] = schema

        # Persist after each batch (safe)
        save_json_dict(args.opt_db, opt_db)
        if schema_db is not None and str(args.schema_db).lower() != "none":
            save_json_dict(args.schema_db, schema_db)

        idx += args.batch_size
        save_checkpoint(args.checkpoint, {
            "mode": "optimize",
            "raw_db": args.raw_db,
            "opt_db": args.opt_db,
            "index": idx,
            "processed": processed,
            "timestamp": now,
        })

        print(f"[OPTIMIZE] processed={processed} / {len(target_ids)} | next_index={idx}")
        safe_sleep(args.llm_delay)
        print("\n[OPTIMIZE] Done.")

# ----------------------------- Functionality 3: ONE (local-first, else NVD fetch) -----------------------------

def cmd_one(args) -> None:
    """
    Interactive CVE query + optimization interface (optimized cache -> raw cache -> NVD fetch -> optimize).

    Behavior per requested CVE:
      1) If in OPT DB (cve_optimized.json) and not --force: print optimized_description and return
      2) Else if in RAW DB (cve_raw.json): optimize, save to OPT DB, print
      3) Else: fetch from NVD, save to RAW DB, optimize, save to OPT DB, print
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not set.\nPowerShell: $env:ANTHROPIC_API_KEY='sk-ant-...'\n")
        return

    model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
    nvd_api_key = os.environ.get("NVD_API_KEY")

    raw_db = load_json_dict(args.raw_db)
    opt_db = load_json_dict(args.opt_db)
    schema_db = {} if str(args.schema_db).lower() == "none" else load_json_dict(args.schema_db)

    optimizer = BatchOptimizer(api_key=api_key, model=model)

    def _save_opt_and_schema(cid: str, opt_desc: str, desc: str, schema: Dict) -> None:
        now = utc_now_iso()
        opt_db[cid] = {
            "optimized_description": opt_desc,
            "original_tokens": approx_tokens(desc),
            "optimized_tokens": approx_tokens(opt_desc),
            "timestamp": now,
            "model": model,
        }
        save_json_dict(args.opt_db, opt_db)

        if schema_db is not None and str(args.schema_db).lower() != "none":
            schema = schema or {}
            schema["timestamp"] = now
            schema["model"] = model
            schema_db[cid] = schema
            save_json_dict(args.schema_db, schema_db)

    def _print_opt(cid: str) -> None:
        rec = opt_db.get(cid, {}) or {}
        desc = (rec.get("optimized_description") or "").strip()
        if not desc:
            print(f"[ONE] No optimized_description stored for {cid}.")
            return
        print("\n" + "=" * 80)
        print(cid)
        print("-" * 80)
        print(desc)
        print("=" * 80 + "\n")

    def _ensure_raw(cid: str) -> Optional[Dict]:
        rec = raw_db.get(cid)
        if rec and rec.get("description_en"):
            return rec

        print(f"[ONE] {cid} not in local RAW DB (or missing description). Fetching from NVD...")
        fetched = nvd_fetch_by_id(cid, nvd_api_key=nvd_api_key)
        if not fetched or not fetched.get("description_en"):
            print(f"[ONE] Failed: no English description for {cid}.")
            return None

        fetched["stored_at"] = utc_now_iso()
        raw_db[cid] = fetched
        save_json_dict(args.raw_db, raw_db)
        print(f"[ONE] Saved RAW -> {args.raw_db}")
        return fetched

    def _optimize_and_cache(cid: str, desc: str) -> None:
        out = optimizer.optimize_batch([{"cve_id": cid, "description_en": desc}])
        by_id = {o.get("cve_id", "").strip().upper(): o for o in out if isinstance(o, dict)}
        o = by_id.get(cid, {}) or {}
        opt_desc = (o.get("optimized_description") or "").strip()
        schema = o.get("exploit_schema") if isinstance(o.get("exploit_schema"), dict) else {}

        _save_opt_and_schema(cid, opt_desc, desc, schema)
        _print_opt(cid)

    def handle_query(cve_text: str) -> None:
        cves = parse_cves_from_text(cve_text or "")
        if not cves:
            # also allow exact CVE id typed without extra text
            maybe = (cve_text or "").strip().upper()
            if re.fullmatch(r"CVE-\d{4}-\d{4,}", maybe):
                cves = [maybe]

        if not cves:
            print("[ONE] No CVE IDs found in input.")
            return

        for cid in sorted(set([c.strip().upper() for c in cves if c.strip()])):
            
            # 1) OPT cache (only if FRESH; if stale, fall through and re-optimize)
            if not args.force and cid in opt_db and not needs_reoptimize(cid, raw_db, opt_db):
                _print_opt(cid)
                continue

            # 2) RAW cache (or 3) NVD fetch)
            raw_rec = _ensure_raw(cid)
            if not raw_rec:
                continue

            desc = raw_rec.get("description_en") or ""
            if len(desc.strip()) < args.min_desc_len:
                print(f"[ONE] RAW description missing/too short for {cid}.")
                continue

            _optimize_and_cache(cid, desc)
            safe_sleep(args.llm_delay)

    # Interactive REPL mode
    if getattr(args, "interactive", False):
        print("\n[ONE] Interactive mode. Type CVE IDs (or paste text containing CVEs).")
        print("      Commands: exit | quit | q  (Ctrl-D / Ctrl-C also exits)\n")
        while True:
            try:
                line = input("CVE> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[ONE] Exiting.")
                break
            if not line:
                continue
            if line.lower() in ("exit", "quit", "q"):
                print("[ONE] Exiting.")
                break
            handle_query(line)
        return

    # Single-shot mode (requires --cve)
    if not args.cve:
        print("[ONE] Error: provide --cve CVE-YYYY-NNNN or run with --interactive.")
        return

    handle_query(args.cve)


# ----------------------------- Functionality 4: AUTO (Automatic daily updates) -----------------------------

def cmd_auto(args) -> None:
    """
    Automatic daily updates: runs download and optimize every 24 hours.
    Uses incremental updates based on lastModified date.
    """
    print("\n" + "="*80)
    print("CVE AUTO-UPDATER")
    print("="*80)
    print("This will run download and optimize automatically every 24 hours.")
    print(f"Will keep {args.days_back} days of history for incremental updates.")
    print(f"First run will process the last {args.days_back} days.")
    print("Press Ctrl+C to stop.\n")
    
    # Track run history
    run_log = []
    last_run_time = None
    
    def calculate_dates():
        """Calculate start and end dates for incremental update"""
        now = datetime.now(timezone.utc)
        end_date = now.strftime("%Y-%m-%d")
        
        if args.incremental and last_run_time:
            # Start from last run time (or 1 day back if first run)
            start_date = last_run_time.strftime("%Y-%m-%d")
        else:
            # Go back specified number of days for initial/full run
            start_date = (now - timedelta(days=args.days_back)).strftime("%Y-%m-%d")
        
        return start_date, end_date
    
    def run_update_cycle():
        """One complete update cycle: download + optimize"""
        nonlocal last_run_time
        
        cycle_start = datetime.now(timezone.utc)
        print(f"\n{'='*60}")
        print(f"UPDATE CYCLE STARTED: {cycle_start.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"{'='*60}")
        
        try:
            # Step 1: Download
            start_date, end_date = calculate_dates()
            print(f"[AUTO] Downloading CVEs from {start_date} to {end_date}")
            
            # Create download args
            class DownloadArgs:
                def __init__(self):
                    self.start_date = start_date
                    self.end_date = end_date
                    self.raw_db = args.raw_db
                    self.checkpoint = "auto_download_checkpoint.json"
                    self.results_per_page = args.results_per_page
                    self.use_pubdate = False  # Always use lastModified for incremental
                    self.page_delay = args.page_delay
            
            download_args = DownloadArgs()
            cmd_download(download_args)
            
            # Step 2: Optimize (only new/unoptimized)
            print(f"\n[AUTO] Optimizing new CVEs...")
            
            class OptimizeArgs:
                def __init__(self):
                    self.raw_db = args.raw_db
                    self.opt_db = args.opt_db
                    self.schema_db = args.schema_db
                    self.checkpoint = "auto_optimize_checkpoint.json"
                    self.batch_size = args.batch_size
                    self.min_desc_len = args.min_desc_len
                    self.llm_delay = args.llm_delay
                    self.force = False  # Only optimize unoptimized
                    self.cve = None
            
            optimize_args = OptimizeArgs()
            cmd_optimize(optimize_args)
            
            cycle_end = datetime.now(timezone.utc)
            duration = (cycle_end - cycle_start).total_seconds()
            last_run_time = cycle_end
            
            # Log this run
            run_log.append({
                "start": cycle_start.isoformat(),
                "end": cycle_end.isoformat(),
                "duration_seconds": duration,
                "dates": f"{start_date} to {end_date}"
            })
            
            # Save run log
            with open("auto_update_log.json", "w") as f:
                json.dump(run_log, f, indent=2)
            
            print(f"\n{'='*60}")
            print(f"UPDATE CYCLE COMPLETED in {duration:.1f} seconds")
            print(f"Next run in 24 hours at: {(cycle_end + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S UTC')}")
            print(f"{'='*60}\n")
            
        except Exception as e:
            print(f"\n[!] ERROR in update cycle: {e}")
            print(f"[!] Will retry in 1 hour")
            return False
        
        return True
    
    def run_once_now():
        """Run one update cycle immediately"""
        print("\n[AUTO] Running initial update now...")
        success = run_update_cycle()
        if success:
            print("[AUTO] Initial update completed successfully.")
        else:
            print("[AUTO] Initial update failed. Check logs.")
    
    # Setup scheduler
    print("[AUTO] Setting up scheduler...")
    
    # Run immediately on start
    if args.run_now:
        run_once_now()
    
    # Schedule daily updates
    schedule.every(24).hours.do(run_update_cycle)
    
    # Also schedule a health check every 6 hours
    def health_check():
        print(f"[AUTO] Health check at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[AUTO] Next update: {schedule.next_run()}")
        print(f"[AUTO] Total runs so far: {len(run_log)}")
    
    schedule.every(6).hours.do(health_check)
    
    print(f"[AUTO] Scheduled daily updates at: {schedule.next_run()}")
    print(f"[AUTO] Health checks every 6 hours")
    print(f"[AUTO] Log file: auto_update_log.json")
    print("\n[AUTO] Running scheduler. Press Ctrl+C to exit...")
    
    # Main scheduler loop
    try:
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    except KeyboardInterrupt:
        print("\n[AUTO] Shutting down...")
        print(f"[AUTO] Completed {len(run_log)} update cycles")
        if run_log:
            last_run = run_log[-1]
            print(f"[AUTO] Last run: {last_run['dates']} ({last_run['duration_seconds']:.1f}s)")
    except Exception as e:
        print(f"\n[AUTO] Fatal error: {e}")




# ----------------------------- Functionality 5: AGENT (Query-focused around ONE) -----------------------------

def cmd_agent(args) -> None:
    """
    Interactive query-focused LangChain agent built around the SAME dataflow as `one`.
    This does not change other commands; it adds a new `agent` command.
    """
    try:
        from langchain_core.tools import tool
        from langchain_core.prompts import ChatPromptTemplate
        from langchain.agents import AgentExecutor, create_tool_calling_agent
    except Exception as e:
        print("[AGENT] Missing LangChain packages. Install: pip install langchain langchain-core")
        print(f"[AGENT] Import error: {e}")
        return

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not set. PowerShell: $env:ANTHROPIC_API_KEY='sk-ant-...'\n")
        return

    model = args.model or os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
    llm = ChatAnthropic(model=model, api_key=api_key, temperature=0)

    raw_db_path = args.raw_db
    opt_db_path = args.opt_db
    schema_db_path = args.schema_db

    @tool("cve_lookup", return_direct=True)
    def cve_lookup(text: str, force: bool = False) -> str:
        """Lookup CVEs in text and return optimized descriptions (and schema if enabled)."""
        nvd_api_key = os.environ.get("NVD_API_KEY")

        raw_db: Dict[str, any] = load_json_dict(raw_db_path)
        opt_db: Dict[str, any] = load_json_dict(opt_db_path)
        schema_db = None if str(schema_db_path).lower() == "none" else load_json_dict(schema_db_path)

        cves = parse_cves_from_text(text or "")
        if not cves:
            maybe = (text or "").strip().upper()
            if re.fullmatch(r"CVE-\d{4}-\d{4,}", maybe):
                cves = [maybe]
        cves = sorted(set([c.strip().upper() for c in cves if c.strip()]))
        if not cves:
            return "No CVE IDs found. Example: CVE-2026-24635"

        optimizer = BatchOptimizer(api_key=api_key, model=model)

        def ensure_raw(cid: str) -> Optional[Dict]:
            rec = raw_db.get(cid)
            if rec and rec.get("description_en"):
                return rec
            fetched = nvd_fetch_by_id(cid, nvd_api_key=nvd_api_key)
            if not fetched or not fetched.get("description_en"):
                return None
            fetched["stored_at"] = utc_now_iso()
            raw_db[cid] = fetched
            save_json_dict(raw_db_path, raw_db)
            return fetched

        def save_opt_and_schema(cid: str, opt_desc: str, raw_desc: str, schema: Dict) -> None:
            now = utc_now_iso()
            opt_db[cid] = {
                "optimized_description": opt_desc,
                "original_tokens": approx_tokens(raw_desc),
                "optimized_tokens": approx_tokens(opt_desc),
                "timestamp": now,
                "model": model,
            }
            save_json_dict(opt_db_path, opt_db)
            if schema_db is not None and str(schema_db_path).lower() != "none":
                schema = schema or {}
                schema["timestamp"] = now
                schema["model"] = model
                schema_db[cid] = schema
                save_json_dict(schema_db_path, schema_db)

        def fmt_dt(dt):
            if not dt:
                return "unknown"
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

        reports: List[str] = []
        for cid in cves:
            if (not force) and (cid in opt_db) and (not needs_reoptimize(cid, raw_db, opt_db)):
                raw_lm = iso_to_dt(raw_db.get(cid, {}).get("lastModified"))
                opt_ts = iso_to_dt(opt_db.get(cid, {}).get("timestamp"))
                opt_desc = (opt_db.get(cid, {}) or {}).get("optimized_description", "").strip()
                reports.append("\n".join([
                    "=" * 80,
                    f"{cid}  [cache_hit:fresh]",
                    f"raw.lastModified: {fmt_dt(raw_lm)}",
                    f"opt.timestamp:    {fmt_dt(opt_ts)}",
                    "-" * 80,
                    opt_desc if opt_desc else "(no optimized_description stored)",
                    "=" * 80,
                ]))
                continue

            raw_rec = ensure_raw(cid)
            if not raw_rec:
                reports.append("\n".join([
                    "=" * 80,
                    f"{cid}  [error]",
                    "-" * 80,
                    "Unable to fetch RAW from NVD or English description missing.",
                    "=" * 80,
                ]))
                continue

            raw_desc = (raw_rec.get("description_en") or "").strip()
            if len(raw_desc) < args.min_desc_len:
                reports.append("\n".join([
                    "=" * 80,
                    f"{cid}  [error]",
                    "-" * 80,
                    "RAW description missing/too short to optimize.",
                    "=" * 80,
                ]))
                continue

            out = optimizer.optimize_batch([{"cve_id": cid, "description_en": raw_desc}])
            by_id = {o.get("cve_id", "").strip().upper(): o for o in out if isinstance(o, dict)}
            o = by_id.get(cid, {}) or {}
            opt_desc = (o.get("optimized_description") or "").strip()
            schema = o.get("exploit_schema") if isinstance(o.get("exploit_schema"), dict) else {}

            save_opt_and_schema(cid, opt_desc, raw_desc, schema)

            raw_lm = iso_to_dt(raw_rec.get("lastModified"))
            opt_ts = iso_to_dt(opt_db.get(cid, {}).get("timestamp"))

            reports.append("\n".join([
                "=" * 80,
                f"{cid}  [optimized:{'forced' if force else 'updated_or_missing'}]",
                f"raw.lastModified: {fmt_dt(raw_lm)}",
                f"opt.timestamp:    {fmt_dt(opt_ts)}",
                "-" * 80,
                opt_desc if opt_desc else "(no optimized_description produced)",
                "=" * 80,
            ]))

        return "\n\n".join(reports)

    tools = [cve_lookup]
    system = (
        "You are a CVE query assistant. When the user provides a CVE ID or text containing CVE IDs, "
        "you MUST call cve_lookup. Do not invent CVE details; rely on the tool output."
    )
    prompt = ChatPromptTemplate.from_messages([
        ("system", system),
        ("human", "{input}"),
    ])
    agent = create_tool_calling_agent(llm=llm, tools=tools, prompt=prompt)
    executor = AgentExecutor(agent=agent, tools=tools, verbose=False)

    print("\n[CVE AGENT] Query mode. Paste CVE IDs or text containing CVEs.")
    print("           Commands: exit | quit | q  (Ctrl-D/Ctrl-C also exits)\n")
    while True:
        try:
            user_in = input("CVE> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[CVE AGENT] Exiting.")
            break
        if not user_in:
            continue
        if user_in.lower() in ("exit", "quit", "q"):
            print("[CVE AGENT] Exiting.")
            break
        try:
            out = executor.invoke({"input": user_in})
            print((out.get("output", "") or "").rstrip() + "\n")
        except Exception as e:
            print(f"[CVE AGENT] Error: {e}\n")


# ----------------------------- CLI -----------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="CVE program: download | optimize | one | auto")
    sub = p.add_subparsers(dest="cmd", required=True)

    # download
    d = sub.add_parser("download", help="Download CVEs from NVD into RAW JSON dict DB")
    d.add_argument("--start-date", required=True, help="YYYY-MM-DD")
    d.add_argument("--end-date", required=True, help="YYYY-MM-DD")
    d.add_argument("--raw-db", default="cve_raw.json", help="RAW JSON dict file")
    d.add_argument("--checkpoint", default="download_checkpoint.json", help="Checkpoint file")
    d.add_argument("--results-per-page", type=int, default=2000)
    d.add_argument("--use-pubdate", action="store_true", help="Use published date window instead of lastModified")
    d.add_argument("--page-delay", type=float, default=1.0)

    # optimize
    o = sub.add_parser("optimize", help="Optimize CVEs from RAW DB into OPT DB (batch LLM)")
    o.add_argument("--raw-db", default="cve_raw.json")
    o.add_argument("--opt-db", default="cve_optimized.json")
    o.add_argument("--schema-db", default="cve_schema.json", help="Use 'none' to disable schema output")
    o.add_argument("--checkpoint", default="optimize_checkpoint.json")
    o.add_argument("--batch-size", type=int, default=10)
    o.add_argument("--min-desc-len", type=int, default=20)
    o.add_argument("--llm-delay", type=float, default=0.0)
    o.add_argument("--force", action="store_true")
    o.add_argument("--cve", nargs="*", help="Optional: optimize only these CVE IDs (space separated)")

    # one
    one = sub.add_parser("one", help="Interactive CVE query + optimization (optimized -> raw -> NVD -> optimize)")
    one.add_argument("--cve", required=False, help="CVE ID like CVE-2026-24635 (omit when using --interactive)")
    one.add_argument("--interactive", action="store_true", help="Run an interactive CVE query terminal (REPL)")
    one.add_argument("--raw-db", default="cve_raw.json")
    one.add_argument("--opt-db", default="cve_optimized.json")
    one.add_argument("--schema-db", default="cve_schema.json", help="Use 'none' to disable schema output")
    one.add_argument("--min-desc-len", type=int, default=20)
    one.add_argument("--llm-delay", type=float, default=0.0)
    one.add_argument("--force", action="store_true")

    # auto
    auto = sub.add_parser("auto", help="Automatic daily updates (download + optimize every 24 hours)")
    auto.add_argument("--days-back", type=int, default=7, 
                     help="Number of days to look back for initial download (default: 7)")
    auto.add_argument("--raw-db", default="cve_raw.json")
    auto.add_argument("--opt-db", default="cve_optimized.json")
    auto.add_argument("--schema-db", default="cve_schema.json", help="Use 'none' to disable schema output")
    auto.add_argument("--checkpoint", default="auto_checkpoint.json", help="Auto-update checkpoint")
    auto.add_argument("--batch-size", type=int, default=10)
    auto.add_argument("--min-desc-len", type=int, default=20)
    auto.add_argument("--llm-delay", type=float, default=0.0)
    auto.add_argument("--results-per-page", type=int, default=2000)
    auto.add_argument("--page-delay", type=float, default=1.0)
    auto.add_argument("--run-now", action="store_true", 
                     help="Run update immediately on start (default: wait 24 hours)")
    auto.add_argument("--incremental", action="store_true", default=True,
                     help="Use incremental updates based on last run time (enabled by default)")

    # agent (query-focused around `one`)
    ag = sub.add_parser("agent", help="Interactive LangChain agent for CVE queries (built on the `one` workflow)")
    ag.add_argument("--raw-db", default="cve_raw.json")
    ag.add_argument("--opt-db", default="cve_optimized.json")
    ag.add_argument("--schema-db", default="cve_schema.json", help="Use 'none' to disable schema output")
    ag.add_argument("--min-desc-len", type=int, default=20)
    ag.add_argument("--model", default=None, help="Override ANTHROPIC_MODEL for the agent")

    return p
def main() -> None:
    args = build_parser().parse_args()

    if args.cmd == "download":
        cmd_download(args)
    elif args.cmd == "optimize":
        cmd_optimize(args)
    elif args.cmd == "one":
        cmd_one(args)
    elif args.cmd == "auto":
        cmd_auto(args)


    elif args.cmd == "agent":
        cmd_agent(args)
if __name__ == "__main__":
    # Install required package if not present
    try:
        import schedule
    except ImportError:
        print("Installing required package: schedule...")
        import subprocess
        subprocess.check_call(["pip", "install", "schedule"])
        import schedule
    
    main()