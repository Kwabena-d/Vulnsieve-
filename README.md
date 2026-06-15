# VulnSieve CVE Program

A command-line tool for fetching, compressing, and querying CVE records from the NVD (National Vulnerability Database) using the Anthropic Claude API. Built for multi-agent penetration testing pipelines where token efficiency matters.

---

## Overview

Raw NVD CVE descriptions are verbose — typically 300–800 words. This program compresses each record to a compact, exploit-focused representation (~50 tokens) while preserving all technically relevant fields. It also extracts a structured **exploit schema** per CVE, suitable for downstream agent consumption.

The program supports five operational modes:

| Command    | Purpose |
|------------|---------|
| `download` | Bulk-fetch CVEs from NVD into a local raw JSON database |
| `optimize` | Batch-compress raw CVEs using Claude; output optimized descriptions and exploit schemas |
| `one`      | Lookup or optimize a single CVE (cache-first, NVD fallback) |
| `auto`     | Scheduled daemon: download + optimize every 24 hours |
| `agent`    | Interactive LangChain agent for natural-language CVE queries |

---

## Requirements

### Python

Python 3.8+

### Dependencies

```
pip install requests langchain-anthropic langchain schedule
```

### API Keys

| Variable            | Required | Description |
|---------------------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes      | Anthropic API key (`sk-ant-...`) |
| `NVD_API_KEY`       | No       | Raises NVD rate limit from 5 to 50 req/30s |
| `ANTHROPIC_MODEL`   | No       | Defaults to `claude-sonnet-4-20250514` |

**Setting environment variables:**

```bash
# Linux / macOS
export ANTHROPIC_API_KEY="sk-ant-..."
export NVD_API_KEY="your-nvd-key"

# Windows PowerShell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
$env:NVD_API_KEY = "your-nvd-key"
```

---

## Output Files

Three JSON files are maintained as local databases:

| File                    | Contents |
|-------------------------|----------|
| `cve_raw.json`          | Raw CVE records from NVD (minimal extracted fields) |
| `cve_optimized.json`    | Compressed descriptions + token counts per CVE |
| `cve_schema.json`       | Structured exploit schemas (10-field JSON per CVE) |
| `*_checkpoint.json`     | Resume state for interrupted downloads/optimizations |

All writes use atomic temp-file replacement to prevent corruption on interruption.

---

## Commands

### `download` — Fetch CVEs from NVD

Downloads CVE records for a given date window and stores them in the raw database. Supports resuming interrupted downloads via checkpoint.

```bash
python CVE_Vulnsieve.py download --start-date 2026-01-01 --end-date 2026-01-31
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--start-date` | *(required)* | Start of window (`YYYY-MM-DD`) |
| `--end-date` | *(required)* | End of window (`YYYY-MM-DD`) |
| `--raw-db` | `cve_raw.json` | Output raw database file |
| `--checkpoint` | `download_checkpoint.json` | Resume file |
| `--results-per-page` | `2000` | NVD page size (max 2000) |
| `--use-pubdate` | off | Filter by published date instead of last-modified date |
| `--page-delay` | `1.0` | Seconds to wait between NVD pages |

---

### `optimize` — Compress CVEs with Claude

Reads raw CVE descriptions from the raw database and sends them to Claude in batches. Outputs a compressed description and a structured exploit schema for each CVE. Skips already-optimized CVEs unless their raw record has been updated since last optimization.

```bash
python CVE_Vulnsieve.py optimize --batch-size 10
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--raw-db` | `cve_raw.json` | Source raw database |
| `--opt-db` | `cve_optimized.json` | Destination optimized database |
| `--schema-db` | `cve_schema.json` | Exploit schema output (use `none` to disable) |
| `--checkpoint` | `optimize_checkpoint.json` | Resume file |
| `--batch-size` | `10` | CVEs per Claude API call |
| `--min-desc-len` | `20` | Skip CVEs with descriptions shorter than this |
| `--llm-delay` | `0.0` | Seconds to wait between batches |
| `--force` | off | Re-optimize all CVEs, even if already current |
| `--cve` | *(all)* | Space-separated list of specific CVE IDs to optimize |

---

### `one` — Single CVE lookup or optimization

Retrieves a single CVE using a three-tier cache strategy:
1. Optimized cache hit → return immediately (no API call)
2. Raw cache hit → optimize with Claude, cache result
3. Not cached → fetch from NVD, cache raw, optimize, cache result

Also supports an interactive REPL mode for querying multiple CVEs in sequence.

```bash
# Single CVE
python CVE_Vulnsieve.py one --cve CVE-2026-24635

# Interactive terminal
python CVE_Vulnsieve.py one --interactive
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--cve` | *(none)* | CVE ID to look up |
| `--interactive` | off | Start interactive REPL session |
| `--raw-db` | `cve_raw.json` | Raw database path |
| `--opt-db` | `cve_optimized.json` | Optimized database path |
| `--schema-db` | `cve_schema.json` | Schema database path |
| `--min-desc-len` | `20` | Minimum description length to attempt optimization |
| `--force` | off | Re-optimize even if a fresh cached result exists |

---

### `auto` — Scheduled daily updates

Runs download + optimize on a 24-hour schedule. Uses incremental updates by default, fetching only CVEs modified since the last run. Optionally runs once immediately on startup with `--run-now`.

```bash
python CVE_Vulnsieve.py auto --days-back 7 --run-now
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--days-back` | `7` | Days to look back on initial download |
| `--raw-db` | `cve_raw.json` | Raw database path |
| `--opt-db` | `cve_optimized.json` | Optimized database path |
| `--schema-db` | `cve_schema.json` | Schema database path |
| `--checkpoint` | `auto_checkpoint.json` | Auto-update state file |
| `--batch-size` | `10` | CVEs per Claude batch |
| `--run-now` | off | Execute immediately on start instead of waiting 24h |
| `--incremental` | on | Use last-run timestamp for delta updates |

---

### `agent` — Interactive LangChain agent

Starts a conversational agent backed by LangChain's tool-calling framework. Accepts free-text queries containing CVE IDs and resolves them through the same three-tier cache strategy as `one`. The agent will not hallucinate CVE details — it relies exclusively on the tool output.

```bash
python CVE_Vulnsieve.py agent
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--raw-db` | `cve_raw.json` | Raw database path |
| `--opt-db` | `cve_optimized.json` | Optimized database path |
| `--schema-db` | `cve_schema.json` | Schema database path |
| `--model` | env `ANTHROPIC_MODEL` | Override Claude model for agent only |

**Example session:**
```
CVE> Tell me about CVE-2026-24635 and CVE-2025-12345
[agent fetches and returns optimized descriptions for both]

CVE> exit
```

---

## Exploit Schema

Each CVE is extracted into a 10-field structured schema. Fields are set to `"unknown"` if not explicitly stated in the source description — no inference is performed.

```json
{
  "product": "...",
  "component": "...",
  "version_range": "...",
  "vulnerability_type": "...",
  "vulnerable_surface": "...",
  "root_cause": "...",
  "attacker_prerequisites": "...",
  "exploit_primitive": "...",
  "impact": "...",
  "confidence": "explicit | partial"
}
```

---

## Resilience

- **Exponential backoff** with jitter on all NVD and Anthropic API calls
- **Checkpoint files** allow interrupted downloads and optimizations to resume exactly where they stopped
- **Stale-detection** re-optimizes CVEs whose raw record has been updated after their optimization timestamp
- **Atomic file writes** via temp-file + rename prevent database corruption

---

## Project Context

This tool is part of the **VulnSieve** research system, published at SPIE Defense + Security (April 2026). VulnSieve addresses the problem of LLM recall unreliability on CVE data — models recall CVE details correctly only ~7.5% of the time unaided. By pre-processing and compressing NVD records into structured, token-efficient representations, VulnSieve enables reliable CVE-grounded reasoning in multi-agent penetration testing pipelines.
