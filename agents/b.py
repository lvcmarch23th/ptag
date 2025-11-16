#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, os, json, re, logging, subprocess, yaml, time
from typing import List, Dict, Any, Optional, Set
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# project utils
from utils.merge_scores import merge
from utils.version_limit import get_affected_cve
from utils.model_manager import get_model  # dùng cho LLM

# (nếu dùng LangChain chat models)
try:
    from langchain_core.messages import HumanMessage
except Exception:
    HumanMessage = None  # fallback invoke(string)

logger = logging.getLogger(__name__)

# ------------------------------ Load config ------------------------------ #

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'configs', 'config.yaml')
with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
    CONFIG = yaml.safe_load(f)

summarize_config: Dict[str, Any] = CONFIG.get('runtime', {}).get('summarize', {}) or {}
cvemap_config: Dict[str, Any]   = summarize_config.get('cvemap', {}) or {}
exploitdb_cfg: Dict[str, Any]   = summarize_config.get('exploitdb', {}) or {}
llm_v_cfg: Dict[str, Any]       = summarize_config.get('llm_verifier', {}) or {}

# ------------------------------ Utils ------------------------------ #

def normalize_ws(s: str) -> str:
    return re.sub(r'\s+', ' ', (s or '')).strip()

def extract_json_loose(s: str) -> Optional[dict]:
    m = re.search(r'```json\s*(\{[\s\S]*?\})\s*```', s)
    if m: s = m.group(1)
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        m2 = re.search(r'(\{(?:[^{}]|(?1))*\})', s)
        if m2:
            try:
                return json.loads(m2.group(1))
            except json.JSONDecodeError:
                return None
        return None

def compact_text(*parts: str, max_chars: int = 2000) -> str:
    text = normalize_ws(" | ".join([p for p in parts if p]))
    if len(text) > max_chars:
        text = text[:max_chars] + " ..."
    return text

# ------------------------------ CVEMAP ------------------------------ #

def cvemap_product_by_keyword(keyword: str, output_dir: str, cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    os.makedirs(output_dir, exist_ok=True)
    out_json = os.path.join(output_dir, "cvemap.json")
    term = normalize_ws(keyword)
    if not term:
        raise ValueError("Empty keyword for cvemap")

    query_type = '-q' if cfg.get("fuzzy_search", False) else '-p'
    all_results: List[Dict[str, Any]] = []
    limit = 50
    offset = 0

    min_year = int(cfg.get("min_year", 0) or 0)
    max_year = int(cfg.get("max_year", 9999) or 9999)
    max_entry = int(cfg.get("max_entry", 0) or 0)

    while True:
        if max_entry and len(all_results) >= max_entry:
            break

        cmd = ["cvemap", query_type, term, "-l", str(limit), "-offset", str(offset), "-j"]
        try:
            run = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
            batch = json.loads(run.stdout) if run.stdout.strip() else []
            if not batch:
                break

            filtered = []
            for item in batch:
                cve_id = item.get("cve_id", "")
                try:
                    year = int(cve_id.split("-")[1])
                except (IndexError, ValueError):
                    year = None

                if year is not None:
                    if year > max_year or year < min_year:
                        continue

                filtered.append(item)
                if max_entry and (len(all_results) + len(filtered) >= max_entry):
                    break

            all_results.extend(filtered)

            if len(batch) < limit or (max_entry and len(all_results) >= max_entry):
                break
            offset += limit

        except subprocess.CalledProcessError as e:
            print("[ERROR] cvemap failed.")
            print("STDOUT:", e.stdout)
            print("STDERR:", e.stderr)
            raise
        except json.JSONDecodeError:
            print(f"[WARNING] Failed to decode JSON at offset {offset}")
            break

    if max_entry:
        all_results = all_results[:max_entry]

    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    return all_results

# ------------------------------ Exploit-DB ------------------------------ #

def has_searchsploit() -> bool:
    try:
        subprocess.run(["searchsploit", "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        return True
    except Exception:
        return False

def parse_exploitdb_json_for_cves(obj: Any) -> Set[str]:
    out: Set[str] = set()
    if not isinstance(obj, dict):
        return out
    cve_re = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    for key in ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE"):
        arr = obj.get(key) or []
        if not isinstance(arr, list):
            continue
        for row in arr:
            if not isinstance(row, dict): 
                continue
            text = " ".join(str(row.get(k, "")) for k in ("Title", "Path", "URL"))
            for m in cve_re.findall(text):
                out.add(m.upper())
    return out

def searchsploit_query_json(query: str, timeout: int = 25) -> Optional[dict]:
    q = normalize_ws(query)
    if not q:
        return None
    try:
        p = subprocess.run(["searchsploit", "-j", q], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        if not p.stdout.strip():
            return None
        return json.loads(p.stdout)
    except Exception:
        return None

def exploitdb_collect_cves(keyword: str, version: str, extra_queries: List[str], timeout: int = 25) -> Set[str]:
    cves: Set[str] = set()
    if version:
        d = searchsploit_query_json(f"{keyword} {version}", timeout=timeout)
        if d: cves |= parse_exploitdb_json_for_cves(d)
    d = searchsploit_query_json(keyword, timeout=timeout)
    if d: cves |= parse_exploitdb_json_for_cves(d)
    for q in (extra_queries or []):
        d = searchsploit_query_json(q, timeout=timeout)
        if d: cves |= parse_exploitdb_json_for_cves(d)
    return cves

# ------------------------------ LLM Verifier ------------------------------ #

def llm_verify_single(llm, cve_item: Dict[str, Any], keyword: str, version: str, drop_on_uncertain: bool) -> Optional[bool]:
    """
    Trả về:
      True  -> giữ (có ảnh hưởng)
      False -> loại
      None  -> lỗi/không chắc (tuỳ drop_on_uncertain mà quyết định ngoài)
    """
    cve_id = cve_item.get("cve_id", "")
    title = cve_item.get("title") or cve_item.get("summary") or ""
    desc  = cve_item.get("description") or cve_item.get("details") or ""
    refs  = ", ".join(cve_item.get("references") or [])
    text  = compact_text(title, desc, refs, max_chars=1800)

    # Prompt gọn, ép JSON
    ask_version = f' and version "{version}"' if version else ''
    prompt = f"""You are a security analyst. Decide if CVE applies to a product.
Product keyword: "{keyword}"{ask_version}
CVE: {cve_id}
CVE text (title/description/refs, shortened): "{text}"

Return STRICT JSON with keys:
{{
  "cve_id": "{cve_id}",
  "match_product": true/false,
  "match_version": true/false/"n/a",
  "affected": true/false/"uncertain",
  "reason": "one short sentence citing concrete version/product evidence"
}}
Rules:
- If keyword clearly matches the vulnerable product/component in the CVE, set match_product=true; else false.
- If no version info supplied to you, set match_version="n/a".
- "affected" must be true ONLY when both product matches and (if version provided) version condition is satisfied by the vulnerable ranges explicitly stated in the CVE text. If evidence insufficient, set "uncertain".
- Be strict; do NOT guess.
"""

    try:
        if HumanMessage is not None:
            resp = llm.invoke([HumanMessage(content=prompt)], timeout=180)
            content = getattr(resp, "content", None) or str(resp)
        else:
            content = str(llm.invoke(prompt, timeout=180))
    except Exception as e:
        logger.warning(f"LLM call failed for {cve_id}: {e}")
        return None

    data = extract_json_loose(content) or {}
    affected = data.get("affected")
    match_product = data.get("match_product")
    match_version = data.get("match_version")

    logger.info(f"[LLM-VERIFY] {cve_id} -> affected={affected}, match_product={match_product}, match_version={match_version} | reason={data.get('reason','')[:200]}")

    if affected is True:
        return True
    if affected is False:
        return False
    # uncertain
    return None if drop_on_uncertain else True  # nếu không drop khi uncertain thì giữ lại

def llm_filter_items(items: List[Dict[str, Any]], keyword: str, version: str, cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not items:
        return items
    if not cfg.get("enabled", False):
        return items

    # init model (dùng model của summarize)
    try:
        llm = get_model(summarize_config.get('model', 'openai'))
    except Exception as e:
        logger.warning(f"Cannot init LLM for verifier: {e}")
        return items

    max_checks   = int(cfg.get("max_checks", 60) or 60)
    drop_uncertain = bool(cfg.get("drop_on_uncertain", False))
    delay_s      = float(cfg.get("delay_seconds", 0))

    kept: List[Dict[str, Any]] = []
    checked = 0
    for it in items:
        if checked >= max_checks:
            kept.append(it)
            continue
        res = llm_verify_single(llm, it, keyword, version, drop_uncertain)
        checked += 1
        if res is True:
            kept.append(it)
        elif res is False:
            # drop
            pass
        else:
            # None -> error/uncertain
            if drop_uncertain:
                pass
            else:
                kept.append(it)
        if delay_s > 0:
            time.sleep(delay_s)

    logger.info(f"LLM verifier: {len(items)} -> {len(kept)} (checked={checked}, drop_uncertain={drop_uncertain})")
    return kept

# ------------------------------- MAIN -------------------------------------- #

def main():
    """
    Outputs (GIỮ NGUYÊN):
      - <output_root>/<target_name>/summarize/CVEMAP/cvemap.json
      - <output_root>/<target_name>/summarize/cve_list.json
    """
    # ---- Build base dirs ----
    keyword      = normalize_ws(summarize_config.get('keyword') or '')
    version      = normalize_ws(summarize_config.get('version') or '')
    output_root  = summarize_config.get('output_root', 'output')
    target_name  = summarize_config.get('target_name', 'target_1')

    base_dir       = os.path.join(output_root, target_name)
    summarize_dir  = os.path.join(base_dir, "summarize")
    cvemap_dir     = os.path.join(summarize_dir, "CVEMAP")
    logs_dir       = os.path.join(base_dir, "logs")

    for d in (base_dir, summarize_dir, cvemap_dir, logs_dir):
        os.makedirs(d, exist_ok=True)

    # ---- logging ----
    log_file_path = os.path.join(logs_dir, "summarize_agent.log")
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filename=log_file_path,
        level=logging.INFO
    )
    logger.info("Logging to %s", log_file_path)

    if not keyword:
        logger.error("No keyword provided. Please set runtime.summarize.keyword in configs/config.yaml")
        print("ERROR: runtime.summarize.keyword is required.")
        sys.exit(1)

    # optional: warm model (để sẵn env)
    try:
        _ = get_model(summarize_config.get('model', 'openai'))
        logger.info("Model loaded (warm, optional).")
    except Exception as e:
        logger.warning("Model warm init failed: %s", e)

    logger.info("Start summarize for target='%s' keyword='%s' version='%s'", target_name, keyword, version or "<none>")

    # 1) CVEMAP
    cvemap_res = cvemap_product_by_keyword(keyword, cvemap_dir, cvemap_config)

    # 2) Merge/unique
    try:
        merged = merge(cvemap_res) if cvemap_res else []
    except Exception:
        merged = cvemap_res or []

    # 3) Version filter (deterministic)
    items = merged
    if version:
        try:
            items = get_affected_cve(merged or [], version)
            logger.info("Version filter: %d -> %d", len(merged), len(items))
        except Exception as e:
            logger.warning("Version filter failed: %s; fallback merged.", e)
            items = merged

    # 4) Exploit-DB combine
    cvemap_ids_order = [it.get("cve_id") for it in items if it.get("cve_id")]
    cvemap_set = set(cvemap_ids_order)

    if exploitdb_cfg.get("enabled", False):
        if has_searchsploit():
            ex_timeout = int(exploitdb_cfg.get("timeout", 25) or 25)
            extra_q    = exploitdb_cfg.get("extra_queries") or []
            ex_set     = exploitdb_collect_cves(keyword, version, extra_q, timeout=ex_timeout)
            mode       = str(exploitdb_cfg.get("mode", "intersect")).lower().strip()
            if mode == "union":
                only_ex = [c for c in sorted(ex_set) if c not in cvemap_set]
                combined_ids = cvemap_ids_order + only_ex
            else:
                combined_ids = [c for c in cvemap_ids_order if c in ex_set]
            logger.info("Exploit-DB combine (%s): %d -> %d", mode, len(cvemap_ids_order), len(combined_ids))
        else:
            logger.warning("searchsploit not found; skip Exploit-DB combine.")
            combined_ids = cvemap_ids_order
    else:
        combined_ids = cvemap_ids_order

    # map id -> item (lấy từ items; nếu union có phần chỉ ở Exploit-DB thì sẽ không có desc chi tiết — vẫn giữ id)
    by_id = {it.get("cve_id"): it for it in items if it.get("cve_id")}
    items_for_llm = [by_id.get(cid, {"cve_id": cid}) for cid in combined_ids]

    # 5) LLM verifier (giảm FP)
    items_final = llm_filter_items(items_for_llm, keyword, version, llm_v_cfg)

    final_ids = [it.get("cve_id") for it in items_final if it.get("cve_id")]
    if not final_ids:
        logger.warning("No CVE after all filters. Consider relaxing config.")

    # 6) Write only cve_list.json
    cve_list_json_path = os.path.join(summarize_dir, "cve_list.json")
    with open(cve_list_json_path, "w", encoding="utf-8") as fj:
        json.dump(
            {
                "keyword": keyword,
                "version_filter": version or None,
                "count": len(final_ids),
                "cves": final_ids
            },
            fj, indent=2, ensure_ascii=False
        )

    logger.info("Saved %d CVEs -> %s", len(final_ids), cve_list_json_path)
    logger.info("Done. Outputs under summarize/. Logs: %s", log_file_path)
    print(f"Done. See outputs in: {cve_list_json_path}")
    print(f"Logs: {log_file_path}")

if __name__ == "__main__":
    main()
