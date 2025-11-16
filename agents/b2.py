#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.merge_scores import merge
from utils.version_limit import get_affected_cve
from utils.model_manager import get_model  # optional: chỉ để giữ tương thích môi trường

import json
import logging
import subprocess
import yaml
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# ------------------------------ Load config ------------------------------ #

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'configs', 'config.yaml')
with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
    CONFIG = yaml.safe_load(f)

summarize_config: Dict[str, Any] = CONFIG.get('runtime', {}).get('summarize', {}) or {}
cvemap_config: Dict[str, Any]   = summarize_config.get('cvemap', {}) or {}

# ------------------------------ CVEMAP CLI wrapper ----------------------- #

def cvemap_product_by_keyword(keyword: str, output_dir: str, cvemap_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Gọi `cvemap` để lấy danh sách CVE theo keyword/product (KHÔNG truyền version vào CLI),
    phân trang bằng -l/-offset, lọc theo năm (min_year/max_year), và lưu full
    kết quả vào output_dir/cvemap.json. Trả về list này.
    """
    os.makedirs(output_dir, exist_ok=True)
    out_json = os.path.join(output_dir, "cvemap.json")
    term = (keyword or "").strip()
    if not term:
        raise ValueError("Empty keyword for cvemap")

    query_type = '-q' if cvemap_cfg.get("fuzzy_search", False) else '-p'
    all_results: List[Dict[str, Any]] = []
    limit = 50
    offset = 0

    min_year = int(cvemap_cfg.get("min_year", 0) or 0)
    max_year = int(cvemap_cfg.get("max_year", 9999) or 9999)
    max_entry = int(cvemap_cfg.get("max_entry", 0) or 0)

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
                    year = None  # không parse được thì giữ lại

                if year is not None:
                    if year > max_year or year < min_year:
                        continue

                filtered.append(item)
                if max_entry and (len(all_results) + len(filtered) >= max_entry):
                    break

            all_results.extend(filtered)

            # dừng nếu hết trang hoặc đạt max_entry
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

    # Lưu cvemap.json để debug/trace
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    return all_results

# ------------------------------- MAIN -------------------------------------- #

def main():
    """
    Outputs:
      - <output_root>/<target_name>/summarize/cve_list.json
      - (debug) <output_root>/<target_name>/summarize/CVEMAP/cvemap.json
    """
    # ---- Build base dirs from config ----
    keyword      = (summarize_config.get('keyword') or '').strip()
    version      = (summarize_config.get('version') or '').strip()
    output_root  = summarize_config.get('output_root', 'output')
    target_name  = summarize_config.get('target_name', 'target_1')

    base_dir       = os.path.join(output_root, target_name)
    summarize_dir  = os.path.join(base_dir, "summarize")
    cvemap_dir     = os.path.join(summarize_dir, "CVEMAP")
    logs_dir       = os.path.join(base_dir, "logs")

    for d in (base_dir, summarize_dir, cvemap_dir, logs_dir):
        os.makedirs(d, exist_ok=True)

    # ---- Configure logging ----
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

    # optional: init model để tương thích môi trường (không dùng tới)
    try:
        _ = get_model(summarize_config.get('model', 'openai'))
        logger.info("Model loaded successfully (optional).")
    except Exception as e:
        logger.warning("Model init failed (%s), continue without it.", e)

    logger.info("Preparing CVE list for target '%s' (keyword '%s') at base %s", target_name, keyword, base_dir)

    # 1) Query CVEMAP -> summarize/CVEMAP/cvemap.json
    cvemap_res = cvemap_product_by_keyword(keyword, cvemap_dir, cvemap_config)

    # 2) Hợp nhất/khử trùng lặp
    try:
        merged = merge(cvemap_res) if cvemap_res else []
    except Exception:
        merged = cvemap_res or []

    # 3) (Tuỳ chọn) LỌC THEO VERSION — giống summarize_agent (lọc TRÊN RAW cvemap_res), KHÔNG fallback
    if version:
        print("Version constraint has been set, will use this to save tokens.\nThis MAY NOT ACCURATE, please double check!")
        logger.info("Version constraint has been set, will use this to save tokens. This MAY NOT ACCURATE, please double check!")

        limited_lst = get_affected_cve(cvemap_res or [], version)

        print(f"The following CVEs will be searched:\n{limited_lst}")
        logger.info(f"The following CVEs will be searched:\n{limited_lst}")

        items = limited_lst  # giữ nguyên cấu trúc dict như summarize_agent
    else:
        items = merged

    # 4) Trích danh sách CVE ID
    cve_ids = [it.get('cve_id') for it in items if it.get('cve_id')]
    if not cve_ids:
        logger.warning("No CVE found for keyword '%s' with version='%s'.", keyword, version or "")

    # 5) Save ONLY cve_list.json
    cve_list_json_path = os.path.join(summarize_dir, "cve_list.json")
    with open(cve_list_json_path, "w", encoding="utf-8") as fj:
        json.dump(
            {
                "keyword": keyword,
                "version_filter": version or None,
                "count": len(cve_ids),
                "cves": cve_ids
            },
            fj, indent=2, ensure_ascii=False
        )

    logger.info("Saved %d CVEs to %s", len(cve_ids), cve_list_json_path)
    logger.info("Completed. Outputs under: %s (logs in %s)", summarize_dir, logs_dir)
    print(f"Done. See outputs in: {cve_list_json_path}")
    print(f"Logs: {log_file_path}")

if __name__ == "__main__":
    main()
