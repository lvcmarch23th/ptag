#!/usr/bin/env python3
"""
CVE Summarizer Agent (config-driven)

- Đọc settings từ YAML config (runtime.summarize.*)
- Tự tìm CPE + CVE NVD + Exploit-DB + Trickest PoC
- Ghi JSON dạng cve_list:
  {
    "keyword": "...",
    "version_filter": "...",
    "count": <int>,
    "cves": ["CVE-...", ...]
  }
- Đường dẫn output: <output_root>/<target_name>/summarizer/cve_list
"""

import argparse
import csv
import json
import os
import re
import time
from dataclasses import dataclass, asdict
from io import StringIO
from typing import Any, Dict, List, Optional

import requests
import yaml
from termcolor import colored


# --------------------------- Data models ---------------------------

@dataclass
class CVEExploit:
    id: str
    description: str
    link: str


@dataclass
class CVEFinding:
    id: str
    description: str
    weaknesses: str
    nvd_link: str
    exploits: List[CVEExploit]
    github_pocs: List[str]


# --------------------------- NVD / ExploitDB helpers ---------------------------

_EXPLOIT_DB_CACHE: Optional[Dict[str, Dict[str, str]]] = None


def get_exploit_db() -> Dict[str, Dict[str, str]]:
    """Download và cache exploit-db CSV index."""
    global _EXPLOIT_DB_CACHE
    if _EXPLOIT_DB_CACHE is not None:
        return _EXPLOIT_DB_CACHE

    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv?ref_type=heads"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        csv_content = StringIO(resp.text)
        reader = csv.DictReader(csv_content)
        _EXPLOIT_DB_CACHE = {row["id"]: row for row in reader}
        return _EXPLOIT_DB_CACHE
    except Exception as e:
        print(colored(f"[!] Failed to fetch Exploit-DB index: {e}", "red"))
        _EXPLOIT_DB_CACHE = {}
        return _EXPLOIT_DB_CACHE


def search_exploitdb(cve_id: str) -> List[CVEExploit]:
    exploits: List[CVEExploit] = []
    cve_id = cve_id.lower()
    exploit_db = get_exploit_db()

    for exp_id, data in exploit_db.items():
        codes = (data.get("codes") or "").lower()
        if cve_id in codes:
            exploits.append(
                CVEExploit(
                    id=exp_id,
                    description=data.get("description", ""),
                    link=f"https://www.exploit-db.com/exploits/{exp_id}",
                )
            )
    return exploits


def make_api_request(url: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    headers = {"User-Agent": "Mozilla/5.0"}
    for attempt in range(3):
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=60)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", 6))
                print(colored(f"[!] NVD rate limit. Sleep {retry_after}s...", "yellow"))
                time.sleep(retry_after)
                continue
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            print(colored(f"[!] Request error: {e}", "red"))
            time.sleep(2 ** attempt)
    return None


def cve_in_year_range(cve_id: str, min_year: Optional[int], max_year: Optional[int]) -> bool:
    try:
        year = int(cve_id.split("-")[1])
    except Exception:
        return True

    if min_year is not None and year < min_year:
        return False
    if max_year is not None and year > max_year:
        return False
    return True


def fetch_trickest_info(cve_id: str, enable_poc: bool = True) -> List[str]:
    """Lấy list GitHub PoC từ repo Trickest (nếu có)."""
    if not enable_poc:
        return []
    try:
        year = cve_id.split("-")[1]
    except Exception:
        return []
    url = f"https://raw.githubusercontent.com/trickest/cve/refs/heads/main/{year}/{cve_id}.md"
    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code != 200:
            return []
        return sorted(set(re.findall(r"https://github\\.com/[^\\s)]+", resp.text)))[:10]
    except Exception:
        return []


def find_cpes(component: str, version: str) -> List[str]:
    """
    Dùng NVD CPE API tìm các CPE có đúng version.
    """
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    keyword = f"{component} {version}"
    print(colored(f"[+] Searching CPE for: {keyword}", "cyan"))
    data = make_api_request(url, {"keywordSearch": keyword})
    if not data:
        return []

    version_regex = rf":{re.escape(version)}(?:$|:)"

    out: List[str] = []
    for item in data.get("products", []):
        cpe = item["cpe"]["cpeName"]
        if re.search(version_regex, cpe):
            out.append(cpe)

    return out


def fetch_cves_for_cpe(
    cpe_string: str,
    min_year: Optional[int],
    max_year: Optional[int],
    enable_poc: bool = True,
) -> List[CVEFinding]:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    data = make_api_request(url, {"cpeName": cpe_string})
    if not data:
        return []

    findings: List[CVEFinding] = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]

        if not cve_in_year_range(cve_id, min_year, max_year):
            continue

        desc_list = cve.get("descriptions") or []
        description = desc_list[0].get("value", "N/A") if desc_list else "N/A"

        weaknesses_list = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                val = d.get("value")
                if val:
                    weaknesses_list.append(val)
        weaknesses = ", ".join(sorted(set(weaknesses_list)))

        exploits = search_exploitdb(cve_id)
        trickest_links = fetch_trickest_info(cve_id, enable_poc=enable_poc)

        findings.append(
            CVEFinding(
                id=cve_id,
                description=description,
                weaknesses=weaknesses,
                nvd_link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                exploits=exploits,
                github_pocs=trickest_links,
            )
        )
    return findings


# --------------------------- Config + Agent logic ---------------------------


def load_yaml_config(path: str) -> Dict[str, Any]:
    script_dir = os.path.dirname(os.path.abspath(__file__))

    candidates = [
        path,
        os.path.join(script_dir, path),
        os.path.join(script_dir, "../configs/", path),
    ]

    for p in candidates:
        p = os.path.abspath(p)
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}

    raise FileNotFoundError(f"Config file not found in: {', '.join(candidates)}")


def build_output_json(
    target_name: str,
    component: str,
    version: str,
    cpes: List[str],
    findings: List[CVEFinding],
) -> Dict[str, Any]:
    """
    Output format: giống summarizer cve_list:
    {
      "keyword": "...",
      "version_filter": "...",
      "count": <int>,
      "cves": ["CVE-...", ...]
    }
    """
    # Lấy danh sách CVE ID từ findings
    cve_ids = [f.id for f in findings]
    # Có thể giữ nguyên (cho trùng đúng behaviour cũ) hoặc unique:
    # unique_ids = sorted(set(cve_ids))
    # Ở đây mình dùng unique cho sạch, nếu bạn muốn giữ nguyên thứ tự lặp lại thì đổi lại cho phù hợp.
    unique_ids = sorted(set(cve_ids))

    return {
        "keyword": component,
        "version_filter": version,
        "count": len(unique_ids),
        "cves": unique_ids,
    }


def run_agent_from_config(cfg: Dict[str, Any], section: str = "summarize") -> Dict[str, Any]:
    """
    Đọc runtime.<section> từ config.yaml rồi chạy agent.
    """
    runtime_cfg = cfg.get("runtime", {})
    agent_cfg = runtime_cfg.get(section, {})
    if not agent_cfg:
        raise KeyError(f"Missing runtime.{section} section in config.yaml")

    component = agent_cfg.get("keyword") or agent_cfg.get("component")
    version = agent_cfg.get("version")
    target_name = agent_cfg.get("target_name", "unknown_target")
    output_root = agent_cfg.get("output_root", "output")
    min_year = agent_cfg.get("min_year")
    max_year = agent_cfg.get("max_year")

    if isinstance(min_year, str) and min_year.strip() == "":
        min_year = None
    if isinstance(max_year, str) and max_year.strip() == "":
        max_year = None

    if component is None or version is None:
        raise ValueError("runtime.summarize.keyword & runtime.summarize.version are required")

    print(colored(f"[+] Component: {component}, version: {version}", "green"))

    cpes = find_cpes(component, version)
    if not cpes:
        print(colored("[!] No CPEs found – returning empty finding list", "yellow"))
        findings: List[CVEFinding] = []
        output = build_output_json(target_name, component, version, [], findings)
    else:
        all_findings: List[CVEFinding] = []
        for cpe in cpes:
            print(colored(f"[+] Fetching CVEs for CPE: {cpe}", "blue"))
            cpe_findings = fetch_cves_for_cpe(
                cpe, min_year=min_year, max_year=max_year, enable_poc=True
            )
            all_findings.extend(cpe_findings)

        output = build_output_json(target_name, component, version, cpes, all_findings)

    # Ghi JSON ra <output_root>/<target_name>/summarizer/cve_list
    output_dir = os.path.join(output_root, target_name, "summarize")
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "cve_list.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(colored(f"[+] Result written to {out_path}", "cyan"))
    return output


# --------------------------- CLI entrypoint ---------------------------


def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="YAML-driven CVE Summarizer Agent (test.py replacement)",
    )
    parser.add_argument(
        "-c",
        "--config",
        dest="config_path",
        default="config.yaml",
        help="Path to YAML config file (default: config.yaml)",
    )
    parser.add_argument(
        "--section",
        default="summarize",
        help="Section under runtime.* to use (default: summarize)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_cli_args()
    cfg = load_yaml_config(args.config_path)
    run_agent_from_config(cfg, section=args.section)


if __name__ == "__main__":
    main()
