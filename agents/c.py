#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, json, time, argparse, logging
import sys
from typing import Any, Dict, List, Optional, Tuple
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import yaml
from dotenv import load_dotenv
from langchain.memory import ConversationBufferMemory
from utils.model_manager import get_model

LOGGER = logging.getLogger("detect_template_agent")
LOGGER.setLevel(logging.INFO)
_FMT = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
_SH = logging.StreamHandler(); _SH.setFormatter(_FMT); LOGGER.addHandler(_SH)

# ---------------- Config (STRICT from config.yaml) ---------------- #

def load_config_strict(config_path: Optional[str]) -> Dict[str, Any]:
    if not config_path:
        raise SystemExit("No --config provided.")
    if not os.path.exists(config_path):
        raise SystemExit(f"Config not found: {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    if "runtime" not in cfg or "detect" not in cfg["runtime"]:
        raise SystemExit("Invalid config: expected runtime.detect.*")
    d = cfg["runtime"]["detect"]
    required = ["model", "memory_dir", "max_llm_retries", "target_name", "output_root", "target"]
    miss = [k for k in required if k not in d]
    if miss:
        raise SystemExit(f"Invalid config: missing runtime.detect keys: {', '.join(miss)}")
    return cfg

def _configure_file_logger(log_path: str):
    for h in list(LOGGER.handlers):
        if isinstance(h, logging.FileHandler):
            LOGGER.removeHandler(h)
            try: h.close()
            except: pass
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    fh = logging.FileHandler(log_path, encoding="utf-8"); fh.setFormatter(_FMT); LOGGER.addHandler(fh)

# ---------------- Prompts ---------------- #

SYSTEM_PROMPT = (
    "You are BugBT-Agent, a security detection instruction writer.\n"
    "Create SAFE, NON-DESTRUCTIVE verification steps for a known CVE.\n\n"
    "Return STRICT JSON ONLY:\n"
    "{\n"
    "  \"Task\": \"<one-line objective tied to the CVE>\",\n"
    "  \"Input Context\": {\n"
    "    \"Target_info\": \"<hosts/stack/what we're testing>\",\n"
    "    \"Target_parameter/API/endpoint\": [\"<endpoint-or-param>\", \"...\"],\n"
    "    \"How to detect\": \"<short safe approach to confirm without damage>\"\n"
    "  },\n"
    "  \"Instructions\": [\"Step 1: ...\", \"Step 2: ...\", \"Step 3: ...\"],\n"
    "  \"cve\": \"CVE-2024-12345\"\n"
    "}\n"
    "Constraints: detection-only; 3–6 steps; single JSON object; no extra text."
)

USER_PROMPT = (
    "Produce STRICT JSON per the schema.\n"
    "CVE: {cve}\n"
    "Keyword(from planning): {keyword}\n"
    "Version_filter: {version}\n"
    "Target: {target}\n"
    "- Tailor steps to CVE {cve}.\n"
    "- Use passive checks or harmless unique markers.\n"
    "- Return ONLY the JSON object (no code fences)."
)

FIX_SHAPE_PROMPT = (
    "Your reply did not match the STRICT JSON schema. Regenerate ONE JSON object only "
    "with keys: \"Task\", \"Input Context\" (\"Target_info\",\"Target_parameter/API/endpoint\",\"How to detect\"), "
    "\"Instructions\" (3–6 strings), and \"cve\" (CVE-YYYY-NNNN). No extra text."
)

# ---------------- Helpers ---------------- #

def _safe_filename_from_cve(cve: str, used: Dict[str, int]) -> str:
    base = cve.upper().replace("/", "_")
    if base not in used:
        used[base] = 1
        return f"{base}.json"
    used[base] += 1
    return f"{base}_{used[base]}.json"

def _load_cve_list(path: str) -> Tuple[str, Optional[str], List[str]]:
    if not os.path.exists(path):
        raise SystemExit(f"cve_list.json not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    keyword = str(obj.get("keyword", "")).strip()
    version = obj.get("version_filter")
    if isinstance(version, str):
        version = version.strip() or None
    cves = [c for c in obj.get("cves", []) if isinstance(c, str) and c.startswith("CVE-")]
    return keyword, version, cves

def _strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```") and t.endswith("```"):
        lines = t.splitlines()
        if len(lines) >= 2:
            return "\n".join(lines[1:-1]).strip()
    return t

def _is_valid_json_obj(text: str):
    t = _strip_fences(text)
    if "{" in t and "}" in t:
        try:
            t = t[t.index("{"): t.rfind("}")+1]
        except Exception:
            pass
    try:
        obj = json.loads(t)
    except Exception:
        return None
    if not isinstance(obj, dict): return None
    for k in ("Task","Input Context","Instructions","cve"):
        if k not in obj: return None
    ic = obj["Input Context"]
    if not isinstance(ic, dict): return None
    for k in ("Target_info","Target_parameter/API/endpoint","How to detect"):
        if k not in ic: return None
    if not isinstance(ic["Target_parameter/API/endpoint"], list): return None
    inst = obj["Instructions"]
    if not isinstance(inst, list) or not (3 <= len(inst) <= 6): return None
    if not all(isinstance(x, str) and x.strip() for x in inst): return None
    if not re.match(r"^CVE-\d{4}-\d{3,7}$", str(obj["cve"]).strip(), re.I): return None
    return obj

# ---------------- Generator ---------------- #

class TemplateAgent:
    def __init__(self, model_name: str, memory_dir: str, retries: int):
        # load .env if present
        for probe in (os.path.join(os.getcwd(), ".env"), os.path.join(os.path.dirname(__file__), ".env")):
            if os.path.exists(probe):
                load_dotenv(dotenv_path=probe, override=False)
                LOGGER.info(f".env loaded: {probe}")
                break
        self.llm = get_model(model_name)
        LOGGER.info(f"Loaded model: {model_name}")
        os.makedirs(memory_dir, exist_ok=True)
        self.memory = ConversationBufferMemory(return_messages=True, memory_key="history")
        self.retries = retries

    def generate(self, cve: str, keyword: str, version: Optional[str], target: str) -> Dict[str, Any]:
        self.memory.clear()
        self.memory.chat_memory.add_ai_message(SYSTEM_PROMPT)
        up = USER_PROMPT.format(cve=cve, keyword=keyword or "(unknown)", version=version or "(none)", target=target or "(unknown)")
        self.memory.chat_memory.add_user_message(up)
        resp = self.llm.invoke(self.memory.chat_memory.messages, timeout=180)
        content = getattr(resp, "content", str(resp))

        for _ in range(self.retries):
            parsed = _is_valid_json_obj(content)
            if parsed:
                parsed["cve"] = cve
                return parsed
            self.memory.chat_memory.add_user_message(FIX_SHAPE_PROMPT)
            resp = self.llm.invoke(self.memory.chat_memory.messages, timeout=180)
            content = getattr(resp, "content", str(resp))

        parsed = _is_valid_json_obj(content)
        if not parsed:
            raise RuntimeError(f"Model did not return valid STRICT-JSON for {cve}")
        parsed["cve"] = cve
        return parsed

# ---------------- Main ---------------- #

def main():
    ap = argparse.ArgumentParser(description="Generate detection templates per CVE (config.yaml only)")
    default_cfg = os.path.join(os.path.dirname(os.path.dirname(__file__)), "configs", "config.yaml")
    ap.add_argument("--config", default=default_cfg, help="Path to configs/config.yaml")
    args = ap.parse_args()

    cfg = load_config_strict(args.config)
    d = cfg["runtime"]["detect"]
    model_name      = d["model"]
    memory_dir      = d["memory_dir"]
    retries         = int(d["max_llm_retries"])
    target_name     = d["target_name"]
    output_root     = d["output_root"]
    target          = d["target"]  # field 'target'

    # cve_list mặc định: <output_root>/<target_name>/summarize/cve_list.json
    default_cve_list = os.path.join(output_root, target_name, "summarize", "cve_list.json")
    cve_list_path    = d.get("cve_list", default_cve_list)

    base_dir = os.path.join(output_root, target_name)
    # CHỈNH Ở ĐÂY: ghi templates ra thẳng <target_name>/detection_templates
    templates_dir = os.path.join(base_dir, "detection_templates")
    logs_dir = os.path.join(base_dir, "logs")
    os.makedirs(templates_dir, exist_ok=True); os.makedirs(logs_dir, exist_ok=True)

    log_path = os.path.join(logs_dir, "detect_template_agent.log")
    _configure_file_logger(log_path)
    LOGGER.info("TargetName=%s, OutputRoot=%s, Target=%s", target_name, output_root, target)
    LOGGER.info("cve_list.json: %s", cve_list_path)

    # đọc cve_list
    keyword, version, cves = _load_cve_list(cve_list_path)
    if not cves:
        LOGGER.warning("No CVE found in %s", cve_list_path)
        print("No CVE to process."); return

    agent = TemplateAgent(model_name, memory_dir, retries)
    manifest: List[Dict[str, Any]] = []
    used: Dict[str, int] = {}

    for cve in cves:
        try:
            obj = agent.generate(cve=cve, keyword=keyword, version=version, target=target)
            out_name = _safe_filename_from_cve(cve, used)
            out_path = os.path.join(templates_dir, out_name)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
            LOGGER.info("Wrote %s", out_path)
            manifest.append({"cve": cve, "file": f"detection_templates/{out_name}"})
        except Exception as e:
            LOGGER.exception("Failed for %s: %s", cve, e)

    if not manifest:
        LOGGER.warning("No templates generated.")
        print("No templates generated."); return

    # index ở ngay detection_templates
    index_path = os.path.join(templates_dir, "index.json")
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(
            {"target": target_name, "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "items": manifest},
            f, ensure_ascii=False, indent=2
        )
    LOGGER.info("Wrote %s", index_path)

    print(f"Generated {len(manifest)} templates at {templates_dir}")
    for it in manifest:
        print(f" - {it['cve']} -> {it['file']}")
    LOGGER.info("Logs at %s", log_path)

if __name__ == "__main__":
    main()
