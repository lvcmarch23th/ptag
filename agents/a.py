#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import re
import time
import logging
import subprocess
from typing import Optional, List

# 3rd-party
from dotenv import load_dotenv
import yaml
from pydantic import BaseModel, Field
from langchain.memory import ConversationBufferMemory
from langchain_core.messages import HumanMessage, AIMessage
from langchain_community.chat_message_histories import FileChatMessageHistory

# project utils
from utils.model_manager import get_model
from utils.prompt import PentestAgentPrompt

# ---------------------------
# Logging (console now; file handler added after config)
# ---------------------------
logger = logging.getLogger("recon_agent")
logger.setLevel(logging.INFO)
_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

_has_console = any(isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler) for h in logger.handlers)
if not _has_console:
    _console = logging.StreamHandler()
    _console.setFormatter(_formatter)
    logger.addHandler(_console)

# ---------------------------
# Config load
# ---------------------------
CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'configs', 'config.yaml')
logger.info(f"Loading config from: {CONFIG_PATH}")
try:
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        _cfg = yaml.safe_load(f)
    logger.info("Config loaded successfully")
except Exception as e:
    logger.error(f"Failed to load config: {e}")
    sys.exit(1)

if 'runtime' not in _cfg or 'recon' not in _cfg['runtime']:
    logger.error("Config missing 'runtime.recon' section.")
    sys.exit(1)

recon_config = _cfg['runtime']['recon']
TARGET_IP: str   = recon_config.get('target_ip', 'unknown_ip')
MODEL_NAME: str  = recon_config.get('model', 'openai')
TARGET_NAME: str = recon_config.get('target_name', 'default_target')
OUTPUT_ROOT: str = recon_config.get('output_root', 'output')

# ---------------------------
# File logging -> {OUTPUT_ROOT}/{TARGET_NAME}/logs/recon_agent.log
# ---------------------------
LOG_DIR = os.path.join(OUTPUT_ROOT, TARGET_NAME, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, 'recon_agent.log')

for h in list(logger.handlers):
    if isinstance(h, logging.FileHandler):
        logger.removeHandler(h)

_file = logging.FileHandler(log_path, encoding='utf-8')
_file.setFormatter(_formatter)
logger.addHandler(_file)
logger.info(f"Log file: {log_path}")

# ---------------------------
# Memory dir inside logs -> {OUTPUT_ROOT}/{TARGET_NAME}/logs/recon_memory
# ---------------------------
_memory_dir_name = recon_config.get('memory_dir', 'recon_memory')  # keep name if provided
MEMORY_DIR: str = os.path.join(LOG_DIR, os.path.basename(_memory_dir_name))
os.makedirs(MEMORY_DIR, exist_ok=True)

# ---------------------------
# Paths
# ---------------------------
# summary path = output_root/target_name/recon/recon_summary.json
XYZ_PATH = os.path.join(OUTPUT_ROOT, TARGET_NAME, 'recon', 'recon_summary.json')

# ---------------------------
# Helpers
# ---------------------------
def ensure_parent_dir(path: str):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)

def extract_json_loose(s: str) -> Optional[dict]:
    """Ưu tiên ```json ...```, rồi fallback parse block { ... } theo đếm ngoặc."""
    m = re.search(r'```json\s*(\{[\s\S]*?\})\s*```', s, flags=re.I)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass
    first = s.find('{')
    while first != -1:
        depth = 0
        for i in range(first, len(s)):
            ch = s[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    cand = s[first:i+1]
                    try:
                        return json.loads(cand)
                    except json.JSONDecodeError:
                        break
        first = s.find('{', first + 1)
    return None

# ---------------------------
# Data models
# ---------------------------
class ReconResponse(BaseModel):
    analysis: str = Field(description="Analysis of the previous step")
    next_step: str = Field(description="What to do next")
    executable: str = Field(description="Command to execute, or 'None' if no command needed")

# ---------------------------
# Agent
# ---------------------------
class ReconAgent:
    def __init__(self, model_name: str, memory_dir: str):
        logger.info(f"Initializing ReconAgent with model={model_name}")

        # load .env (nếu có) cùng thư mục script
        env_path = os.path.join(os.path.dirname(__file__), ".env")
        if os.path.exists(env_path):
            load_dotenv(dotenv_path=env_path, override=False)
            logger.info(f".env loaded from: {env_path}")
        else:
            logger.info(".env file not found; continue")

        try:
            self.llm = get_model(model_name)
            logger.info(f"Model {model_name} loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load model {model_name}: {e}")
            self.llm = None

        self.memory_dir = memory_dir
        os.makedirs(self.memory_dir, exist_ok=True)
        self.memory_map = {}

    def _memory_file(self, topic: str) -> str:
        return os.path.join(self.memory_dir, f"{topic}.json")

    def get_memory(self, topic: str) -> ConversationBufferMemory:
        if topic not in self.memory_map:
            mem = ConversationBufferMemory(return_messages=True, memory_key="history")
            self.memory_map[topic] = mem
            logger.info(f"Created memory for topic: {topic}")
        return self.memory_map[topic]

    def init_thread(self, topic: str):
        logger.info(f"Initializing thread for topic: {topic}")
        self.get_memory(topic)
        self.load_memory_from_file(topic)

    def send_message(self, topic: str, msg_content: str):
        mem = self.get_memory(topic)
        mem.chat_memory.add_user_message(msg_content)

    def get_last_message(self, topic: str) -> str:
        mem = self.get_memory(topic)
        msgs = mem.chat_memory.messages
        return msgs[-1].content if msgs else ""

    def get_conversation_history(self, topic: str) -> List:
        return self.get_memory(topic).chat_memory.messages

    def save_memory_to_file(self, topic: str):
        try:
            mem = self.get_memory(topic)
            msgs = mem.chat_memory.messages
            if not msgs:
                logger.info(f"No messages to save for topic: {topic}")
                return
            memory_file = self._memory_file(topic)
            chat_history = FileChatMessageHistory(memory_file)
            for m in msgs:
                if isinstance(m, HumanMessage):
                    chat_history.add_user_message(m.content)
                elif isinstance(m, AIMessage):
                    chat_history.add_ai_message(m.content)
            logger.info(f"Saved {len(msgs)} messages to {memory_file}")
        except Exception as e:
            logger.error(f"Error saving memory for topic {topic}: {e}")

    def load_memory_from_file(self, topic: str):
        try:
            memory_file = self._memory_file(topic)
            if not os.path.exists(memory_file):
                logger.info(f"No existing memory file for topic: {topic}")
                return
            chat_history = FileChatMessageHistory(memory_file)
            mem = self.get_memory(topic)
            for m in chat_history.messages:
                if isinstance(m, HumanMessage):
                    mem.chat_memory.add_user_message(m.content)
                elif isinstance(m, AIMessage):
                    mem.chat_memory.add_ai_message(m.content)
            logger.info(f"Loaded {len(chat_history.messages)} messages from {memory_file}")
        except Exception as e:
            logger.error(f"Error loading memory for topic {topic}: {e}")

    def run_thread(self, topic: str) -> Optional[str]:
        logger.info(f"Running thread for topic: {topic}")
        mem = self.get_memory(topic)
        if not mem.chat_memory.messages:
            logger.warning(f"No messages found for topic: {topic}")
            return None
        if not self.llm:
            logger.error("LLM not initialized")
            return None

        max_retries = 3
        for attempt in range(max_retries):
            try:
                logger.info(f"Invoking LLM (attempt {attempt+1}/{max_retries})")
                messages = mem.chat_memory.messages
                resp = self.llm.invoke(messages, timeout=180)
                content = resp.content
                mem.chat_memory.add_ai_message(content)
                logger.info("LLM response appended to memory")
                return content
            except Exception as e:
                logger.error(f"API call failed (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    wait = 2 * (attempt + 1)
                    logger.info(f"Retrying in {wait}s ...")
                    time.sleep(wait)
                else:
                    logger.error("API call failed after retries")
                    return None

    def run_shell_command(self, command: str) -> str:
        logger.debug(f"Executing command: {command}")
        try:
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=180
            )
            out = result.stdout
            logger.info(f"Command executed; output length={len(out)}")
            return out
        except subprocess.CalledProcessError as e:
            msg = f"Command failed with error: {e.stderr}"
            logger.error(msg)
            return msg
        except subprocess.TimeoutExpired:
            msg = "Command timed out after 180 seconds"
            logger.error(msg)
            return msg

    def extract_json_data(self, s: str) -> Optional[dict]:
        return extract_json_loose(s)

    def parse_structured_response(self, response_text: str) -> ReconResponse:
        try:
            data = self.extract_json_data(response_text)
            if data:
                return ReconResponse(**data)
            # Fallback: cố tìm 'executable:' trong text thuần
            executable = "None"
            next_step = ""
            analysis = response_text
            m = re.search(r'executable:\s*(.*?)\n', response_text, re.IGNORECASE)
            if m:
                executable = m.group(1).strip()
            return ReconResponse(analysis=analysis, next_step=next_step, executable=executable)
        except Exception as e:
            logger.error(f"parse_structured_response error: {e}")
            return ReconResponse(analysis=response_text, next_step="", executable="None")

# ---------------------------
# Main
# ---------------------------
def main():
    logger.info("Starting ReconAgent")
    start = time.time()

    agent = ReconAgent(MODEL_NAME, MEMORY_DIR)
    prompt = PentestAgentPrompt()

    curr_topic = recon_config.get('current_topic', TARGET_NAME or 'default_topic')
    logger.info(f"Current topic: {curr_topic}")
    logger.info(f"Target IP: {TARGET_IP}")

    # Init message
    recon_init_message = prompt.recon_init.replace("<Target-Ip>", TARGET_IP)

    # Start thread and seed prompt
    agent.init_thread(curr_topic)
    agent.send_message(curr_topic, recon_init_message)

    # Main loop
    max_attempts = 10
    attempts = 0
    while attempts < max_attempts:
        res = agent.run_thread(curr_topic)
        if not res:
            print(res)
            break

        last = agent.get_last_message(curr_topic)
        parsed = agent.parse_structured_response(last)

        # Print step
        try:
            parsed_json = agent.extract_json_data(last)
        except Exception:
            parsed_json = None

        print("\n==============================")
        if parsed_json:
            print("[LLM Analysis]\n", parsed_json.get("analysis", ""))
            print("[Next Step]\n", parsed_json.get("next_step", ""))
            print("[Executable Command]\n", parsed_json.get("executable", ""))
        else:
            print("[Raw LLM Response]\n", last[:1000])
        print("==============================\n")

        cmd = parsed.executable
        if cmd and cmd != 'None':
            cmd_res = agent.run_shell_command(cmd)
            print("[Command Execution Result]\n", cmd_res)
            agent.send_message(curr_topic, "Here is what I got from executing previous executable command.\n" + cmd_res)
            attempts += 1
            continue
        else:
            # LLM đã quyết định dừng (executable=None). Ra khỏi vòng lặp để lấy RECON_SUMMARY cuối.
            break

    # Yêu cầu tổng kết RECON một lần
    logger.info("Requesting final RECON_SUMMARY")
    agent.send_message(curr_topic, prompt.recon_summary)

    logger.info("Running thread for final summary")
    final_response = agent.run_thread(curr_topic)

    # Ghi file summary
    if final_response:
        raw = agent.get_last_message(curr_topic)
        parsed_final = agent.extract_json_data(raw)
        try:
            ensure_parent_dir(XYZ_PATH)
            with open(XYZ_PATH, 'w', encoding='utf-8') as f:
                if parsed_final is not None:
                    json.dump(parsed_final, f, ensure_ascii=False, indent=2)
                else:
                    f.write(raw)
            logger.info(f"Wrote RECON_SUMMARY to: {XYZ_PATH}")
            print(f"[Saved RECON_SUMMARY] -> {XYZ_PATH}")
        except Exception as e:
            logger.error(f"Failed to write RECON_SUMMARY to {XYZ_PATH}: {e}")
    else:
        logger.warning("No final response received; nothing to write")

    # Save memory snapshot (stored under .../logs/recon_memory)
    logger.info("Saving memory to file")
    agent.save_memory_to_file(curr_topic)

    cost = time.time() - start
    logger.info(f"Reconnaissance agent execution completed in {cost:.2f} seconds")

if __name__ == "__main__":
    main()
