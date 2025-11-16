# import os
# import logging
# import yaml
# from typing import Dict, Any, Optional
# from utils.llm_factory import llm_manager, create_llm_from_config

# logger = logging.getLogger(__name__)

# class ModelManager:
#     def __init__(self, config_path: Optional[str] = None):
#         if config_path is None:
#             config_path = os.path.join(
#                 os.path.dirname(os.path.dirname(__file__)), 'configs', 'config.yaml')
#         self.config_path = config_path
#         self.config = self._load_config()
#         self.initialized_models = {}

#     def _load_config(self) -> Dict[str, Any]:
#         try:
#             with open(self.config_path, 'r', encoding='utf-8') as f:
#                 return yaml.safe_load(f)
#         except Exception as e:
#             logger.error(f"Failed to load config: {e}")
#             raise

#     def _process_environment_variables(self, config: Dict[str, Any]) -> Dict[str, Any]:
#         processed = {}
#         for key, value in config.items():
#             if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
#                 env_var = value[2:-1]
#                 env_val = os.getenv(env_var)
#                 if env_val is None:
#                     logger.warning(f"Env var {env_var} not found")
#                     env_val = ""
#                 processed[key] = env_val
#             else:
#                 processed[key] = value
#         return processed

#     def get_model(self, model_name: str = "openai"):
#         if model_name in self.initialized_models:
#             return self.initialized_models[model_name]

#         model_cfgs = self.config.get("models", {})
#         if model_name not in model_cfgs:
#             raise ValueError(f"Model '{model_name}' not found in config")

#         cfg = self._process_environment_variables(model_cfgs[model_name])
#         cfg['name'] = model_name
#         llm = create_llm_from_config(cfg)
#         self.initialized_models[model_name] = llm
#         return llm

#     def get_runtime_model(self, agent_type: str) -> str:
#         runtime = self.config.get("runtime", {})
#         return runtime.get(agent_type, {}).get("model", "default")

# model_manager = ModelManager()

# def get_model(model_name: str = "default"):
#     try:
#         return model_manager.get_model(model_name)
#     except Exception as e:
#         logger.error(f"Failed to load model '{model_name}': {e}")
#         return None

# def get_agent_model(agent_type: str):
#     return model_manager.get_model(model_manager.get_runtime_model(agent_type))
# utils/model_manager.py
# utils/model_manager.py






# import os, yaml
# from pathlib import Path
# from typing import Any, Dict
# from langchain_openai import ChatOpenAI  # pip install langchain-openai

# def _load_config() -> Dict[str, Any]:
#     for p in [
#         Path.cwd() / "configs" / "config.yaml",
#         Path(__file__).resolve().parent.parent / "configs" / "config.yaml",
#         Path.cwd() / "config.yaml",
#     ]:
#         if p.exists():
#             with open(p, "r", encoding="utf-8") as f:
#                 return yaml.safe_load(f) or {}
#     return {}

# def get_model(key: str):
#     """
#     Returns a LangChain ChatModel configured from config.yaml under models.<key>.
#     Supports:
#       - provider: openai  (uses ChatOpenAI; API key via OPENAI_API_KEY or models.<key>.api_key)
#       - provider: deepseek (OpenAI-compatible; API key via DEEPSEEK_API_KEY or models.<key>.api_key)
#     Also supports arbitrary OpenAI-compatible endpoints if you set base_url.
#     """
#     cfg = _load_config()
#     models = (cfg.get("models") or {})
#     conf = models.get(key)
#     if not conf:
#         raise RuntimeError(f"Model key '{key}' not found in config.models")

#     provider   = (conf.get("provider") or key).lower()
#     model_name = conf.get("model") or "gpt-4o-mini"
#     temperature= float(conf.get("temperature", 0))
#     timeout    = int(conf.get("timeout", 120))
#     base_url   = conf.get("base_url")

#     if provider == "openai":
#         api_key = os.getenv("OPENAI_API_KEY") or conf.get("api_key")
#         if not api_key:
#             raise RuntimeError("OPENAI_API_KEY (or models.openai.api_key) is required")
#         env_base = os.getenv("OPENAI_BASE_URL") or base_url
#         if env_base:
#             return ChatOpenAI(model=model_name, temperature=temperature, timeout=timeout,
#                               api_key=api_key, base_url=env_base)
#         return ChatOpenAI(model=model_name, temperature=temperature, timeout=timeout, api_key=api_key)

#     if provider == "deepseek":
#         api_key = os.getenv("DEEPSEEK_API_KEY") or conf.get("api_key")
#         if not api_key:
#             raise RuntimeError("DEEPSEEK_API_KEY (or models.deepseek.api_key) is required")
#         env_base = os.getenv("OPENAI_BASE_URL") or base_url or "https://api.deepseek.com/v1"
#         return ChatOpenAI(model=model_name, temperature=temperature, timeout=timeout,
#                           api_key=api_key, base_url=env_base)
    
    

#     # Generic OpenAI-compatible: if you specify base_url in YAML.
#     if base_url:
#         api_key = conf.get("api_key") or os.getenv("OPENAI_API_KEY") or "dummy"
#         return ChatOpenAI(model=model_name, temperature=temperature, timeout=timeout,
#                           api_key=api_key, base_url=base_url)

#     raise RuntimeError(f"Unknown provider '{provider}' for model key '{key}'")


import os, yaml
from pathlib import Path
from typing import Any, Dict
from langchain_openai import ChatOpenAI
# NEW: Gemini
try:
    from langchain_google_genai import ChatGoogleGenerativeAI
except Exception:
    ChatGoogleGenerativeAI = None

def _load_config() -> Dict[str, Any]:
    for p in [Path.cwd()/"configs"/"config.yaml",
              Path(__file__).resolve().parent.parent/"configs"/"config.yaml",
              Path.cwd()/"config.yaml"]:
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
    return {}

def get_model(key: str):
    cfg = _load_config()
    models = (cfg.get("models") or {})
    conf = models.get(key)
    if not conf:
        raise RuntimeError(f"Model key '{key}' not found in config.models")

    provider    = (conf.get("provider") or key).lower()
    model_name  = conf.get("model") or "gpt-4o-mini"
    temperature = float(conf.get("temperature", 0))
    timeout     = int(conf.get("timeout", 120))
    base_url    = conf.get("base_url")

    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY") or conf.get("api_key")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY (or models.<key>.api_key) is required")
        env_base = os.getenv("OPENAI_BASE_URL") or base_url
        if env_base:
            return ChatOpenAI(model=model_name, temperature=temperature, timeout=timeout,
                              api_key=api_key, base_url=env_base)
        return ChatOpenAI(model=model_name, temperature=temperature, timeout=timeout, api_key=api_key)

    if provider == "deepseek":
        api_key = os.getenv("DEEPSEEK_API_KEY") or conf.get("api_key")
        if not api_key:
            raise RuntimeError("DEEPSEEK_API_KEY (or models.<key>.api_key) is required")
        env_base = os.getenv("OPENAI_BASE_URL") or base_url or "https://api.deepseek.com/v1"
        return ChatOpenAI(model=model_name, temperature=temperature, timeout=timeout,
                          api_key=api_key, base_url=env_base)

    # NEW: Google / Gemini
    if provider in ("google", "gemini"):
        if ChatGoogleGenerativeAI is None:
            raise RuntimeError("langchain-google-genai is not installed. Run: pip install -U langchain-google-genai")
        api_key = os.getenv("GEMINI_API_KEY") or conf.get("api_key")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY (or models.<key>.api_key) is required")
        # ChatGoogleGenerativeAI ignores base_url; chỉ cần model + api_key
        return ChatGoogleGenerativeAI(model=model_name, temperature=temperature, google_api_key=api_key)

    # OpenAI-compatible qua base_url
    if base_url:
        api_key = conf.get("api_key") or os.getenv("OPENAI_API_KEY") or "dummy"
        return ChatOpenAI(model=model_name, temperature=temperature, timeout=timeout,
                          api_key=api_key, base_url=base_url)

    raise RuntimeError(f"Unknown provider '{provider}' for model key '{key}'")

