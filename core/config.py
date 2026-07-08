#!/usr/bin/env python3
"""
AI杀软 — 配置模块
管理 API 提供商/Key、路径等全局配置
"""

import os
import json
import sys
from pathlib import Path

# ─── 安装根目录 ─────────────────────────────
# deploy.sh 会把软件装到 ~/AI360
AI360_HOME = os.path.expanduser("~/AI360")
CONFIG_DIR = os.path.join(AI360_HOME, "config")
CONFIG_FILE = os.path.join(CONFIG_DIR, "settings.json")

# ─── 隔离目录 ───────────────────────────────
# 用户要求: 被隔离的文件放在 ~/被隔离的文件/
QUARANTINE_DIR = os.path.expanduser("~/被隔离的文件")

# ─── 其他路径 ───────────────────────────────
LOG_DIR = os.path.join(AI360_HOME, "logs")
PID_FILE = os.path.join(LOG_DIR, "av.pid")
RULES_DIR = os.path.join(AI360_HOME, "rules")

# 监控目录
WATCH_DIRS = [
    os.path.expanduser("~/下载"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/桌面"),
    os.path.expanduser("~/Downloads"),
    "/tmp",
]

# ─── 默认配置 ───────────────────────────────
DEFAULT_CONFIG = {
    "api_provider": "",      # openai / deepseek / custom
    "api_key": "",
    "api_base_url": "",      # 自定义 API 地址
    "api_model": "",         # 自定义模型名
    "enable_ai_scan": True,  # 是否启用云端 AI 分析
    "auto_quarantine": True, # 自动隔离恶意文件
    "watch_dirs": WATCH_DIRS,
}

# ─── 读写配置 ───────────────────────────────
def load_config() -> dict:
    """加载配置，若不存在则返回默认"""
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                # 补全缺失字段
                for k, v in DEFAULT_CONFIG.items():
                    cfg.setdefault(k, v)
                return cfg
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)


def save_config(cfg: dict):
    """保存配置"""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def is_first_run() -> bool:
    """检查是否首次运行（配置不存在或无 API key）"""
    if not os.path.isfile(CONFIG_FILE):
        return True
    cfg = load_config()
    return not cfg.get("api_key") or not cfg.get("api_provider")


# ─── 首次设置向导 ────────────────────────────
def run_setup_wizard():
    """交互式设置向导 — 让用户输入 API 提供商和 Key"""
    print("\033[1;36m" + "=" * 50)
    print("  🛡️  AI360 杀软 — 首次配置")
    print("=" * 50 + "\033[0m")
    print()
    print("需要配置 AI API 才能启用云端智能分析。")
    print("支持的提供商:")
    print("  1) OpenAI      — api.openai.com")
    print("  2) DeepSeek    — api.deepseek.com")
    print("  3) 自定义      — 自建 API 地址")
    print()

    cfg = load_config()

    # 选择提供商
    choice = input("请选择 [1-3] (默认 1): ").strip()
    if choice == "2":
        cfg["api_provider"] = "deepseek"
        cfg["api_base_url"] = "https://api.deepseek.com"
        cfg["api_model"] = "deepseek-chat"
    elif choice == "3":
        cfg["api_provider"] = "custom"
        cfg["api_base_url"] = input("请输入 API Base URL (如 https://api.xxx.com/v1): ").strip()
        cfg["api_model"] = input("请输入模型名称: ").strip()
    else:
        cfg["api_provider"] = "openai"
        cfg["api_base_url"] = "https://api.openai.com/v1"
        cfg["api_model"] = "gpt-4o-mini"

    # 输入 API Key
    key = input(f"\n请输入 [{cfg['api_provider']}] API Key: ").strip()
    while not key:
        print("  \033[1;33m[!] API Key 不能为空\033[0m")
        key = input(f"请输入 [{cfg['api_provider']}] API Key: ").strip()
    cfg["api_key"] = key

    # 是否启用 AI 扫描
    ai_scan = input("\n启用云端 AI 深度分析? [Y/n]: ").strip().lower()
    cfg["enable_ai_scan"] = ai_scan != "n"

    save_config(cfg)
    print()
    print("\033[0;32m[✓] 配置完成！AI360 已就绪\033[0m")
    print()

    return cfg
