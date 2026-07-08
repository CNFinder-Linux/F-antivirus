#!/usr/bin/env python3
"""
AI360 杀软 — 文件 & 进程监控器
使用轮询检测新文件 + 轮询 /proc 检测脚本执行
"""

import os
import time
import json
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from core.ai_engine import analyze_file
from core.config import load_config, QUARANTINE_DIR, LOG_DIR

# ─── 配置 ────────────────────────────────────────
cfg = load_config()
WATCH_DIRS = cfg.get("watch_dirs", [
    os.path.expanduser("~/下载"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/桌面"),
    os.path.expanduser("~/Downloads"),
    "/tmp",
])

LOG_FILE = os.path.join(LOG_DIR, "alerts.log")
POLL_INTERVAL = 3        # 文件轮询间隔 (秒)
SCRIPT_POLL = 1.5        # 脚本进程轮询间隔 (秒)
MAX_FILE_SIZE_MB = 50    # 跳过 >50MB 的文件

# 已分析文件缓存
_analyzed = set()
_known_processes = set()
# 已弹窗通知的文件 (防重复)
_notified = set()


# ─── 日志 ────────────────────────────────────────
def log_alert(level: str, message: str, details: dict = None):
    os.makedirs(LOG_DIR, exist_ok=True)
    entry = {
        "timestamp": datetime.now().isoformat(),
        "level": level,
        "message": message,
        "details": details or {}
    }
    line = json.dumps(entry, ensure_ascii=False)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
    return entry


# ─── 通知 ────────────────────────────────────────
def notify_terminal(entry: dict):
    """终端醒目告警"""
    ts = entry["timestamp"][11:19]
    level = entry["level"]
    msg = entry["message"]

    if level == "CRITICAL":
        prefix = "\033[1;31m[!] ⚠ AI360 严重告警"
    elif level == "WARNING":
        prefix = "\033[1;33m[*] ⚡ AI360 警告"
    else:
        prefix = "\033[0;32m[i] AI360 信息"

    print(f"{prefix} [{ts}] {msg}\033[0m")

    if entry["details"].get("risk_score", 0) >= 50:
        reasons = entry["details"].get("reasons", [])
        for r in reasons[:5]:
            print(f"  \033[0;31m  └ {r}\033[0m")

    # 桌面通知 (每个文件只弹一次, 3秒自动消失)
    filepath = entry["details"].get("file", "")
    if filepath and filepath in _notified:
        return
    if filepath:
        _notified.add(filepath)
    try:
        subprocess.run(
            ["notify-send",
             "-t", "3000",
             "-u", "normal",
             "-a", "AI360",
             f"[{level}] {msg}"[:120],
             ("\n".join(entry["details"].get("reasons", [msg])))[:250]
             ],
            timeout=3, stderr=subprocess.DEVNULL
        )
    except Exception:
        pass


# ─── 轮询扫描新文件 ─────────────────────────────
def poll_new_files():
    """轮询监控目录中的新文件"""
    while True:
        try:
            for watch_dir in WATCH_DIRS:
                if not os.path.isdir(watch_dir):
                    continue
                try:
                    for root, _dirs, files in os.walk(watch_dir, topdown=True):
                        # 限制遍历深度: 跳过 . 开头的隐藏目录和 node_modules 等
                        _dirs[:] = [d for d in _dirs
                                    if not d.startswith('.')
                                    and d not in ('node_modules', '__pycache__',
                                                  '.git', 'venv', '.venv')]
                        for fname in files:
                            fpath = os.path.join(root, fname)

                            # 跳过已分析
                            if fpath in _analyzed:
                                continue

                            # 只分析新建文件 (修改时间在 120 秒内)
                            try:
                                mtime = os.path.getmtime(fpath)
                                if time.time() - mtime > 120:
                                    _analyzed.add(fpath)
                                    continue
                            except Exception:
                                continue

                            scan_new_file(fpath)
                except PermissionError:
                    continue
        except Exception:
            pass

        time.sleep(POLL_INTERVAL)


def scan_new_file(filepath: str):
    """分析新文件"""
    if filepath in _analyzed:
        return
    _analyzed.add(filepath)

    if not os.path.isfile(filepath):
        return

    # 大小检查
    try:
        size = os.path.getsize(filepath)
        if size == 0:
            return
        if size > MAX_FILE_SIZE_MB * 1024 * 1024:
            return
    except Exception:
        return

    # 跳过完全安全的扩展名
    ext = Path(filepath).suffix.lower()
    very_safe = {'.txt', '.md', '.log', '.json', '.yaml', '.yml', '.toml',
                 '.ini', '.cfg', '.conf', '.xml', '.html', '.css',
                 '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.ico',
                 '.mp3', '.mp4', '.wav', '.flac',
                 '.c', '.h', '.cpp', '.rs', '.go'}
    if ext in very_safe and size < 1024 * 1024:
        return

    result = analyze_file(filepath)

    if result["verdict"] == "malicious":
        entry = log_alert("CRITICAL",
                          f"检测到恶意文件: {filepath}",
                          {"file": filepath, **result})
        notify_terminal(entry)

        try:
            quarantine_file(filepath)
        except Exception as e:
            log_alert("WARNING", f"隔离失败: {filepath}", {"error": str(e)})

    elif result["verdict"] == "suspicious":
        entry = log_alert("WARNING",
                          f"可疑文件: {filepath}",
                          {"file": filepath, **result})
        notify_terminal(entry)


def quarantine_file(filepath: str):
    """移至 ~/被隔离的文件/"""
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    fname = Path(filepath).name
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(QUARANTINE_DIR, f"{ts}_{fname}")
    os.rename(filepath, dest)
    log_alert("INFO", f"文件已隔离: {fname} → {dest}")
    notify_terminal({
        "timestamp": datetime.now().isoformat(),
        "level": "WARNING",
        "message": f"文件已移至隔离区: {dest}",
        "details": {}
    })


# ─── 脚本进程监控 ────────────────────────────────
def script_execution_monitor():
    """轮询 /proc 检测新执行的 sh/bash 脚本"""
    global _known_processes
    while True:
        try:
            current = set()
            for pid_str in os.listdir("/proc"):
                if not pid_str.isdigit():
                    continue
                try:
                    comm_path = f"/proc/{pid_str}/comm"
                    with open(comm_path) as f:
                        comm = f.read().strip()
                    if comm in ("bash", "sh", "dash", "zsh"):
                        cmdline_path = f"/proc/{pid_str}/cmdline"
                        with open(cmdline_path, "rb") as f:
                            raw = f.read().replace(b'\x00', b' ').decode('utf-8', errors='ignore').strip()
                        if raw:
                            current.add((pid_str, comm, raw))
                except (IOError, OSError):
                    continue

            new_procs = current - _known_processes
            for pid_str, shell, cmdline in new_procs:
                parts = cmdline.split()
                script_path = None
                if len(parts) >= 2 and parts[0] in ("bash", "sh", "dash", "zsh"):
                    script_path = parts[1]
                elif len(parts) >= 1 and parts[0].endswith(".sh"):
                    script_path = parts[0]

                if script_path and script_path.endswith(".sh") and os.path.isfile(script_path):
                    result = analyze_file(script_path)
                    if result["verdict"] in ("malicious", "suspicious"):
                        level = "CRITICAL" if result["verdict"] == "malicious" else "WARNING"
                        entry = log_alert(
                            level,
                            f"执行风险脚本 [PID {pid_str}]: {script_path}",
                            {"pid": pid_str, "shell": shell, "cmdline": cmdline,
                             "script": script_path, **result}
                        )
                        notify_terminal(entry)

                        if result["verdict"] == "malicious":
                            try:
                                os.kill(int(pid_str), 15)
                                log_alert("INFO", f"已终止恶意进程 PID {pid_str}")
                                notify_terminal({
                                    "timestamp": datetime.now().isoformat(),
                                    "level": "INFO",
                                    "message": f"已终止恶意进程 PID {pid_str} ({script_path})",
                                    "details": {}
                                })
                            except (OSError, ProcessLookupError):
                                pass

            _known_processes = current
        except Exception:
            pass

        time.sleep(SCRIPT_POLL)


# ─── 启动 ────────────────────────────────────────
def start_monitoring():
    """启动所有监控线程"""
    print("\033[1;36m" + "=" * 60)
    print("  🛡️  AI360 杀软 监控器 v2.0")
    print(f"  监控目录 ({len(WATCH_DIRS)}):")
    for d in WATCH_DIRS:
        if os.path.isdir(d):
            print(f"    ✓ {d}")
        else:
            print(f"    - {d} (不存在，跳过)")
    print(f"  隔离目录: {QUARANTINE_DIR}")
    print("=" * 60 + "\033[0m")

    t1 = threading.Thread(target=poll_new_files, daemon=True)
    t1.start()

    t2 = threading.Thread(target=script_execution_monitor, daemon=True)
    t2.start()

    print("\033[0;32m[i] 监控已启动（轮询间隔 {}s / {}s）\033[0m".format(POLL_INTERVAL, SCRIPT_POLL))
    print("\033[0;32m[i] 按 Ctrl+C 停止\033[0m" if threading.current_thread() == threading.main_thread() else "")


if __name__ == "__main__":
    start_monitoring()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\033[0;33m[i] AI360 已停止\033[0m")
