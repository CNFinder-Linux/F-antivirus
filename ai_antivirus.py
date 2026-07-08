#!/usr/bin/env python3
"""
AI杀软 主入口 (AI360)
用法:
  ai_antivirus.py start     — 启动监控守护
  ai_antivirus.py stop      — 停止
  ai_antivirus.py scan <文件> — 单文件扫描
  ai_antivirus.py status    — 查看状态
  ai_antivirus.py setup     — 重新配置 API
"""

import sys
import os
import signal
import json
from pathlib import Path
from datetime import datetime

# 加入项目根目录
BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from core.config import load_config, save_config, is_first_run, run_setup_wizard, LOG_DIR, CONFIG_DIR

PID_FILE = os.path.join(LOG_DIR, "av.pid")
LOG_FILE = os.path.join(LOG_DIR, "alerts.log")


def cmd_start():
    """启动守护进程"""
    if os.path.isfile(PID_FILE):
        with open(PID_FILE) as f:
            pid = f.read().strip()
        if os.path.isdir(f"/proc/{pid}"):
            print(f"\033[1;33m[!] AI杀软已在运行中 (PID {pid})\033[0m")
            return

    print("\033[1;36m[+] 启动 AI杀软...\033[0m")
    pid = os.fork()
    if pid > 0:
        # 父进程退出
        with open(PID_FILE, "w") as f:
            f.write(str(pid))
        print(f"\033[0;32m[i] 已启动 (PID {pid})\033[0m")
        sys.exit(0)
    else:
        # 子进程
        os.setsid()
        with open(os.devnull, 'w') as null:
            os.dup2(null.fileno(), 0)
            os.dup2(null.fileno(), 1)
            os.dup2(null.fileno(), 2)

        from core.monitor import start_monitoring
        import threading
        import time

        # 先创建目录
        os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
        os.makedirs(LOG_DIR, exist_ok=True)

        # 写 PID
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))

        start_monitoring()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            if os.path.isfile(PID_FILE):
                os.unlink(PID_FILE)


def cmd_stop():
    """停止守护进程"""
    if not os.path.isfile(PID_FILE):
        print("\033[1;33m[!] AI杀软未运行\033[0m")
        return

    with open(PID_FILE) as f:
        pid = f.read().strip()

    try:
        os.kill(int(pid), signal.SIGTERM)
        os.unlink(PID_FILE)
        print(f"\033[0;32m[i] AI杀软已停止 (PID {pid})\033[0m")
    except ProcessLookupError:
        os.unlink(PID_FILE)
        print("\033[1;33m[!] 进程不存在，已清理 PID 文件\033[0m")


def cmd_status():
    """查看状态"""
    running = False
    if os.path.isfile(PID_FILE):
        with open(PID_FILE) as f:
            pid = f.read().strip()
        if os.path.isdir(f"/proc/{pid}"):
            running = True
            print(f"\033[0;32m[✓] AI杀软 运行中 (PID {pid})\033[0m")

    if not running:
        print("\033[0;33m[✗] AI杀软 未运行\033[0m")

    # 显示最近的告警
    if os.path.isfile(LOG_FILE):
        with open(LOG_FILE) as f:
            lines = f.readlines()
        critical = [l for l in lines if '"CRITICAL"' in l]
        warning = [l for l in lines if '"WARNING"' in l]
        print(f"\n   总告警: {len(lines)} | 严重: {len(critical)} | 警告: {len(warning)}")

        if critical:
            print("\n  \033[1;31m最近严重告警:\033[0m")
            for line in critical[-3:]:
                try:
                    e = json.loads(line)
                    print(f"    [{e['timestamp'][:19]}] {e['message'][:80]}")
                except Exception:
                    pass


def cmd_scan(target: str):
    """单文件扫描"""
    from core.ai_engine import analyze_file
    path = os.path.abspath(target)
    if not os.path.isfile(path):
        print(f"\033[1;31m[!] 文件不存在: {path}\033[0m")
        return

    print(f"\033[1;36m[🔍] 正在扫描: {path}\033[0m")
    result = analyze_file(path)

    verdict_color = {
        "malicious": "\033[1;31m[!] 恶意",
        "suspicious": "\033[1;33m[?] 可疑",
        "safe": "\033[0;32m[✓] 安全",
    }.get(result["verdict"], "\033[0;37m[?] 未知")

    print(f"\n  {verdict_color}\033[0m")
    print(f"  风险评分: {result['risk_score']}/100")
    if result["hash"]:
        print(f"  SHA256: {result['hash'][:32]}...")
    print(f"  文件大小: {result['size']:,} 字节")

    if result["reasons"]:
        print(f"\n  \033[1;37m分析理由:\033[0m")
        for r in result["reasons"]:
            print(f"    └ {r}")

    return result


def cmd_realtime():
    """前台实时监控 (用于测试)"""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    # 直接运行 monitor 模块
    from core.monitor import inotify_watcher, script_execution_monitor
    import threading
    import time

    print("\033[1;36m" + "=" * 60)
    print("  🛡️  AI杀软 实时监控 (前台)")
    print("=" * 60 + "\033[0m")

    t1 = threading.Thread(target=inotify_watcher, daemon=True)
    t1.start()
    t2 = threading.Thread(target=script_execution_monitor, daemon=True)
    t2.start()

    print("\033[0;32m[i] 监控中，按 Ctrl+C 停止\033[0m")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\033[0;33m[i] 已停止\033[0m")


def cmd_setup():
    """重新运行配置向导"""
    run_setup_wizard()
    print("运行 \033[1;36mai_antivirus.py start\033[0m 启动服务")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1]
    if cmd == "start":
        # 首次运行检查
        if is_first_run():
            print("\033[1;33m[!] 首次运行，请先配置 API\033[0m")
            run_setup_wizard()
        cmd_start()
    elif cmd == "stop":
        cmd_stop()
    elif cmd == "status":
        cmd_status()
    elif cmd == "scan" and len(sys.argv) >= 3:
        cmd_scan(sys.argv[2])
    elif cmd == "realtime":
        cmd_realtime()
    elif cmd == "setup":
        cmd_setup()
    else:
        print("未知命令。用法:")
        print("  ai_antivirus.py start     — 后台启动")
        print("  ai_antivirus.py stop      — 停止")
        print("  ai_antivirus.py status    — 状态")
        print("  ai_antivirus.py scan <文件> — 扫描文件")
        print("  ai_antivirus.py setup     — 配置 API")
        print("  ai_antivirus.py realtime  — 前台监控")


if __name__ == "__main__":
    main()
