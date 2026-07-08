#!/usr/bin/env python3
"""
AI杀软核心引擎 — 基于启发式 + 熵分析 + 特征匹配的智能检测模块
"""

import os
import math
import re
import json
import hashlib
from pathlib import Path

# 可选 AI API (仅在配置后启用)
try:
    from core.ai_api import ai_analyze_file
except ImportError:
    ai_analyze_file = None

# ─── 危险特征库 ─────────────────────────────────────

MALICIOUS_PATTERNS = {
    # Shell 反弹 / 远程控制
    "reverse_shell": [
        r'bash -i >& /dev/tcp/',
        r'/dev/tcp/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',
        r'mkfifo /tmp/.*; cat /tmp/.*',
        r'sh -i >& /dev/udp/',
        r'nc\s+-e\s+/bin/',
        r'ncat\s+-e\s+/bin/',
        r'socat\s+.*exec:',
    ],
    # 勒索 / 破坏
    "ransomware": [
        r'openssl\s+enc\s+-aes',
        r'gpg\s+--symmetric.*--output',
        r'find\s+/.*-name\s+.*-exec\s+.*rm',
        r'chmod\s+000\s+/',
        r'dd\s+if=/dev/urandom\s+of=',
    ],
    # 信息窃取
    "info_stealer": [
        r'curl.*\b(token|password|secret|key|credential)\b',
        r'wget.*\b(token|password|secret|key|credential)\b',
        r'cat\s+.*\.(pem|key|id_rsa|env)',
        r'scp\s+.*\b(\.ssh|\.aws|\.config)\b',
    ],
    # 自复制 / 蠕虫
    "worm": [
        r'cp\s+.*\$0\s+',
        r'for\s+.*\bdo\s+.*cp\s+\$',
        r'wget.*-O\s+/tmp/.*&&\s+(bash|chmod)',
        r'curl.*-o\s+/tmp/.*&&\s+(bash|chmod)',
    ],
    # 挖矿
    "crypto_miner": [
        r'stratum\+[a-z]*://',
        r'xmrig',
        r'minerd',
        r'ethminer',
        r'--algo\s+(rx|cn|astroid)',
        r'pool\.mine',
    ],
    # 权限提升
    "privilege_escalation": [
        r'sudo\s+chmod\s+4[0-9]{3}\s+/etc/',
        r'chown\s+.*:.*\s+/etc/',
        r'echo\s+".*"\s*>=\s+/etc/',
        r'usermod\s+-aG\s+sudo',
        r'pkexec\s+--user\s+root',
    ],
    # 下载执行
    "download_and_execute": [
        r'(wget|curl)\s+.*(?:https?|ftp)://.*\s*[|;]\s*(?:bash|sh|python|perl)',
        r'(wget|curl)\s+.*(?:https?|ftp)://.*\s*&&\s*(?:bash|sh|python|perl)',
        r'python[23]?\s+-c\s+["\'].*urllib.*',
    ],
    # Windows PE / ELF 二进制在非预期位置
    "binary_anomaly": [
        rb'^\x7fELF',
        rb'^MZ',
    ],
}

# 扩展名风险评分 (0-100)
EXTENSION_RISK = {
    # 极高风险
    '.exe': 90, '.dll': 85, '.sys': 90, '.vbs': 85,
    '.ps1': 85, '.bat': 80, '.cmd': 80, '.scr': 85,
    '.jar': 70, '.class': 60,
    # 脚本类
    '.sh': 40,  # 正常脚本低分，内容检测加分
    '.py': 30, '.pl': 35, '.rb': 35, '.php': 40,
    '.js': 45, '.jse': 80, '.wsf': 80,
    # 宏 / office
    '.docm': 60, '.xlsm': 60, '.pptm': 60,
    '.doc': 20, '.xls': 20,
    # 安装包
    '.msi': 65, '.appimage': 50, '.deb': 40, '.rpm': 40,
    # 压缩包 (可能含毒)
    '.zip': 25, '.rar': 25, '.7z': 25, '.gz': 20,
    # 其他
    '.bin': 70, '.dat': 40, '.tmp': 30,
}

# 安全扩展 (白名单)
SAFE_EXTENSIONS = {
    '.txt', '.md', '.log', '.json', '.yaml', '.yml', '.toml',
    '.ini', '.cfg', '.conf', '.xml', '.html', '.css', '.csv',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.ico',
    '.mp3', '.mp4', '.wav', '.flac', '.ogg', '.avi', '.mov',
    '.pdf', '.epub', '.mobi',
    '.c', '.h', '.cpp', '.hpp', '.rs', '.go', '.swift',
    '.ts', '.jsx', '.tsx',
}

# ─── 核心检测函数 ──────────────────────────────────

def calculate_entropy(data: bytes) -> float:
    """计算字节熵 (Shannon entropy)，高熵 ≈ 加密/压缩/混淆"""
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy


def sha256_hash(filepath: str) -> str:
    """计算文件 SHA256"""
    h = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def scan_content(filepath: str) -> dict:
    """扫描文件内容，返回匹配到的危险模式"""
    results = {}
    try:
        with open(filepath, 'rb') as f:
            data = f.read(1024 * 1024)  # 最多读 1MB
    except Exception:
        return results

    # 尝试解码为文本 (忽略错误)
    try:
        text = data.decode('utf-8', errors='ignore')
    except Exception:
        text = data.decode('latin-1', errors='ignore')

    for category, patterns in MALICIOUS_PATTERNS.items():
        if category == "binary_anomaly":
            # 二进制模式用 bytes 匹配
            for p in patterns:
                if re.search(p, data):
                    results.setdefault(category, []).append(p.pattern if hasattr(p, 'pattern') else str(p))
        else:
            for p in patterns:
                if re.search(p, text, re.IGNORECASE):
                    results.setdefault(category, []).append(p.pattern if hasattr(p, 'pattern') else str(p))
    return results


def analyze_file(filepath: str) -> dict:
    """
    综合 AI 分析文件，返回:
      - risk_score: 0-100
      - verdict: safe / suspicious / malicious
      - reasons: 得分原因列表
      - matched_patterns: 匹配的危险模式
    """
    path = Path(filepath)
    if not path.exists():
        return {"risk_score": 0, "verdict": "safe",
                "reasons": ["文件不存在"], "matched_patterns": {}}

    reasons = []
    risk_score = 0
    matched = {}

    # 1. 文件大小检查
    size = path.stat().st_size
    if size == 0:
        return {"risk_score": 0, "verdict": "safe",
                "reasons": ["空文件"], "matched_patterns": {}}
    if size > 10 * 1024 * 1024:
        risk_score += 5
        reasons.append(f"大文件 ({size/1024/1024:.1f}MB)")

    # 2. 扩展名分析
    ext = path.suffix.lower()
    if ext in EXTENSION_RISK:
        risk_score += EXTENSION_RISK[ext]
        reasons.append(f"扩展名 '{ext}' 风险 {EXTENSION_RISK[ext]}/100")
    elif ext in SAFE_EXTENSIONS:
        risk_score -= 10
    elif ext == '':
        # 无扩展名 — 检查是否为 ELF 二进制
        try:
            with open(filepath, 'rb') as f:
                magic = f.read(4)
            if magic.startswith(b'\x7fELF'):
                risk_score += 65
                reasons.append("无扩展名 ELF 二进制")
            elif magic.startswith(b'#!'):
                risk_score += 10
                reasons.append("无扩展名脚本文件")
        except Exception:
            pass

    # 3. 熵分析 (对 >1KB 文件)
    try:
        with open(filepath, 'rb') as f:
            sample = f.read(4096)
        entropy = calculate_entropy(sample)
        if size > 1024:
            if entropy > 7.5:
                risk_score += 30
                reasons.append(f"熵极高 ({entropy:.2f}) — 可能加密/混淆")
            elif entropy > 6.5:
                risk_score += 10
                reasons.append(f"熵偏高 ({entropy:.2f})")
    except Exception:
        pass

    # 4. 内容特征扫描
    matched = scan_content(filepath)
    for category, patterns in matched.items():
        severity = {
            "reverse_shell": 50, "ransomware": 60,
            "info_stealer": 40, "worm": 45,
            "crypto_miner": 40, "privilege_escalation": 35,
            "download_and_execute": 50,
        }.get(category, 30)
        risk_score += severity
        reasons.append(f"匹配 {category}: {len(patterns)} 条特征")

    # 5. AI 云端深度分析 (仅对风险评分 >= 35 的)
    if ai_analyze_file and risk_score >= 35:
        try:
            # 取前 2KB 文本做 API 请求
            with open(filepath, "rb") as f:
                sample_raw = f.read(2048)
            try:
                sample_text = sample_raw.decode("utf-8", errors="ignore")
            except Exception:
                sample_text = sample_raw.decode("latin-1", errors="ignore")

            ai_result = ai_analyze_file(filepath, sample_text)
            if ai_result["verdict"] == "malicious" and risk_score < 90:
                risk_score = max(risk_score, ai_result["risk_score"])
                reasons.append(f"AI 分析确认恶意: {ai_result['reason']}")
            elif ai_result["verdict"] == "safe" and risk_score < 50:
                risk_score = min(risk_score, 30)
                reasons.append(f"AI 分析认为安全: {ai_result['reason']}")
            else:
                reasons.append(f"AI 分析: {ai_result['reason']}")
        except Exception:
            pass

    # 6. Hash 查毒 (可选扩展)
    file_hash = sha256_hash(filepath)

    # ─── 判决 ──────────────────────────────────
    if risk_score >= 70:
        verdict = "malicious"
    elif risk_score >= 35:
        verdict = "suspicious"
    else:
        verdict = "safe"

    # 对安全扩展名降级
    if ext in SAFE_EXTENSIONS and verdict == "suspicious":
        verdict = "safe"
        risk_score = min(risk_score, 30)

    return {
        "risk_score": min(risk_score, 100),
        "verdict": verdict,
        "reasons": reasons,
        "matched_patterns": matched,
        "hash": file_hash,
        "size": size,
    }


# ─── 命令行测试 ──────────────────────────────────
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("用法: ai_engine.py <文件路径>")
        sys.exit(1)

    result = analyze_file(sys.argv[1])
    print(json.dumps(result, ensure_ascii=False, indent=2))
