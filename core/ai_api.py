#!/usr/bin/env python3
"""
AI杀软 — 云端 AI 分析接口
调用 LLM API 进行深度文件安全分析
"""

import os
import json
import requests
from core.config import load_config


def ai_analyze_file(filepath: str, sample_text: str = None) -> dict:
    """
    调用 LLM API 分析文件安全性
    返回: {"verdict": "safe|suspicious|malicious", "reason": "...", "risk_score": 0-100}
    """
    cfg = load_config()
    if not cfg.get("enable_ai_scan") or not cfg.get("api_key"):
        return {"verdict": "unknown", "reason": "AI 未配置", "risk_score": 0}

    provider = cfg.get("api_provider", "")
    api_key = cfg.get("api_key", "")
    base_url = cfg.get("api_base_url", "")
    model = cfg.get("api_model", "")

    # 快速验证: Key 太短或明显是测试 Key 则跳过
    if len(api_key) < 8 or api_key.startswith("sk-test") or api_key == "YOUR_API_KEY_HERE":
        return {"verdict": "unknown", "reason": "API Key 无效或测试 Key", "risk_score": 0}

    # 提取文件内容供分析 (最多 2KB)
    if not sample_text:
        try:
            with open(filepath, "rb") as f:
                raw = f.read(2048)
            try:
                sample = raw.decode("utf-8", errors="ignore")
            except Exception:
                sample = raw.decode("latin-1", errors="ignore")
        except Exception:
            sample = ""
    else:
        sample = sample_text[:2048]

    # 构造 Prompt
    prompt = f"""你是一个 AI 安全分析专家。判断以下文件是否包含恶意代码。

分析依据：
1. 是否有反向 Shell、挖矿、勒索等恶意模式
2. 是否有危险系统操作 (rm -rf /, dd, 格式化等)
3. 是否有信息窃取行为
4. 是否下载并执行远程代码
5. 是否有提权行为

仅返回 JSON: {{"verdict": "safe|suspicious|malicious", "risk_score": 0-100, "reason": "简短中文原因"}}

文件名: {os.path.basename(filepath)}
文件内容片段:
```
{sample}
```"""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "你是一个安全分析专家。始终返回纯 JSON，不要包含其他内容。"},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 200
    }

    try:
        url = f"{base_url.rstrip('/')}/chat/completions"
        resp = requests.post(url, headers=headers, json=payload, timeout=8)
        resp.raise_for_status()
        result = resp.json()
        content = result["choices"][0]["message"]["content"].strip()

        # 提取 JSON
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        content = content.strip()

        parsed = json.loads(content)
        return {
            "verdict": parsed.get("verdict", "unknown"),
            "risk_score": parsed.get("risk_score", 0),
            "reason": parsed.get("reason", ""),
        }
    except Exception as e:
        return {"verdict": "unknown", "reason": f"API 调用失败: {str(e)}", "risk_score": 0}
