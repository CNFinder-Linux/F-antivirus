# 🛡️ AI杀软

**AI驱动的智能文件安全检测工具** — 实时监控新建文件、检测恶意脚本执行、自动隔离风险。

## ✨ 核心功能

| 功能 | 说明 |
|------|------|
| 🔍 **新建文件监控** | 自动扫描下载/桌面/tmp 等目录的新文件 |
| 🧠 **AI 双引擎** | 本地启发式引擎 + 云端 LLM 深度分析 |
| ⚡ **脚本执行拦截** | 检测 `.sh` 脚本运行时实时告警 + 自动终止 |
| 🛑 **自动隔离** | 恶意文件自动移至 `~/被隔离的文件/` |
| 🔔 **多重告警** | 终端醒目提示 + 桌面通知 |
| 🚀 **开机自启** | 随系统自动启动 |
| 🔐 **API 灵活配置** | 支持 OpenAI / DeepSeek / 自定义 |

## 🚀 一键部署

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/你的用户名/AI360/main/deploy.sh)
```

部署脚本会:
1. 从 GitHub 拉取源码到 `~/AI360`
2. 安装系统依赖
3. 创建 `~/被隔离的文件/` 隔离区
4. 配置开机自启动
5. 引导输入 API 提供商 + Key
6. 立即启动守护进程

## 📦 手动安装

```bash
# 克隆仓库
git clone https://github.com/你的用户名/AI360.git ~/AI360
cd ~/AI360

# 安装依赖
pip3 install requests
sudo apt-get install -y inotify-tools libnotify-bin

# 首次配置
python3 ai_antivirus.py setup

# 启动
python3 ai_antivirus.py start
```

## 🎮 使用指南

```bash
cd ~/AI360

# 查看状态
python3 ai_antivirus.py status

# 扫描单个文件
python3 ai_antivirus.py scan /path/to/suspicious-file

# 前台实时监控 (看实时告警)
python3 ai_antivirus.py realtime

# 停止
python3 ai_antivirus.py stop

# 重新配置 API
python3 ai_antivirus.py setup
```

## 🧠 检测原理

### 本地引擎 (无需网络)
1. **扩展名风险评分** — .exe/.vbs/.ps1 等高危扩展名自动加分
2. **熵分析** — Shannon 熵 >7.5 标记为加密/混淆/加壳
3. **8 大类危险模式匹配**:
   - 反向 Shell (`bash -i >& /dev/tcp/`)
   - 勒索行为 (`openssl enc -aes`)
   - 挖矿 (`stratum+tcp://`, xmrig)
   - 信息窃取 (`cat .ssh/id_rsa`)
   - 蠕虫自复制 (`wget ... && bash`)
   - 下载执行 (`curl ... | bash`)
   - 权限提升 (`pkexec --user root`)
   - 系统破坏 (`dd if=/dev/urandom`)

### 云端 AI 引擎 (需配置 API)
- 可疑文件送入 LLM 分析 (OpenAI / DeepSeek)
- 更精准的语义理解，减少误报

## 📂 项目结构

```
~/AI360/
├── ai_antivirus.py       # 主入口
├── deploy.sh             # 部署脚本 (GitHub 分发用)
├── README.md
├── core/
│   ├── ai_engine.py      # 本地启发式检测引擎
│   ├── ai_api.py         # 云端 AI API 接口
│   ├── config.py         # 配置管理模块
│   └── monitor.py        # 文件/进程监控器
├── config/
│   └── settings.json     # API 配置 (含 Key)
├── rules/
│   └── custom.rules      # 自定义检测规则
├── logs/
│   └── alerts.log        # 告警日志
└── ... (自动创建)
~/被隔离的文件/            # 隔离区 (自动创建)
```

## 🔧 自定义规则

编辑 `~/AI360/rules/custom.rules`，格式:

```
block:rm\s+-rf\s+/:检测递归删除根目录
warn:nc\s+-e:检测绑定 shell
```

- `block` — 阻止 + 告警
- `warn` — 仅告警
- `monitor` — 仅记录日志

## 📤 上传到 GitHub

```bash
cd ~/桌面/AI-Antivirus
git init
git add .
git commit -m "Initial commit: AI360 Antivirus"
gh repo create AI360 --public --source=. --push
```

上传后修改 `deploy.sh` 顶部的 `GITHUB_USER` 和 `GITHUB_REPO`，然后即可一键安装。

## ⚠️ 安全提示

- API Key 存储在 `~/AI360/config/settings.json` (权限 600)
- 隔离区 `~/被隔离的文件/` 仅当前用户可读写
- 检测到恶意文件自动隔离 + 桌面通知
- 运行 `.sh` 高危脚本自动 `kill`
