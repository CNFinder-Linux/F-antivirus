#!/usr/bin/env bash
# ==============================================
#  AI360 杀软 — 一键部署脚本
#  用法: bash <(curl -fsSL https://raw.githubusercontent.com/你的用户名/AI360/main/deploy.sh)
#  或:  bash deploy.sh
# ==============================================
#  本脚本从 GitHub 拉取源码，安装到 ~/AI360，
#  配置开机自启，并引导用户输入 API 信息。
# ==============================================

set -e

RED='\033[1;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
NC='\033[0m'

# ─── GitHub 仓库配置 ──────────────────────────
# 上传到 GitHub 后修改下面三行
GITHUB_USER="你的GitHub用户名"
GITHUB_REPO="AI360"
GITHUB_BRANCH="main"
GITHUB_URL="https://github.com/${GITHUB_USER}/${GITHUB_REPO}.git"

# ─── 目标路径 ────────────────────────────────
INSTALL_DIR="$HOME/AI360"
QUARANTINE_DIR="$HOME/被隔离的文件"
AUTOSTART_DIR="$HOME/.config/autostart"

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════╗"
echo "║       🛡️  AI360 杀软 — 安装向导        ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

# ─── 1. 检查依赖 ─────────────────────────────
echo -e "${YELLOW}[1/6] 检查系统依赖...${NC}"
DEPS_NEEDED=""

for cmd in python3 git inotifywait notify-send; do
    if ! command -v "$cmd" &>/dev/null; then
        DEPS_NEEDED="$DEPS_NEEDED $cmd"
    fi
done

if [ -n "$DEPS_NEEDED" ]; then
    echo -e "  ${YELLOW}[!] 缺失依赖:${DEPS_NEEDED}${NC}"
    echo -e "  ${YELLOW}[~] 正在安装...${NC}"
    sudo apt-get update -qq
    # 先装 git, pip
    sudo apt-get install -y -qq git python3-pip inotify-tools libnotify-bin 2>/dev/null || true
    # requests 用于 AI API 调用
    pip3 install requests --quiet 2>/dev/null || true
fi
echo -e "  ${GREEN}[✓] 依赖检查完成${NC}"

# ─── 2. 从 GitHub 拉取源码 ────────────────────
echo -e "${YELLOW}[2/6] 从 GitHub 拉取源码...${NC}"

if [ -d "$INSTALL_DIR" ]; then
    echo -e "  ${YELLOW}[!] $INSTALL_DIR 已存在，更新中...${NC}"
    cd "$INSTALL_DIR"
    git pull origin "$GITHUB_BRANCH" 2>/dev/null || true
else
    git clone --depth=1 -b "$GITHUB_BRANCH" "$GITHUB_URL" "$INSTALL_DIR" 2>/dev/null || {
        echo -e "  ${RED}[✗] Git 克隆失败，尝试直接下载...${NC}"
        # 如果 git clone 失败，用 curl 下载 zip
        ZIP_URL="https://github.com/${GITHUB_USER}/${GITHUB_REPO}/archive/refs/heads/${GITHUB_BRANCH}.zip"
        if command -v unzip &>/dev/null; then
            curl -fsSL "$ZIP_URL" -o /tmp/ai360.zip
            mkdir -p "$INSTALL_DIR"
            unzip -qo /tmp/ai360.zip -d /tmp/ai360_extract
            cp -r /tmp/ai360_extract/*/* "$INSTALL_DIR/"
            rm -rf /tmp/ai360.zip /tmp/ai360_extract
        else
            echo -e "  ${RED}[✗] 无法下载源码，请检查网络或手动安装 unzip${NC}"
            exit 1
        fi
    }
fi
echo -e "  ${GREEN}[✓] 源码已拉取到 $INSTALL_DIR${NC}"

# ─── 3. 创建隔离目录 ──────────────────────────
echo -e "${YELLOW}[3/6] 创建隔离目录...${NC}"
mkdir -p "$QUARANTINE_DIR"
chmod 700 "$QUARANTINE_DIR"
echo -e "  ${GREEN}[✓] 隔离目录: $QUARANTINE_DIR${NC}"

# ─── 4. 创建必要目录 ──────────────────────────
echo -e "${YELLOW}[4/6] 设置权限和目录...${NC}"
mkdir -p "$INSTALL_DIR"/{logs,config}
touch "$INSTALL_DIR"/logs/alerts.log
chmod +x "$INSTALL_DIR"/ai_antivirus.py 2>/dev/null || true
echo -e "  ${GREEN}[✓] 目录已就绪${NC}"

# ─── 5. 开机自启 ──────────────────────────────
echo -e "${YELLOW}[5/6] 配置开机自启动...${NC}"
mkdir -p "$AUTOSTART_DIR"

cat > "$AUTOSTART_DIR/ai360.desktop" << AUTOEOF
[Desktop Entry]
Type=Application
Name=AI360 杀软
Comment=AI驱动的智能文件安全检测
Exec=python3 $INSTALL_DIR/ai_antivirus.py start
Terminal=false
StartupNotify=false
X-GNOME-Autostart-enabled=true
AUTOEOF

echo -e "  ${GREEN}[✓] 开机自启已配置${NC}"

# ─── 6. 首次配置 (API 提供商 + Key) ──────────
echo -e "${YELLOW}[6/6] 首次 API 配置...${NC}"
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  配置 AI API 以启用云端智能分析"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  支持的提供商:"
echo "    1) OpenAI      — api.openai.com"
echo "    2) DeepSeek    — api.deepseek.com"
echo "    3) 自定义      — 自建 API 地址"
echo ""

# 选择提供商
read -p "  请选择 [1-3] (默认 1): " PROVIDER_CHOICE
PROVIDER_CHOICE=${PROVIDER_CHOICE:-1}

case "$PROVIDER_CHOICE" in
    2)
        API_PROVIDER="deepseek"
        API_BASE="https://api.deepseek.com"
        API_MODEL="deepseek-chat"
        ;;
    3)
        API_PROVIDER="custom"
        read -p "  请输入 API Base URL (如 https://api.xxx.com/v1): " API_BASE
        read -p "  请输入模型名称: " API_MODEL
        ;;
    *)
        API_PROVIDER="openai"
        API_BASE="https://api.openai.com/v1"
        API_MODEL="gpt-4o-mini"
        ;;
esac

# 输入 Key
echo ""
read -p "  请输入 [${API_PROVIDER}] API Key: " API_KEY
while [ -z "$API_KEY" ]; do
    echo -e "  ${YELLOW}[!] API Key 不能为空${NC}"
    read -p "  请输入 [${API_PROVIDER}] API Key: " API_KEY
done

read -p "  启用云端 AI 深度分析? [Y/n]: " AI_ENABLE
AI_ENABLE=${AI_ENABLE:-Y}

# 写入配置
cat > "$INSTALL_DIR/config/settings.json" << CONFIGEOF
{
  "api_provider": "${API_PROVIDER}",
  "api_key": "${API_KEY}",
  "api_base_url": "${API_BASE}",
  "api_model": "${API_MODEL}",
  "enable_ai_scan": $(echo "$AI_ENABLE" | grep -iq "^n" && echo "false" || echo "true"),
  "auto_quarantine": true,
  "watch_dirs": [
    "$HOME/下载",
    "$HOME/Desktop",
    "$HOME/桌面",
    "$HOME/Downloads",
    "/tmp",
    "$HOME"
  ]
}
CONFIGEOF

chmod 600 "$INSTALL_DIR/config/settings.json"
echo -e "  ${GREEN}[✓] API 配置完成${NC}"

# ─── 启动服务 ─────────────────────────────────
echo ""
echo -e "${YELLOW}[~] 启动 AI360 服务...${NC}"
cd "$INSTALL_DIR"
nohup python3 ai_antivirus.py start > /dev/null 2>&1 &
sleep 1

# ─── 完成 ─────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║    ✅  AI360 杀软 安装完成!             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  安装路径: ${CYAN}$INSTALL_DIR${NC}"
echo -e "  隔离目录: ${CYAN}$QUARANTINE_DIR${NC}"
echo ""
echo -e "  ${GREEN}常用命令:${NC}"
echo -e "    python3 $INSTALL_DIR/ai_antivirus.py status   — 查看状态"
echo -e "    python3 $INSTALL_DIR/ai_antivirus.py stop     — 停止"
echo -e "    python3 $INSTALL_DIR/ai_antivirus.py start    — 启动"
echo -e "    python3 $INSTALL_DIR/ai_antivirus.py scan <文件>  — 扫描"
echo -e "    python3 $INSTALL_DIR/ai_antivirus.py setup    — 重新配置 API"
echo ""
echo -e "  ${YELLOW}提示: 终端会实时显示告警，也可查看日志:${NC}"
echo -e "    tail -f $INSTALL_DIR/logs/alerts.log"
echo ""
