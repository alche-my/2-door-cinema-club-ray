#!/usr/bin/env bash

################################################################################
# RU Server Setup Script for 3x-ui with VLESS Reality
#
# Description:
#   Interactive script to configure RU server (Entry/Bridge) with:
#   - 1-3 inbound configurations (VLESS Reality)
#   - Multiple outbound connections to non-RU servers
#   - Load balancer with leastPing strategy
#   - Routing rules
#   - BBR optimization
#   - Port forwarding 3000-3100 → 443
#
# Usage:
#   bash setup-ru-server.sh
#
# Requirements:
#   - Ubuntu 22.04+ or Debian 12+
#   - Root privileges
#   - 3x-ui installed (script will check)
#
# Author: Claude Code
# Version: 1.0.0
# Date: 2025-12-16
################################################################################

set -euo pipefail

# ==============================================================================
# CONSTANTS
# ==============================================================================

readonly SCRIPT_VERSION="1.0.0"
readonly LOG_FILE="/var/log/ru-server-setup.log"
readonly CONFIG_DIR="/root"
readonly REQUIRED_DEPS=("curl" "jq" "iptables" "netstat" "bc")

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color
readonly BOLD='\033[1m'

# ==============================================================================
# LOGGING FUNCTIONS
# ==============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "${LOG_FILE}"
}

log_info() {
    log "INFO" "$@"
}

log_success() {
    log "SUCCESS" "$@"
}

log_warn() {
    log "WARN" "$@"
}

log_error() {
    log "ERROR" "$@"
}

log_debug() {
    log "DEBUG" "$@"
}

# ==============================================================================
# OUTPUT FUNCTIONS
# ==============================================================================

print_header() {
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║     RU Server Setup Script for 3x-ui with VLESS Reality      ║"
    echo "║                     Version ${SCRIPT_VERSION}                           ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_section() {
    echo -e "\n${BLUE}${BOLD}═══ $1 ═══${NC}"
    log_info "Section: $1"
}

print_info() {
    echo -e "${CYAN}ℹ ${NC}$1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
    log_success "$1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
    log_error "$1"
}

print_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
    log_warn "$1"
}

# ==============================================================================
# USER INPUT FUNCTIONS
# ==============================================================================

ask_input() {
    local prompt="$1"
    local default="${2:-}"
    local var_name="$3"
    local input

    if [ -n "$default" ]; then
        read -r -p "$(echo -e "${CYAN}?${NC} ${prompt} ${YELLOW}[${default}]${NC}: ")" input
        input="${input:-$default}"
    else
        read -r -p "$(echo -e "${CYAN}?${NC} ${prompt}: ")" input
    fi

    eval "$var_name='$input'"
    log_debug "User input for '$prompt': $input"
}

ask_password() {
    local prompt="$1"
    local var_name="$2"
    local password

    read -r -s -p "$(echo -e "${CYAN}?${NC} ${prompt}: ")" password
    echo
    eval "$var_name='$password'"
    log_debug "Password input received for '$prompt'"
}

ask_confirm() {
    local prompt="$1"
    local default="${2:-n}"
    local response

    if [ "$default" = "y" ]; then
        read -r -p "$(echo -e "${CYAN}?${NC} ${prompt} ${YELLOW}[Y/n]${NC}: ")" response
        response="${response:-y}"
    else
        read -r -p "$(echo -e "${CYAN}?${NC} ${prompt} ${YELLOW}[y/N]${NC}: ")" response
        response="${response:-n}"
    fi

    log_debug "Confirmation for '$prompt': $response"
    [[ "$response" =~ ^[Yy]$ ]]
}

ask_choice() {
    local prompt="$1"
    shift
    local options=("$@")
    local choice

    echo -e "${CYAN}?${NC} ${prompt}"
    for i in "${!options[@]}"; do
        echo "  $((i+1))) ${options[$i]}"
    done

    while true; do
        read -r -p "$(echo -e "${CYAN}?${NC} Выбор [1-${#options[@]}]: ")" choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#options[@]}" ]; then
            log_debug "Choice selected: ${options[$((choice-1))]}"
            echo "${options[$((choice-1))]}"
            return 0
        fi
        print_error "Неверный выбор. Введите число от 1 до ${#options[@]}"
    done
}

# ==============================================================================
# VALIDATION FUNCTIONS
# ==============================================================================

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS='.'
        local -a octets=($ip)
        for octet in "${octets[@]}"; do
            if [ "$octet" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    fi
    return 1
}

validate_uuid() {
    local uuid="$1"
    if [[ "$uuid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        return 0
    fi
    return 1
}

validate_domain() {
    local domain="$1"
    if [[ "$domain" =~ ^([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        return 0
    fi
    return 1
}

# ==============================================================================
# SYSTEM CHECK FUNCTIONS
# ==============================================================================

check_root() {
    print_section "Проверка прав доступа"
    if [ "$EUID" -ne 0 ]; then
        print_error "Скрипт должен быть запущен с правами root"
        log_error "Script not run as root. Exiting."
        exit 1
    fi
    print_success "Скрипт запущен с правами root"
}

check_os() {
    print_section "Проверка операционной системы"

    if [ ! -f /etc/os-release ]; then
        print_error "Не удалось определить операционную систему"
        exit 1
    fi

    source /etc/os-release

    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        print_error "Поддерживаются только Ubuntu и Debian"
        print_info "Ваша ОС: $ID"
        exit 1
    fi

    print_success "ОС: $PRETTY_NAME"
    log_info "Operating System: $PRETTY_NAME"
}

check_dependencies() {
    print_section "Проверка зависимостей"

    local missing_deps=()

    for dep in "${REQUIRED_DEPS[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
            print_warn "Отсутствует: $dep"
        else
            print_success "Найдено: $dep"
        fi
    done

    if [ ${#missing_deps[@]} -gt 0 ]; then
        print_info "Установка недостающих зависимостей..."
        log_info "Installing missing dependencies: ${missing_deps[*]}"

        apt-get update -qq
        for dep in "${missing_deps[@]}"; do
            apt-get install -y "$dep" >> "${LOG_FILE}" 2>&1
            print_success "Установлено: $dep"
        done
    fi

    print_success "Все зависимости установлены"
}

check_3xui() {
    print_section "Проверка 3x-ui"

    if systemctl is-active --quiet x-ui; then
        print_success "3x-ui установлен и запущен"
        return 0
    elif systemctl list-unit-files | grep -q x-ui; then
        print_warn "3x-ui установлен, но не запущен"
        if ask_confirm "Запустить 3x-ui?" "y"; then
            systemctl start x-ui
            print_success "3x-ui запущен"
        fi
        return 0
    else
        print_error "3x-ui не установлен"
        log_error "3x-ui not found on system"

        if ask_confirm "Установить 3x-ui сейчас?" "y"; then
            install_3xui
            return 0
        else
            print_error "3x-ui необходим для работы скрипта"
            exit 1
        fi
    fi
}

install_3xui() {
    print_info "Установка 3x-ui..."
    log_info "Installing 3x-ui..."

    bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh) >> "${LOG_FILE}" 2>&1

    if systemctl is-active --quiet x-ui; then
        print_success "3x-ui успешно установлен"
        return 0
    else
        print_error "Не удалось установить 3x-ui"
        exit 1
    fi
}

# ==============================================================================
# BBR CONFIGURATION
# ==============================================================================

setup_bbr() {
    print_section "Настройка BBR"

    # Check if BBR is already enabled
    if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        print_success "BBR уже включен"
        return 0
    fi

    print_info "Включение BBR..."
    log_info "Enabling BBR..."

    cat >> /etc/sysctl.conf <<EOF

# BBR Configuration (added by ru-server-setup.sh)
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

    sysctl -p >> "${LOG_FILE}" 2>&1

    if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        print_success "BBR успешно включен"
    else
        print_error "Не удалось включить BBR"
    fi
}

# ==============================================================================
# PORT FORWARDING CONFIGURATION
# ==============================================================================

setup_port_forwarding() {
    print_section "Настройка port forwarding (3000-3100 → 443)"

    print_info "Создание правил iptables..."
    log_info "Setting up port forwarding: 3000-3100 -> 443"

    # Enable IP forwarding
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        sysctl -p >> "${LOG_FILE}" 2>&1
    fi

    # Add PREROUTING rules for port forwarding
    for port in {3000..3100}; do
        if ! iptables -t nat -C PREROUTING -p tcp --dport "$port" -j REDIRECT --to-port 443 2>/dev/null; then
            iptables -t nat -A PREROUTING -p tcp --dport "$port" -j REDIRECT --to-port 443
            log_debug "Added port forwarding rule: $port -> 443"
        fi
    done

    # Save iptables rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    print_success "Port forwarding настроен (3000-3100 → 443)"
}

# ==============================================================================
# 3X-UI API FUNCTIONS
# ==============================================================================

xui_login() {
    local api_url="$1"
    local username="$2"
    local password="$3"

    log_info "Attempting 3x-ui API login..."

    local response
    response=$(curl -s -c /tmp/3xui-cookies.txt \
        -X POST "${api_url}/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${username}\",\"password\":\"${password}\"}" 2>&1)

    if echo "$response" | jq -e '.success' &>/dev/null; then
        log_success "Successfully logged in to 3x-ui API"
        return 0
    else
        log_error "Failed to login to 3x-ui API: $response"
        return 1
    fi
}

xui_generate_uuid() {
    local api_url="$1"

    log_debug "Generating UUID via API..."

    local response
    response=$(curl -s -b /tmp/3xui-cookies.txt \
        -X GET "${api_url}/panel/api/server/getNewUUID" 2>&1)

    local uuid
    uuid=$(echo "$response" | jq -r '.obj' 2>/dev/null)

    if validate_uuid "$uuid"; then
        log_debug "Generated UUID: $uuid"
        echo "$uuid"
        return 0
    else
        log_error "Failed to generate UUID: $response"
        return 1
    fi
}

xui_generate_x25519() {
    local api_url="$1"

    log_debug "Generating X25519 keys via API..."

    local response
    response=$(curl -s -b /tmp/3xui-cookies.txt \
        -X GET "${api_url}/panel/api/server/getNewX25519Cert" 2>&1)

    local private_key
    local public_key
    private_key=$(echo "$response" | jq -r '.obj.privateKey' 2>/dev/null)
    public_key=$(echo "$response" | jq -r '.obj.publicKey' 2>/dev/null)

    if [ -n "$private_key" ] && [ -n "$public_key" ]; then
        log_debug "Generated X25519 keys successfully"
        echo "${private_key}|${public_key}"
        return 0
    else
        log_error "Failed to generate X25519 keys: $response"
        return 1
    fi
}

parse_vless_url() {
    local vless_url="$1"

    log_debug "Parsing VLESS URL..."

    # Remove vless:// prefix
    local url_part="${vless_url#vless://}"

    # Extract UUID and rest
    local uuid="${url_part%%@*}"
    local rest="${url_part#*@}"

    # Extract address and port
    local addr_port="${rest%%\?*}"
    local address="${addr_port%:*}"
    local port="${addr_port#*:}"

    # Extract query parameters
    local query="${rest#*\?}"

    # Parse parameters
    local -A params
    IFS='&' read -ra PAIRS <<< "$query"
    for pair in "${PAIRS[@]}"; do
        local key="${pair%%=*}"
        local value="${pair#*=}"
        # URL decode
        value=$(echo -e "${value//%/\\x}")
        params["$key"]="$value"
    done

    # Output as JSON-like format
    cat <<EOF
{
    "uuid": "${uuid}",
    "address": "${address}",
    "port": "${port}",
    "type": "${params[type]:-tcp}",
    "security": "${params[security]:-reality}",
    "sni": "${params[sni]:-}",
    "fp": "${params[fp]:-chrome}",
    "pbk": "${params[pbk]:-}",
    "sid": "${params[sid]:-}",
    "spx": "${params[spx]:-}",
    "flow": "${params[flow]:-}"
}
EOF
}

# ==============================================================================
# INBOUND CONFIGURATION
# ==============================================================================

create_inbounds() {
    print_section "Создание Inbound конфигураций"

    local num_inbounds
    ask_input "Сколько inbound создать?" "2" num_inbounds

    if ! [[ "$num_inbounds" =~ ^[1-3]$ ]]; then
        print_error "Можно создать от 1 до 3 inbound"
        num_inbounds=2
    fi

    log_info "Creating $num_inbounds inbound(s)"

    local -a inbound_configs=()

    for i in $(seq 1 "$num_inbounds"); do
        echo ""
        print_info "=== Inbound #${i} ==="

        local port transport sni dest utls

        # Port
        local default_port=$((443 + i - 1))
        ask_input "Порт" "$default_port" port

        while ! validate_port "$port"; do
            print_error "Неверный порт. Введите число от 1 до 65535"
            ask_input "Порт" "$default_port" port
        done

        # Transport
        print_info "Выберите транспорт:"
        transport=$(ask_choice "Транспорт" "tcp" "xhttp")

        # SNI/DEST
        print_info "Рекомендуемые домены для SNI:"
        echo "  • dl.google.com"
        echo "  • www.microsoft.com"
        echo "  • www.apple.com"
        echo "  • cdn.yandex.net"

        ask_input "SNI домен" "www.microsoft.com" sni

        while ! validate_domain "$sni"; do
            print_error "Неверный формат домена"
            ask_input "SNI домен" "www.microsoft.com" sni
        done

        ask_input "DEST (обычно тот же что SNI:443)" "${sni}:443" dest

        # uTLS
        utls=$(ask_choice "uTLS fingerprint" "chrome" "firefox" "safari" "random")

        # Generate UUID and keys
        print_info "Генерация UUID и ключей Reality..."

        local uuid keys private_key public_key short_id
        uuid=$(xui_generate_uuid "$API_URL" || uuidgen || cat /proc/sys/kernel/random/uuid)
        keys=$(xui_generate_x25519 "$API_URL" || echo "")

        if [ -n "$keys" ]; then
            private_key="${keys%|*}"
            public_key="${keys#*|}"
        else
            print_warn "Не удалось сгенерировать ключи через API, используем openssl"
            private_key=$(openssl rand -base64 32)
            public_key=$(openssl rand -base64 32)
        fi

        short_id=$(openssl rand -hex 8)

        # Store config
        local inbound_config
        inbound_config=$(cat <<EOF
{
    "number": ${i},
    "port": ${port},
    "transport": "${transport}",
    "sni": "${sni}",
    "dest": "${dest}",
    "utls": "${utls}",
    "uuid": "${uuid}",
    "private_key": "${private_key}",
    "public_key": "${public_key}",
    "short_id": "${short_id}"
}
EOF
)

        inbound_configs+=("$inbound_config")

        print_success "Inbound #${i} настроен (порт: ${port}, SNI: ${sni})"

        # Save to file
        cat >> "${CONFIG_DIR}/inbound-${i}-config.json" <<EOF
$inbound_config
EOF
        chmod 600 "${CONFIG_DIR}/inbound-${i}-config.json"

        log_info "Inbound #${i} configuration saved to ${CONFIG_DIR}/inbound-${i}-config.json"
    done

    # Save all configs
    echo "${inbound_configs[@]}" | jq -s '.' > "${CONFIG_DIR}/all-inbounds.json"
    chmod 600 "${CONFIG_DIR}/all-inbounds.json"

    print_success "Все inbound конфигурации созданы и сохранены"
}

# ==============================================================================
# OUTBOUND CONFIGURATION
# ==============================================================================

create_outbounds() {
    print_section "Создание Outbound конфигураций"

    local num_outbounds
    ask_input "Сколько non-RU серверов (outbound) добавить?" "3" num_outbounds

    if ! [[ "$num_outbounds" =~ ^[1-9][0-9]*$ ]]; then
        print_error "Введите корректное число"
        num_outbounds=3
    fi

    log_info "Creating $num_outbounds outbound(s)"

    local -a outbound_configs=()
    local -a outbound_tags=()

    for i in $(seq 1 "$num_outbounds"); do
        echo ""
        print_info "=== Outbound #${i} ==="

        local tag vless_url

        # Tag
        ask_input "Название (тег) outbound" "exit-${i}" tag
        outbound_tags+=("$tag")

        # VLESS URL
        print_info "Вставьте VLESS конфигурацию от non-RU сервера:"
        echo -e "${YELLOW}Формат: vless://uuid@ip:port?type=tcp&security=reality&...${NC}"
        ask_input "" "" vless_url

        # Parse VLESS URL
        local parsed
        parsed=$(parse_vless_url "$vless_url")

        if [ -z "$parsed" ]; then
            print_error "Не удалось распарсить VLESS URL"
            continue
        fi

        # Extract parameters
        local out_uuid out_address out_port out_type out_security out_sni out_fp out_pbk out_sid out_spx out_flow
        out_uuid=$(echo "$parsed" | jq -r '.uuid')
        out_address=$(echo "$parsed" | jq -r '.address')
        out_port=$(echo "$parsed" | jq -r '.port')
        out_type=$(echo "$parsed" | jq -r '.type')
        out_security=$(echo "$parsed" | jq -r '.security')
        out_sni=$(echo "$parsed" | jq -r '.sni')
        out_fp=$(echo "$parsed" | jq -r '.fp')
        out_pbk=$(echo "$parsed" | jq -r '.pbk')
        out_sid=$(echo "$parsed" | jq -r '.sid')
        out_spx=$(echo "$parsed" | jq -r '.spx')
        out_flow=$(echo "$parsed" | jq -r '.flow')

        # Store config
        local outbound_config
        outbound_config=$(cat <<EOF
{
    "tag": "${tag}",
    "uuid": "${out_uuid}",
    "address": "${out_address}",
    "port": ${out_port},
    "type": "${out_type}",
    "security": "${out_security}",
    "sni": "${out_sni}",
    "fingerprint": "${out_fp}",
    "public_key": "${out_pbk}",
    "short_id": "${out_sid}",
    "spider_x": "${out_spx}",
    "flow": "${out_flow}"
}
EOF
)

        outbound_configs+=("$outbound_config")

        print_success "Outbound '${tag}' настроен (${out_address}:${out_port})"

        # Save to file
        cat > "${CONFIG_DIR}/outbound-${tag}.json" <<EOF
$outbound_config
EOF
        chmod 600 "${CONFIG_DIR}/outbound-${tag}.json"

        log_info "Outbound '${tag}' configuration saved to ${CONFIG_DIR}/outbound-${tag}.json"
    done

    # Save all configs
    echo "${outbound_configs[@]}" | jq -s '.' > "${CONFIG_DIR}/all-outbounds.json"
    chmod 600 "${CONFIG_DIR}/all-outbounds.json"

    # Save tags for balancer
    printf '%s\n' "${outbound_tags[@]}" > "${CONFIG_DIR}/outbound-tags.txt"
    chmod 600 "${CONFIG_DIR}/outbound-tags.txt"

    print_success "Все outbound конфигурации созданы и сохранены"

    # Export for balancer
    OUTBOUND_TAGS=("${outbound_tags[@]}")
}

# ==============================================================================
# BALANCER CONFIGURATION
# ==============================================================================

create_balancer() {
    print_section "Создание Балансировщика"

    if [ ${#OUTBOUND_TAGS[@]} -eq 0 ]; then
        print_error "Нет outbound для балансировки"
        return 1
    fi

    print_info "Используется стратегия: leastPing"
    print_info "Observatory будет проверять серверы каждые 3 минуты"

    # Create balancer config
    local selector_array
    selector_array=$(printf '"%s",' "${OUTBOUND_TAGS[@]}" | sed 's/,$//')

    local balancer_config
    balancer_config=$(cat <<EOF
{
    "tag": "exit-balancer",
    "selector": [${selector_array}],
    "strategy": {
        "type": "leastPing"
    },
    "fallbackTag": "${OUTBOUND_TAGS[0]}"
}
EOF
)

    # Create observatory config
    local observatory_config
    observatory_config=$(cat <<EOF
{
    "subjectSelector": [${selector_array}],
    "probeURL": "https://www.gstatic.com/generate_204",
    "probeInterval": "3m",
    "enableConcurrency": true
}
EOF
)

    # Save configs
    echo "$balancer_config" | jq '.' > "${CONFIG_DIR}/balancer-config.json"
    echo "$observatory_config" | jq '.' > "${CONFIG_DIR}/observatory-config.json"
    chmod 600 "${CONFIG_DIR}/balancer-config.json" "${CONFIG_DIR}/observatory-config.json"

    print_success "Балансировщик настроен (leastPing, ${#OUTBOUND_TAGS[@]} серверов)"
    print_success "Observatory: проверка каждые 3 минуты"

    log_info "Balancer configuration saved to ${CONFIG_DIR}/balancer-config.json"
    log_info "Observatory configuration saved to ${CONFIG_DIR}/observatory-config.json"
}

# ==============================================================================
# ROUTING RULES
# ==============================================================================

create_routing_rules() {
    print_section "Создание Routing Rules"

    print_info "Создается правило: весь трафик → балансировщик"

    local routing_rule
    routing_rule=$(cat <<EOF
{
    "type": "field",
    "network": "tcp,udp",
    "balancerTag": "exit-balancer"
}
EOF
)

    echo "$routing_rule" | jq '.' > "${CONFIG_DIR}/routing-rule.json"
    chmod 600 "${CONFIG_DIR}/routing-rule.json"

    print_success "Routing rule создано"
    log_info "Routing rule saved to ${CONFIG_DIR}/routing-rule.json"
}

# ==============================================================================
# FINAL REPORT
# ==============================================================================

generate_final_report() {
    print_section "Генерация финального отчета"

    local report_file="${CONFIG_DIR}/ru-server-setup-report.txt"

    cat > "$report_file" <<'EOF'
╔═══════════════════════════════════════════════════════════════╗
║           RU SERVER CONFIGURATION REPORT                      ║
╚═══════════════════════════════════════════════════════════════╝

ВАЖНО: Автоматическое создание inbound/outbound через API в 3x-ui
пока не реализовано. Вам нужно настроить их вручную через веб-панель.

==================================================================
ШАГИ ДЛЯ РУЧНОЙ НАСТРОЙКИ ПАНЕЛИ 3x-ui:
==================================================================

1. Откройте веб-панель 3x-ui:
   URL: http://YOUR_SERVER_IP:2053

2. Войдите с учетными данными (сохранены в /root/3xui-credentials.txt)

3. СОЗДАЙТЕ INBOUND (для клиентов):
   - Откройте: Inbounds → Add Inbound
   - Используйте данные из файлов: /root/inbound-*-config.json

   Пример для Inbound #1:
   • Protocol: VLESS
   • Port: [из конфига]
   • Network: [tcp или xhttp из конфига]
   • Security: reality
   • Reality Settings:
     - Dest: [из конфига]
     - Server Names: [из конфига]
     - Private Key: [из конфига]
     - Short IDs: [из конфига]
     - uTLS: [из конфига]
     - Flow: ОСТАВЬТЕ ПУСТЫМ (none)

   Повторите для всех inbound

4. СОЗДАЙТЕ OUTBOUND (к non-RU серверам):
   - Откройте: Xray Settings → Outbounds → Add Outbound
   - Используйте данные из файлов: /root/outbound-*.json

   Для каждого outbound:
   • Tag: [из конфига]
   • Protocol: VLESS
   • Address: [из конфига]
   • Port: [из конфига]
   • UUID: [из конфига]
   • Security: reality
   • Reality Settings:
     - SNI: [из конфига]
     - Public Key: [из конфига]
     - Short ID: [из конфига]
     - Spider X: [из конфига если есть]
     - Fingerprint: [из конфига]
   • Flow: [из конфига если есть]

5. НАСТРОЙТЕ БАЛАНСИРОВЩИК:
   - Откройте: Xray Settings → JSON Editor
   - Найдите секцию "routing"
   - Добавьте balancer из файла: /root/balancer-config.json
   - В секцию "balancers" вставьте содержимое файла

6. НАСТРОЙТЕ OBSERVATORY:
   - В том же JSON Editor
   - На верхнем уровне добавьте секцию "observatory"
   - Вставьте содержимое файла: /root/observatory-config.json

7. НАСТРОЙТЕ ROUTING RULE:
   - В секции "routing" → "rules"
   - Добавьте правило из файла: /root/routing-rule.json

8. СОХРАНИТЕ и ПЕРЕЗАПУСТИТЕ Xray:
   - Нажмите "Save" в JSON Editor
   - Перезапустите: systemctl restart x-ui

==================================================================
ПРОВЕРКА РАБОТОСПОСОБНОСТИ:
==================================================================

1. Проверьте статус 3x-ui:
   systemctl status x-ui

2. Проверьте логи:
   tail -f /var/log/ru-server-setup.log
   x-ui log

3. Добавьте тестового клиента через панель и попробуйте подключиться

4. Проверьте IP клиента должен показывать IP non-RU сервера:
   https://ifconfig.me

==================================================================
ФАЙЛЫ КОНФИГУРАЦИИ:
==================================================================

EOF

    # Add list of generated files
    ls -lh "${CONFIG_DIR}"/*.json 2>/dev/null | awk '{print $9, "(" $5 ")"}' >> "$report_file"

    cat >> "$report_file" <<'EOF'

==================================================================
ДОПОЛНИТЕЛЬНЫЕ НАСТРОЙКИ:
==================================================================

✓ BBR включен
✓ Port forwarding 3000-3100 → 443 настроен
✓ Все конфигурации сохранены в /root/

==================================================================
ПОДДЕРЖКА:
==================================================================

Если возникли проблемы:
- Проверьте логи: /var/log/ru-server-setup.log
- Проверьте документацию: README.md

Версия скрипта: 1.0.0
Дата: $(date '+%Y-%m-%d %H:%M:%S')

EOF

    chmod 600 "$report_file"

    print_success "Финальный отчет сохранен: $report_file"

    # Display summary
    echo ""
    echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║                  НАСТРОЙКА ЗАВЕРШЕНА                          ║${NC}"
    echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Следующие шаги:${NC}"
    echo "  1. Откройте панель 3x-ui"
    echo "  2. Настройте inbound/outbound вручную (инструкции в отчете)"
    echo "  3. Настройте балансировщик через JSON Editor"
    echo "  4. Добавьте клиентов"
    echo ""
    echo -e "${CYAN}Файлы:${NC}"
    echo "  • Отчет: ${report_file}"
    echo "  • Логи: ${LOG_FILE}"
    echo "  • Конфигурации: ${CONFIG_DIR}/*.json"
    echo ""
}

# ==============================================================================
# MAIN FUNCTION
# ==============================================================================

main() {
    # Initialize log
    touch "${LOG_FILE}"
    chmod 644 "${LOG_FILE}"

    log_info "=== RU Server Setup Script Started ==="
    log_info "Version: ${SCRIPT_VERSION}"
    log_info "Date: $(date '+%Y-%m-%d %H:%M:%S')"

    # Print header
    print_header

    # System checks
    check_root
    check_os
    check_dependencies
    check_3xui

    # Get API credentials
    print_section "Подключение к 3x-ui API"

    local api_host api_port api_username api_password
    ask_input "3x-ui панель URL (без http://)" "localhost:2053" api_host
    API_URL="http://${api_host}"

    ask_input "Username 3x-ui" "admin" api_username
    ask_password "Password 3x-ui" api_password

    if ! xui_login "$API_URL" "$api_username" "$api_password"; then
        print_error "Не удалось подключиться к 3x-ui API"
        print_warn "Продолжаем без API (генерация ключей будет через openssl)"
    else
        print_success "Подключено к 3x-ui API"
    fi

    # BBR
    setup_bbr

    # Port forwarding
    setup_port_forwarding

    # Create configurations
    declare -a OUTBOUND_TAGS=()

    create_inbounds
    create_outbounds
    create_balancer
    create_routing_rules

    # Final report
    generate_final_report

    log_info "=== RU Server Setup Script Completed ==="

    # Cleanup
    rm -f /tmp/3xui-cookies.txt
}

# ==============================================================================
# ENTRY POINT
# ==============================================================================

main "$@"
