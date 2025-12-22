#!/usr/bin/env bash

################################################################################
# Non-RU Server Inbound Setup Script
#
# Description:
#   Automatically creates 1 VLESS Reality inbound on non-RU server:
#   - VLESS + TCP + Reality (port 443, github.com, xtls-rprx-vision)
#
# Usage:
#   bash setup-nonru-inbound.sh
#
# Requirements:
#   - 3x-ui installed and running
#   - curl, jq, openssl
#
# Author: Claude Code
# Version: 1.0.0
################################################################################

set -euo pipefail

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# Log file
readonly LOG_FILE="/var/log/setup-nonru-inbound.log"

# ==============================================================================
# LOGGING & OUTPUT
# ==============================================================================

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"
}

print_header() {
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║      Non-RU Server - Inbound Setup (1 configuration)         ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
    log "SUCCESS: $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
    log "ERROR: $1"
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

# ==============================================================================
# CHECKS
# ==============================================================================

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Скрипт должен быть запущен с правами root"
        exit 1
    fi
}

check_dependencies() {
    for cmd in curl jq openssl; do
        if ! command -v "$cmd" &> /dev/null; then
            print_error "Отсутствует: $cmd"
            exit 1
        fi
    done
    print_success "Все зависимости установлены"
}

check_3xui() {
    if ! systemctl is-active --quiet x-ui; then
        print_error "3x-ui не запущен. Запустите: systemctl start x-ui"
        exit 1
    fi
    print_success "3x-ui запущен"
}

# ==============================================================================
# USER INPUT
# ==============================================================================

get_api_credentials() {
    echo ""
    print_info "Введите данные для подключения к 3x-ui API:"

    read -r -p "$(echo -e "${CYAN}?${NC} URL панели (без http://) [localhost:2053]: ")" API_HOST
    API_HOST="${API_HOST:-localhost:2053}"
    API_URL="http://${API_HOST}"

    read -r -p "$(echo -e "${CYAN}?${NC} Username [admin]: ")" API_USER
    API_USER="${API_USER:-admin}"

    read -r -s -p "$(echo -e "${CYAN}?${NC} Password: ")" API_PASS
    echo ""
}

# ==============================================================================
# API FUNCTIONS
# ==============================================================================

api_login() {
    log "Logging in to 3x-ui API..."

    local response
    response=$(curl -s -c /tmp/3xui-cookies.txt \
        -X POST "${API_URL}/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${API_USER}\",\"password\":\"${API_PASS}\"}")

    if echo "$response" | jq -e '.success' &>/dev/null; then
        print_success "API login успешен"
        return 0
    else
        print_error "API login failed: $response"
        return 1
    fi
}

# ==============================================================================
# GENERATORS
# ==============================================================================

generate_uuid() {
    if command -v uuidgen &>/dev/null; then
        uuidgen | tr '[:upper:]' '[:lower:]'
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

generate_reality_keys() {
    # Generate X25519 keypair
    local private_key public_key

    # Try API first
    local response
    response=$(curl -s -b /tmp/3xui-cookies.txt \
        -X GET "${API_URL}/panel/api/server/getNewX25519Cert" 2>/dev/null)

    private_key=$(echo "$response" | jq -r '.obj.privateKey' 2>/dev/null)
    public_key=$(echo "$response" | jq -r '.obj.publicKey' 2>/dev/null)

    if [ -n "$private_key" ] && [ "$private_key" != "null" ]; then
        echo "${private_key}|${public_key}"
    else
        # Fallback to openssl
        private_key=$(openssl rand -base64 32)
        public_key=$(openssl rand -base64 32)
        echo "${private_key}|${public_key}"
    fi
}

generate_short_id() {
    openssl rand -hex 8
}

# ==============================================================================
# CREATE INBOUND
# ==============================================================================

create_inbound() {
    local remark="NonRU-TCP-Reality"
    local port=443
    local network="tcp"
    local sni="github.com"
    local email="RAWR-2"
    local flow="xtls-rprx-vision"

    log "Creating inbound: $remark (port $port)"

    # Generate credentials
    local uuid keys private_key public_key short_id
    uuid=$(generate_uuid)
    keys=$(generate_reality_keys)
    private_key="${keys%|*}"
    public_key="${keys#*|}"
    short_id=$(generate_short_id)

    # Build settings JSON (clients)
    local settings_json
    settings_json=$(jq -n \
        --arg uuid "$uuid" \
        --arg email "$email" \
        --arg flow "$flow" \
        '{
            clients: [{
                id: $uuid,
                email: $email,
                flow: $flow,
                limitIp: 0,
                totalGB: 0,
                expiryTime: 0,
                enable: true,
                tgId: "",
                subId: ""
            }],
            decryption: "none",
            fallbacks: []
        }' | jq -c '.')

    # Build streamSettings JSON
    local stream_json
    stream_json=$(jq -n \
        --arg sni "$sni" \
        --arg dest "${sni}:443" \
        --arg private_key "$private_key" \
        --arg short_id "$short_id" \
        '{
            network: "tcp",
            security: "reality",
            realitySettings: {
                show: false,
                dest: $dest,
                xver: 0,
                serverNames: [$sni],
                privateKey: $private_key,
                shortIds: [$short_id],
                fingerprint: "chrome"
            },
            tcpSettings: {
                acceptProxyProtocol: false,
                header: {
                    type: "none"
                }
            }
        }' | jq -c '.')

    # Build sniffing JSON
    local sniffing_json
    sniffing_json=$(jq -n '{
        enabled: true,
        destOverride: ["http", "tls", "quic", "fakedns"]
    }' | jq -c '.')

    # Build final request body
    local request_body
    request_body=$(jq -n \
        --argjson port "$port" \
        --arg remark "$remark" \
        --arg settings "$settings_json" \
        --arg stream "$stream_json" \
        --arg sniffing "$sniffing_json" \
        '{
            enable: true,
            port: $port,
            protocol: "vless",
            settings: $settings,
            streamSettings: $stream,
            sniffing: $sniffing,
            remark: $remark,
            listen: "",
            expiryTime: 0
        }')

    # Send request
    local response
    response=$(curl -s -b /tmp/3xui-cookies.txt \
        -X POST "${API_URL}/panel/api/inbounds/add" \
        -H "Accept: application/json" \
        -H "Content-Type: application/json" \
        -d "$request_body")

    if echo "$response" | jq -e '.success' &>/dev/null; then
        print_success "Inbound '$remark' создан (порт: $port)"

        # Save config
        local config_file="/root/inbound-nonru-config.json"
        jq -n \
            --arg remark "$remark" \
            --argjson port "$port" \
            --arg network "$network" \
            --arg sni "$sni" \
            --arg uuid "$uuid" \
            --arg public_key "$public_key" \
            --arg private_key "$private_key" \
            --arg short_id "$short_id" \
            --arg email "$email" \
            --arg flow "$flow" \
            '{
                remark: $remark,
                port: $port,
                network: $network,
                sni: $sni,
                uuid: $uuid,
                public_key: $public_key,
                private_key: $private_key,
                short_id: $short_id,
                email: $email,
                flow: $flow
            }' > "$config_file"
        chmod 600 "$config_file"

        print_info "Конфигурация сохранена: $config_file"

        # Display connection info
        echo ""
        echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}${BOLD}           ДАННЫЕ ДЛЯ ПОДКЛЮЧЕНИЯ RU СЕРВЕРА                   ${NC}"
        echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "${YELLOW}Используйте эти данные для настройки outbound на RU сервере:${NC}"
        echo ""
        echo "UUID:        $uuid"
        echo "Public Key:  $public_key"
        echo "Short ID:    $short_id"
        echo "SNI:         $sni"
        echo "Dest:        ${sni}:443"
        echo "Flow:        $flow"
        echo "Port:        $port"
        echo ""
        echo -e "${CYAN}Сохраните эти данные!${NC}"
        echo ""

        return 0
    else
        print_error "Не удалось создать inbound '$remark': $response"
        return 1
    fi
}

# ==============================================================================
# MAIN
# ==============================================================================

main() {
    print_header

    touch "${LOG_FILE}"
    log "=== Non-RU Inbound Setup Started ==="

    check_root
    check_dependencies
    check_3xui

    get_api_credentials

    if ! api_login; then
        print_error "Не удалось подключиться к API"
        exit 1
    fi

    echo ""
    print_info "Создание inbound..."
    echo ""

    # Create inbound
    print_info "=== VLESS + TCP + Reality (github.com) ==="
    create_inbound

    echo ""
    echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║                  НАСТРОЙКА ЗАВЕРШЕНА                          ║${NC}"
    echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Создан 1 инбаунд:${NC}"
    echo "  • NonRU-TCP-Reality (порт 443, VLESS+TCP+Reality, github.com, xtls-rprx-vision)"
    echo ""
    echo -e "${CYAN}Конфигурация сохранена в:${NC}"
    echo "  • /root/inbound-nonru-config.json"
    echo ""
    echo -e "${CYAN}Логи:${NC}"
    echo "  • ${LOG_FILE}"
    echo ""

    # Cleanup
    rm -f /tmp/3xui-cookies.txt

    log "=== Non-RU Inbound Setup Completed ==="
}

main "$@"
