#!/usr/bin/env bash

################################################################################
# RU Server Inbounds Setup Script
#
# Description:
#   Automatically creates 3 VLESS Reality inbounds on RU server:
#   - Inbound #1: VLESS + TCP + Reality (port 7443, firefox, api-maps.yandex.ru)
#   - Inbound #2: VLESS + gRPC + Reality (port 8443, ios, web.max.ru)
#   - Inbound #3: VLESS + XHTTP + Reality (port 2053, ios, web.max.ru)
#
# Usage:
#   bash setup-ru-inbounds.sh
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
readonly LOG_FILE="/var/log/setup-ru-inbounds.log"

# ==============================================================================
# LOGGING & OUTPUT
# ==============================================================================

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"
}

print_header() {
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║        RU Server - Inbounds Setup (3 configurations)         ║"
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

api_get_session() {
    # Extract session cookie
    if [ -f /tmp/3xui-cookies.txt ]; then
        SESSION=$(grep '3x-ui' /tmp/3xui-cookies.txt | awk '{print $7}')
        echo "$SESSION"
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
# CREATE INBOUNDS
# ==============================================================================

create_inbound() {
    local remark="$1"
    local port="$2"
    local network="$3"
    local utls="$4"
    local sni="$5"
    local email="${6:-client-1}"
    local flow="${7:-}"
    local path="${8:-/}"
    local padding_min="${9:-100}"
    local padding_max="${10:-1000}"

    log "Creating inbound: $remark (port $port, network $network)"

    # Generate credentials
    local uuid keys private_key public_key short_id
    uuid=$(generate_uuid)
    keys=$(generate_reality_keys)
    private_key="${keys%|*}"
    public_key="${keys#*|}"
    short_id=$(generate_short_id)

    # Build settings JSON (clients)
    local settings_json
    if [ -n "$flow" ]; then
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
    else
        settings_json=$(jq -n \
            --arg uuid "$uuid" \
            --arg email "$email" \
            '{
                clients: [{
                    id: $uuid,
                    email: $email,
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
    fi

    # Build streamSettings JSON based on network type
    local stream_json
    case "$network" in
        tcp)
            stream_json=$(jq -n \
                --arg sni "$sni" \
                --arg dest "${sni}:443" \
                --arg private_key "$private_key" \
                --arg short_id "$short_id" \
                --arg utls "$utls" \
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
                        fingerprint: $utls
                    },
                    tcpSettings: {
                        acceptProxyProtocol: false,
                        header: {
                            type: "none"
                        }
                    }
                }' | jq -c '.')
            ;;
        grpc)
            stream_json=$(jq -n \
                --arg sni "$sni" \
                --arg dest "${sni}:443" \
                --arg private_key "$private_key" \
                --arg short_id "$short_id" \
                --arg utls "$utls" \
                '{
                    network: "grpc",
                    security: "reality",
                    realitySettings: {
                        show: false,
                        dest: $dest,
                        xver: 0,
                        serverNames: [$sni],
                        privateKey: $private_key,
                        shortIds: [$short_id],
                        fingerprint: $utls
                    },
                    grpcSettings: {
                        serviceName: "",
                        authority: "",
                        multiMode: false
                    }
                }' | jq -c '.')
            ;;
        xhttp)
            stream_json=$(jq -n \
                --arg sni "$sni" \
                --arg dest "${sni}:443" \
                --arg private_key "$private_key" \
                --arg short_id "$short_id" \
                --arg utls "$utls" \
                --arg path "$path" \
                '{
                    network: "xhttp",
                    security: "reality",
                    realitySettings: {
                        show: false,
                        dest: $dest,
                        xver: 0,
                        serverNames: [$sni],
                        privateKey: $private_key,
                        shortIds: [$short_id],
                        fingerprint: $utls
                    },
                    xhttpSettings: {
                        path: $path,
                        host: "",
                        mode: "auto"
                    }
                }' | jq -c '.')
            ;;
    esac

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
        print_success "Inbound '$remark' создан (порт: $port, network: $network)"

        # Save config
        local config_file="/root/inbound-${remark}.json"
        jq -n \
            --arg remark "$remark" \
            --argjson port "$port" \
            --arg network "$network" \
            --arg sni "$sni" \
            --arg uuid "$uuid" \
            --arg public_key "$public_key" \
            --arg short_id "$short_id" \
            --arg email "$email" \
            '{
                remark: $remark,
                port: $port,
                network: $network,
                sni: $sni,
                uuid: $uuid,
                public_key: $public_key,
                short_id: $short_id,
                email: $email
            }' > "$config_file"
        chmod 600 "$config_file"

        print_info "Конфигурация сохранена: $config_file"
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
    log "=== RU Inbounds Setup Started ==="

    check_root
    check_dependencies
    check_3xui

    get_api_credentials

    if ! api_login; then
        print_error "Не удалось подключиться к API"
        exit 1
    fi

    echo ""
    print_info "Создание 3 инбаундов..."
    echo ""

    # Inbound #1: VLESS + TCP + Reality
    print_info "=== Inbound #1: VLESS + TCP + Reality ==="
    create_inbound "RU-TCP-Reality" 7443 "tcp" "firefox" "api-maps.yandex.ru" "client-1" "" "/" 100 1000

    echo ""

    # Inbound #2: VLESS + gRPC + Reality
    print_info "=== Inbound #2: VLESS + gRPC + Reality ==="
    create_inbound "RU-gRPC-Reality" 8443 "grpc" "ios" "web.max.ru" "client-1"

    echo ""

    # Inbound #3: VLESS + XHTTP + Reality
    print_info "=== Inbound #3: VLESS + XHTTP + Reality ==="
    create_inbound "RU-XHTTP-Reality" 2053 "xhttp" "ios" "web.max.ru" "client-1" "" "/" 100 1000

    echo ""
    echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║                  НАСТРОЙКА ЗАВЕРШЕНА                          ║${NC}"
    echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Создано 3 инбаунда:${NC}"
    echo "  1. RU-TCP-Reality (порт 7443, VLESS+TCP+Reality, firefox, api-maps.yandex.ru)"
    echo "  2. RU-gRPC-Reality (порт 8443, VLESS+gRPC+Reality, ios, web.max.ru)"
    echo "  3. RU-XHTTP-Reality (порт 2053, VLESS+XHTTP+Reality, ios, web.max.ru)"
    echo ""
    echo -e "${CYAN}Конфигурации сохранены в:${NC}"
    echo "  • /root/inbound-RU-TCP-Reality.json"
    echo "  • /root/inbound-RU-gRPC-Reality.json"
    echo "  • /root/inbound-RU-XHTTP-Reality.json"
    echo ""
    echo -e "${CYAN}Логи:${NC}"
    echo "  • ${LOG_FILE}"
    echo ""

    # Cleanup
    rm -f /tmp/3xui-cookies.txt

    log "=== RU Inbounds Setup Completed ==="
}

main "$@"
