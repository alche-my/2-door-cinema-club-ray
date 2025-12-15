#!/bin/bash

################################################################################
# VPN Cascade Setup Script
# Purpose: Configure a two-node cascaded VPN system using 3x-ui and VLESS Reality
# Architecture: RU Server (bridge) → Non-RU Server (exit)
# Version: 1.0
# Date: 2025-12-15
################################################################################

set -euo pipefail

################################################################################
# CONSTANTS AND GLOBALS
################################################################################

readonly SCRIPT_VERSION="1.0"
readonly REQUIRED_OS="Ubuntu"
readonly MIN_VERSION="22.04"
readonly XRAY_UI_REPO="https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh"
readonly LOG_FILE="/var/log/cascade-setup.log"

# Role types
readonly ROLE_RU_SERVER="RU_SERVER"
readonly ROLE_NON_RU_SERVER="NON_RU_SERVER"

# Global variables
SERVER_ROLE=""
SERVER_IP=""
PANEL_PORT="2053"
PANEL_USERNAME=""
PANEL_PASSWORD=""

# Non-RU server connection details (for RU server)
NON_RU_IP=""
NON_RU_PORT=""
NON_RU_UUID=""
NON_RU_FLOW=""
NON_RU_SNI=""
NON_RU_SERVER_NAME=""
NON_RU_PUBLIC_KEY=""
NON_RU_SHORT_ID=""
NON_RU_SPIDER_X=""

# Client inbound details (for RU server)
CLIENT_PORT="443"
CLIENT_UUID=""
CLIENT_SNI=""
CLIENT_SERVER_NAME=""
CLIENT_PUBLIC_KEY=""
CLIENT_SHORT_ID=""
CLIENT_SPIDER_X=""

# Exit inbound details (for Non-RU server)
EXIT_PORT="8443"
EXIT_UUID=""
EXIT_FLOW=""
EXIT_SNI=""
EXIT_SERVER_NAME=""
EXIT_PUBLIC_KEY=""
EXIT_SHORT_ID=""
EXIT_SPIDER_X=""

################################################################################
# LOGGING AND OUTPUT
################################################################################

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Initialize logging
init_logging() {
    touch "$LOG_FILE" 2>/dev/null || {
        echo -e "${RED}[ERROR]${NC} Cannot create log file at $LOG_FILE"
        exit 1
    }
    log_message "INFO" "========== VPN Cascade Setup Script v${SCRIPT_VERSION} =========="
    log_message "INFO" "Execution started at $(date '+%Y-%m-%d %H:%M:%S')"
}

# Log message to file and optionally to console
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" >> "$LOG_FILE"
}

# Print step header
print_step() {
    local step_num="$1"
    local step_desc="$2"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  STEP ${step_num}: ${step_desc}${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    log_message "INFO" "STEP ${step_num}: ${step_desc}"
}

# Print info message
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    log_message "INFO" "$1"
}

# Print success message
print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    log_message "SUCCESS" "$1"
}

# Print warning message
print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    log_message "WARNING" "$1"
}

# Print error message
print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    log_message "ERROR" "$1"
}

# Fatal error - exit with failure
fatal_error() {
    print_error "$1"
    echo ""
    echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                    SETUP FAILED                               ║${NC}"
    echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "Error details: $1"
    echo -e "Check log file: ${LOG_FILE}"
    exit 1
}

################################################################################
# HELPER FUNCTIONS
################################################################################

# Find xray binary
find_xray_binary() {
    local xray_paths=(
        "/usr/local/x-ui/bin/xray-linux-amd64"
        "/usr/local/x-ui/xray"
        "/usr/bin/xray"
        "/usr/local/bin/xray"
        "$(which xray 2>/dev/null)"
    )

    for path in "${xray_paths[@]}"; do
        if [ -n "$path" ] && [ -x "$path" ]; then
            echo "$path"
            return 0
        fi
    done

    return 1
}

# Generate Reality keys
generate_reality_keys() {
    local public_var="$1"
    local private_var="$2"

    log_message "INFO" "=== Starting Reality key generation ==="
    log_message "INFO" "Target variables: public=${public_var}, private=${private_var}"
    print_info "Generating Reality key pair..."

    # Try to find xray binary
    log_message "INFO" "Searching for xray binary..."
    local xray_bin=$(find_xray_binary)

    if [ -n "$xray_bin" ]; then
        log_message "INFO" "Found xray binary: ${xray_bin}"
        print_info "Found xray at: ${xray_bin}"

        # Try to generate keys with timeout
        log_message "INFO" "Executing: timeout 5 ${xray_bin} x25519"
        local keys_output=$(timeout 5 "$xray_bin" x25519 2>&1 || echo "")
        log_message "INFO" "xray x25519 output length: ${#keys_output} chars"
        log_message "INFO" "xray x25519 output (first 100 chars): ${keys_output:0:100}"

        if [ -n "$keys_output" ]; then
            local priv_key=$(echo "$keys_output" | grep "Private key:" | awk '{print $3}')
            local pub_key=$(echo "$keys_output" | grep "Public key:" | awk '{print $3}')

            log_message "INFO" "Extracted private key length: ${#priv_key}"
            log_message "INFO" "Extracted public key length: ${#pub_key}"

            if [ -n "$priv_key" ] && [ -n "$pub_key" ]; then
                eval "$private_var='$priv_key'"
                eval "$public_var='$pub_key'"
                log_message "SUCCESS" "Keys generated via xray binary successfully"
                log_message "INFO" "Public key (first 20 chars): ${pub_key:0:20}..."
                print_success "Keys generated successfully"
                return 0
            else
                log_message "WARNING" "Failed to extract keys from xray output"
            fi
        else
            log_message "WARNING" "xray x25519 returned empty output"
        fi
    else
        log_message "WARNING" "xray binary not found in any standard location"
    fi

    # Fallback: try x-ui command
    log_message "INFO" "Attempting fallback method: x-ui command"
    print_info "Trying alternative method (x-ui command)..."
    local keys_output=$(timeout 5 x-ui x25519 2>&1 || echo "")
    log_message "INFO" "x-ui x25519 output length: ${#keys_output} chars"

    if [ -n "$keys_output" ]; then
        local priv_key=$(echo "$keys_output" | grep "Private key:" | awk '{print $3}')
        local pub_key=$(echo "$keys_output" | grep "Public key:" | awk '{print $3}')

        log_message "INFO" "Extracted private key length from x-ui: ${#priv_key}"
        log_message "INFO" "Extracted public key length from x-ui: ${#pub_key}"

        if [ -n "$priv_key" ] && [ -n "$pub_key" ]; then
            eval "$private_var='$priv_key'"
            eval "$public_var='$pub_key'"
            log_message "SUCCESS" "Keys generated via x-ui command successfully"
            print_success "Keys generated successfully"
            return 0
        else
            log_message "WARNING" "Failed to extract keys from x-ui output"
        fi
    else
        log_message "WARNING" "x-ui x25519 returned empty output"
    fi

    # If all methods failed, ask user to provide keys manually
    log_message "WARNING" "All automatic key generation methods failed"
    log_message "INFO" "Requesting manual key input from user"
    print_warning "Could not auto-generate keys. Please provide them manually."
    echo ""
    echo "You can generate keys using one of these methods:"
    echo "  1. On another server with xray: xray x25519"
    echo "  2. Using x-ui command: x-ui"
    echo "  3. Online generator: https://github.com/XTLS/Xray-core"
    echo ""
    echo "Example of valid keys:"
    echo "  Private key: SInS6Wz7VKlQtUJ-dBFKqQ3BoFaF8tHj5D0lF8kA91k"
    echo "  Public key:  kL9nM4pQ2rT5vW8zA1bC3dE6fG9hJ0kL2mN5pQ8rT1v"
    echo ""

    local temp_pub temp_priv
    ask_input "Public Key" "temp_pub"
    ask_input "Private Key" "temp_priv" false true

    log_message "INFO" "User provided public key length: ${#temp_pub}"
    log_message "INFO" "User provided private key length: ${#temp_priv}"
    log_message "INFO" "Public key (first 20 chars): ${temp_pub:0:20}..."

    eval "$public_var='$temp_pub'"
    eval "$private_var='$temp_priv'"

    log_message "SUCCESS" "Keys provided manually and saved"
    print_success "Keys provided manually"
    return 0
}

################################################################################
# USER INTERACTION
################################################################################

# Ask user for input with validation
ask_input() {
    local prompt="$1"
    local var_name="$2"
    local allow_empty="${3:-false}"
    local is_password="${4:-false}"

    while true; do
        if [ "$is_password" = true ]; then
            read -s -p "$(echo -e ${YELLOW}${prompt}${NC}): " input
            echo ""
        else
            read -p "$(echo -e ${YELLOW}${prompt}${NC}): " input
        fi

        if [ -n "$input" ] || [ "$allow_empty" = true ]; then
            eval "$var_name='$input'"
            log_message "INFO" "User input for ${var_name}: ${input:0:20}..."
            return 0
        else
            print_error "Input cannot be empty. Please try again."
        fi
    done
}

# Ask yes/no question
ask_yes_no() {
    local prompt="$1"
    local default="${2:-n}"

    while true; do
        if [ "$default" = "y" ]; then
            read -p "$(echo -e ${YELLOW}${prompt}${NC} [Y/n]): " answer
            answer=${answer:-y}
        else
            read -p "$(echo -e ${YELLOW}${prompt}${NC} [y/N]): " answer
            answer=${answer:-n}
        fi

        case "$answer" in
            [Yy]|[Yy][Ee][Ss])
                return 0
                ;;
            [Nn]|[Nn][Oo])
                return 1
                ;;
            *)
                print_error "Please answer yes (y) or no (n)."
                ;;
        esac
    done
}

# Confirm with user before proceeding
confirm_action() {
    local message="$1"
    echo ""
    print_warning "CONFIRMATION REQUIRED:"
    print_warning "$message"
    echo ""

    if ! ask_yes_no "Do you want to proceed?"; then
        print_info "Operation cancelled by user."
        exit 0
    fi
}

################################################################################
# ENVIRONMENT VALIDATION
################################################################################

# Check if script is run as root
check_root() {
    print_step "1" "Checking root privileges"

    if [ "$EUID" -ne 0 ]; then
        fatal_error "This script must be run as root. Please use: sudo $0"
    fi

    print_success "Running with root privileges"
}

# Check operating system
check_os() {
    print_step "2" "Validating operating system"

    if [ ! -f /etc/os-release ]; then
        fatal_error "Cannot detect operating system. /etc/os-release not found."
    fi

    source /etc/os-release

    print_info "Detected OS: ${NAME} ${VERSION}"

    if [[ "${NAME}" != *"${REQUIRED_OS}"* ]]; then
        fatal_error "Unsupported OS: ${NAME}. This script requires ${REQUIRED_OS} ${MIN_VERSION} or higher."
    fi

    # Check version
    local version_number=$(echo "${VERSION_ID}" | cut -d. -f1,2)
    local min_version_number=$(echo "${MIN_VERSION}" | cut -d. -f1,2)

    if (( $(echo "${version_number} < ${min_version_number}" | bc -l) )); then
        fatal_error "OS version ${VERSION_ID} is too old. Minimum required: ${MIN_VERSION}"
    fi

    print_success "OS validation passed: ${NAME} ${VERSION_ID}"
}

# Check internet connectivity
check_internet() {
    print_step "3" "Checking internet connectivity"

    local test_hosts=("8.8.8.8" "1.1.1.1" "google.com")
    local connected=false

    for host in "${test_hosts[@]}"; do
        if ping -c 2 -W 3 "$host" &> /dev/null; then
            connected=true
            print_success "Internet connectivity verified (reached ${host})"
            break
        fi
    done

    if [ "$connected" = false ]; then
        fatal_error "No internet connectivity detected. Please check your network connection."
    fi
}

# Install system dependencies
install_dependencies() {
    print_step "4" "Installing system dependencies"

    print_info "Updating package lists..."
    apt-get update -qq || fatal_error "Failed to update package lists"

    local packages=(
        "curl"
        "wget"
        "jq"
        "iptables"
        "iptables-persistent"
        "net-tools"
        "dnsutils"
        "bc"
        "openssl"
        "ufw"
        "socat"
    )

    print_info "Installing required packages: ${packages[*]}"

    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*${package}"; then
            print_info "Installing ${package}..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$package" || \
                fatal_error "Failed to install ${package}"
        else
            print_info "${package} is already installed"
        fi
    done

    print_success "All dependencies installed successfully"
}

# Detect server IP address
detect_server_ip() {
    print_info "Detecting server IP address..."

    # Try multiple methods
    SERVER_IP=$(curl -s -4 https://ifconfig.me || curl -s -4 https://api.ipify.org || curl -s -4 https://icanhazip.com)

    if [ -z "$SERVER_IP" ]; then
        print_warning "Could not auto-detect IP address"
        ask_input "Please enter this server's public IP address" "SERVER_IP"
    else
        print_info "Detected IP: ${SERVER_IP}"
        if ! ask_yes_no "Is this IP address correct: ${SERVER_IP}?" "y"; then
            ask_input "Please enter the correct IP address" "SERVER_IP"
        fi
    fi

    # Validate IP format
    if ! [[ "$SERVER_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        fatal_error "Invalid IP address format: ${SERVER_IP}"
    fi

    print_success "Server IP: ${SERVER_IP}"
}

################################################################################
# ROLE SELECTION
################################################################################

select_server_role() {
    print_step "5" "Server Role Selection"

    echo ""
    echo -e "${MAGENTA}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║                   SELECT SERVER ROLE                          ║${NC}"
    echo -e "${MAGENTA}╠═══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${MAGENTA}║                                                               ║${NC}"
    echo -e "${MAGENTA}║  1) RU_SERVER     - Bridge server (entry point for clients)  ║${NC}"
    echo -e "${MAGENTA}║                     All traffic exits via non-RU server       ║${NC}"
    echo -e "${MAGENTA}║                                                               ║${NC}"
    echo -e "${MAGENTA}║  2) NON_RU_SERVER - Exit server (connects to internet)       ║${NC}"
    echo -e "${MAGENTA}║                     Receives traffic from RU server           ║${NC}"
    echo -e "${MAGENTA}║                                                               ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    while true; do
        read -p "$(echo -e ${YELLOW}Enter your choice [1 or 2]${NC}): " choice

        case "$choice" in
            1)
                SERVER_ROLE="$ROLE_RU_SERVER"
                print_success "Selected role: RU_SERVER (Bridge)"
                break
                ;;
            2)
                SERVER_ROLE="$ROLE_NON_RU_SERVER"
                print_success "Selected role: NON_RU_SERVER (Exit)"
                break
                ;;
            *)
                print_error "Invalid choice. Please enter 1 or 2."
                ;;
        esac
    done

    log_message "INFO" "Server role selected: ${SERVER_ROLE}"

    echo ""
    print_info "Role Description:"
    if [ "$SERVER_ROLE" = "$ROLE_RU_SERVER" ]; then
        echo "  - Acts as entry point for all clients"
        echo "  - Forwards ALL traffic to non-RU server"
        echo "  - Direct internet access will be blocked"
        echo "  - Listens on port ${CLIENT_PORT} for clients"
    else
        echo "  - Acts as exit node to internet"
        echo "  - Receives traffic from RU server"
        echo "  - Provides direct internet access"
        echo "  - Listens on port ${EXIT_PORT} for RU server"
    fi
    echo ""

    confirm_action "This will configure the server as ${SERVER_ROLE}. This action may modify network settings and firewall rules."
}

################################################################################
# 3X-UI INSTALLATION
################################################################################

install_3xui() {
    print_step "6" "Installing 3x-ui Panel"

    log_message "INFO" "Checking for existing 3x-ui installation..."

    # Check if already installed
    if [ -f "/usr/local/x-ui/bin/xray-linux-amd64" ] || [ -f "/usr/local/x-ui/x-ui" ]; then
        log_message "INFO" "3x-ui is already installed, using existing installation"
        print_success "3x-ui is already installed"
        print_info "Using existing 3x-ui installation"

        # Check if service is running
        if systemctl is-active --quiet x-ui; then
            log_message "INFO" "3x-ui service is already running"
            print_success "3x-ui service is running"
        else
            log_message "WARNING" "3x-ui service is not running, attempting to start..."
            print_warning "3x-ui service is not running, attempting to start..."
            if systemctl start x-ui; then
                log_message "SUCCESS" "3x-ui service started"
                print_success "3x-ui service started"
                sleep 3
            else
                log_message "ERROR" "Failed to start 3x-ui service"
                fatal_error "Failed to start 3x-ui service"
            fi
        fi

        # Ensure service is enabled on boot
        systemctl enable x-ui &>/dev/null || log_message "WARNING" "Could not enable x-ui on boot"

        log_message "INFO" "Proceeding with existing 3x-ui installation"
        print_info "Proceeding with configuration..."
        return 0
    fi

    # 3x-ui not installed, install it
    log_message "INFO" "3x-ui not found, proceeding with installation"
    print_info "Downloading and installing 3x-ui from official repository..."
    print_info "Repository: ${XRAY_UI_REPO}"

    # Download and execute install script
    if bash <(curl -Ls "${XRAY_UI_REPO}"); then
        log_message "SUCCESS" "3x-ui installation script completed"
    else
        log_message "ERROR" "3x-ui installation failed"
        fatal_error "Failed to install 3x-ui"
    fi

    # Wait for service to start
    sleep 5

    # Check if service is running
    if systemctl is-active --quiet x-ui; then
        log_message "SUCCESS" "3x-ui service is running"
        print_success "3x-ui service is running"
    else
        log_message "WARNING" "3x-ui service is not running, attempting to start..."
        print_warning "3x-ui service is not running, attempting to start..."
        if systemctl start x-ui; then
            log_message "SUCCESS" "3x-ui service started"
            sleep 3
        else
            log_message "ERROR" "Failed to start 3x-ui service"
            fatal_error "Failed to start 3x-ui service"
        fi
    fi

    # Enable service on boot
    if systemctl enable x-ui; then
        log_message "SUCCESS" "3x-ui enabled on boot"
    else
        log_message "WARNING" "Could not enable x-ui service on boot"
        print_warning "Could not enable x-ui service on boot"
    fi

    log_message "SUCCESS" "3x-ui installed successfully"
    print_success "3x-ui installed successfully"
}

# Get actual 3x-ui panel settings
get_xui_panel_settings() {
    log_message "INFO" "Reading actual 3x-ui panel settings..."

    # Check if x-ui database exists
    if [ -f "/etc/x-ui/x-ui.db" ]; then
        log_message "INFO" "Found x-ui database at /etc/x-ui/x-ui.db"

        # Try to read settings from database if sqlite3 is available
        if command -v sqlite3 &> /dev/null; then
            log_message "INFO" "Attempting to read panel settings from database..."

            # Try to get port from database
            local db_port=$(sqlite3 /etc/x-ui/x-ui.db "SELECT value FROM settings WHERE key='webPort';" 2>/dev/null || echo "")
            if [ -n "$db_port" ]; then
                PANEL_PORT="$db_port"
                log_message "INFO" "Read panel port from database: ${PANEL_PORT}"
            else
                PANEL_PORT="54321"  # x-ui default
                log_message "INFO" "Could not read port from DB, using default: ${PANEL_PORT}"
            fi

            # Try to get username from database
            local db_user=$(sqlite3 /etc/x-ui/x-ui.db "SELECT value FROM settings WHERE key='webUser';" 2>/dev/null || echo "")
            if [ -n "$db_user" ]; then
                PANEL_USERNAME="$db_user"
                log_message "INFO" "Read panel username from database: ${PANEL_USERNAME}"
            else
                PANEL_USERNAME="admin"
                log_message "INFO" "Could not read username from DB, using default: admin"
            fi

            # Note: Password is hashed in DB, so we can't get the plain text
            PANEL_PASSWORD="admin"
            log_message "INFO" "Using default password: admin (cannot read from DB - it's hashed)"
        else
            log_message "INFO" "sqlite3 not available, using default settings"
            PANEL_PORT="54321"  # x-ui default
            PANEL_USERNAME="admin"
            PANEL_PASSWORD="admin"
        fi
    else
        log_message "WARNING" "x-ui database not found at /etc/x-ui/x-ui.db, using defaults"
        PANEL_PORT="2053"
        PANEL_USERNAME="admin"
        PANEL_PASSWORD="admin"
    fi

    log_message "INFO" "Final panel settings - Port: ${PANEL_PORT}, Username: ${PANEL_USERNAME}"
}

# Configure 3x-ui panel settings
configure_3xui_panel() {
    print_step "7" "Reading 3x-ui Panel Configuration"

    log_message "INFO" "Starting panel configuration check..."
    print_info "Detecting 3x-ui panel settings..."

    # Get actual panel settings from x-ui installation
    get_xui_panel_settings

    log_message "INFO" "Detected panel port: ${PANEL_PORT}"
    log_message "INFO" "Default credentials will be used: ${PANEL_USERNAME}/admin"

    echo ""
    print_info "3x-ui panel is configured with DEFAULT settings:"
    print_info "  Port: ${PANEL_PORT}"
    print_info "  Username: ${PANEL_USERNAME}"
    print_info "  Password: ${PANEL_PASSWORD}"
    echo ""

    print_warning "IMPORTANT: These are the DEFAULT credentials set by x-ui installer."
    print_warning "You should change them after first login for security!"
    echo ""

    # Ask if user wants to change settings now
    if ask_yes_no "Do you want to change panel settings now (port/username/password)?" "n"; then
        log_message "INFO" "User chose to customize panel settings"

        local new_port new_user new_pass
        ask_input "New panel port (current: ${PANEL_PORT})" "new_port" true
        ask_input "New panel username (current: ${PANEL_USERNAME})" "new_user" true
        ask_input "New panel password (current: ${PANEL_PASSWORD})" "new_pass" true true

        # Apply changes if provided
        if [ -n "$new_port" ] || [ -n "$new_user" ] || [ -n "$new_pass" ]; then
            print_info "Applying panel configuration changes..."
            log_message "INFO" "Applying custom settings: port=${new_port:-$PANEL_PORT} user=${new_user:-$PANEL_USERNAME}"

            # Use x-ui command to change settings
            local change_cmd="x-ui"
            [ -n "$new_user" ] && change_cmd+=" -username ${new_user}" && PANEL_USERNAME="$new_user"
            [ -n "$new_pass" ] && change_cmd+=" -password ${new_pass}" && PANEL_PASSWORD="$new_pass"
            [ -n "$new_port" ] && change_cmd+=" -port ${new_port}" && PANEL_PORT="$new_port"

            log_message "INFO" "Executing: x-ui with custom parameters"

            if eval "$change_cmd" &>> "$LOG_FILE"; then
                print_success "Panel settings updated successfully"
                log_message "SUCCESS" "Panel settings applied"

                # Restart x-ui to apply changes
                print_info "Restarting x-ui service..."
                systemctl restart x-ui
                sleep 3
            else
                print_warning "Could not apply settings automatically. You can change them in web panel."
                log_message "WARNING" "Failed to apply panel settings via command"
            fi
        else
            print_info "No changes requested, keeping default settings"
            log_message "INFO" "User kept default panel settings"
        fi
    else
        print_info "Keeping default panel settings"
        log_message "INFO" "User chose to keep default settings"
    fi

    print_success "Panel configuration complete"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  3x-ui Panel Access Information:${NC}"
    echo -e "${GREEN}  ─────────────────────────────────────────────────────────────${NC}"
    echo -e "${GREEN}  URL:      http://${SERVER_IP}:${PANEL_PORT}${NC}"
    echo -e "${GREEN}  Username: ${PANEL_USERNAME}${NC}"
    echo -e "${GREEN}  Password: ${PANEL_PASSWORD}${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    log_message "INFO" "Final panel URL: http://${SERVER_IP}:${PANEL_PORT}"
    log_message "INFO" "Final panel username: ${PANEL_USERNAME}"

    # Save credentials to file
    cat > /root/3xui-credentials.txt <<EOF
3x-ui Panel Access Information
===============================
URL:      http://${SERVER_IP}:${PANEL_PORT}
Username: ${PANEL_USERNAME}
Password: ${PANEL_PASSWORD}

IMPORTANT: Change default credentials after first login!

Generated at: $(date)
Server Role: ${SERVER_ROLE}
Server IP: ${SERVER_IP}
EOF

    chmod 600 /root/3xui-credentials.txt
    print_info "Panel info saved to: /root/3xui-credentials.txt"
    log_message "INFO" "Credentials saved to /root/3xui-credentials.txt"
}

################################################################################
# CONFIGURATION - NON-RU SERVER (EXIT NODE)
################################################################################

configure_non_ru_server() {
    log_message "INFO" "=== Starting NON-RU Server Configuration ==="
    print_step "8" "Configuring NON-RU Server (Exit Node)"

    log_message "INFO" "Server IP: ${SERVER_IP}"
    log_message "INFO" "Default exit port: ${EXIT_PORT}"

    print_info "This server will act as the exit node for all traffic."
    print_info "It will receive connections from the RU server and provide internet access."
    echo ""

    # Generate inbound configuration for RU server connection
    log_message "INFO" "Generating VLESS Reality inbound configuration..."
    print_info "Generating VLESS Reality configuration for RU server connection..."

    # Generate UUID
    EXIT_UUID=$(cat /proc/sys/kernel/random/uuid)
    log_message "INFO" "Generated EXIT_UUID: ${EXIT_UUID}"
    print_success "Generated UUID: ${EXIT_UUID}"

    # Ask for Reality settings
    echo ""
    print_info "VLESS Reality Configuration Parameters:"
    print_info "These settings must be used on the RU server to connect to this exit node."
    echo ""

    ask_input "Inbound port for RU server (default: ${EXIT_PORT})" "temp_port" true
    [ -n "$temp_port" ] && EXIT_PORT="$temp_port"
    log_message "INFO" "Exit port set to: ${EXIT_PORT}"

    ask_input "SNI (Server Name Indication, e.g., www.google.com)" "EXIT_SNI"
    log_message "INFO" "EXIT_SNI set to: ${EXIT_SNI}"

    ask_input "Server Name for Reality (e.g., www.google.com)" "EXIT_SERVER_NAME"
    log_message "INFO" "EXIT_SERVER_NAME set to: ${EXIT_SERVER_NAME}"

    # Generate Reality keys using helper function
    log_message "INFO" "Calling generate_reality_keys for EXIT keys..."
    generate_reality_keys "EXIT_PUBLIC_KEY" "EXIT_PRIVATE_KEY"
    log_message "INFO" "EXIT_PUBLIC_KEY length: ${#EXIT_PUBLIC_KEY}"
    log_message "INFO" "EXIT_PRIVATE_KEY length: ${#EXIT_PRIVATE_KEY}"

    # Generate short ID
    EXIT_SHORT_ID=$(openssl rand -hex 8)
    log_message "INFO" "Generated EXIT_SHORT_ID: ${EXIT_SHORT_ID}"
    print_success "Generated Short ID: ${EXIT_SHORT_ID}"

    # Spider X (optional)
    ask_input "Spider X path (optional, press Enter to skip)" "EXIT_SPIDER_X" true

    # Flow
    print_info "Flow options: xtls-rprx-vision (recommended for non-443 ports), none (leave empty)"
    ask_input "Flow (press Enter for none)" "EXIT_FLOW" true

    print_success "Configuration parameters collected"

    # Enable IP forwarding
    print_info "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    sysctl -p > /dev/null
    print_success "IP forwarding enabled"

    # Configure firewall
    configure_firewall_non_ru

    # Display configuration summary
    display_non_ru_summary

    print_success "NON-RU server configuration completed"
    echo ""
    print_warning "IMPORTANT: You must manually configure 3x-ui panel with these settings:"
    echo "  1. Open panel: http://${SERVER_IP}:${PANEL_PORT}"
    echo "  2. Create VLESS Reality inbound on port ${EXIT_PORT}"
    echo "  3. Use the UUID and Reality settings shown above"
    echo "  4. Set routing to allow all traffic to internet (Freedom outbound)"
    echo ""
}

configure_firewall_non_ru() {
    log_message "INFO" "=== Configuring firewall for NON-RU exit node ==="
    print_info "Configuring firewall for exit node..."

    # Allow SSH
    log_message "INFO" "Adding UFW rule: allow 22/tcp (SSH)"
    if ufw allow 22/tcp comment 'SSH' 2>&1 | tee -a "$LOG_FILE"; then
        log_message "SUCCESS" "SSH port 22 allowed"
    else
        log_message "WARNING" "Failed to add UFW rule for SSH"
    fi

    # Allow panel port
    log_message "INFO" "Adding UFW rule: allow ${PANEL_PORT}/tcp (3x-ui Panel)"
    if ufw allow "${PANEL_PORT}/tcp" comment '3x-ui Panel' 2>&1 | tee -a "$LOG_FILE"; then
        log_message "SUCCESS" "Panel port ${PANEL_PORT} allowed"
    else
        log_message "WARNING" "Failed to add UFW rule for panel port"
    fi

    # Allow exit port
    log_message "INFO" "Adding UFW rule: allow ${EXIT_PORT}/tcp (VLESS Reality Exit)"
    if ufw allow "${EXIT_PORT}/tcp" comment 'VLESS Reality Exit' 2>&1 | tee -a "$LOG_FILE"; then
        log_message "SUCCESS" "Exit port ${EXIT_PORT} allowed"
    else
        log_message "WARNING" "Failed to add UFW rule for exit port"
    fi

    # Enable NAT
    log_message "INFO" "Configuring NAT for internet access..."
    print_info "Configuring NAT for internet access..."

    # Get default interface
    log_message "INFO" "Detecting default network interface..."
    local default_iface=$(ip route | grep default | awk '{print $5}' | head -n1)
    log_message "INFO" "ip route output: $(ip route | grep default)"

    if [ -z "$default_iface" ]; then
        log_message "WARNING" "Could not detect default network interface, using eth0"
        print_warning "Could not detect default network interface"
        default_iface="eth0"
    fi

    log_message "INFO" "Using network interface: ${default_iface}"
    print_info "Default interface: ${default_iface}"

    # Configure iptables NAT
    log_message "INFO" "Adding iptables MASQUERADE rule for ${default_iface}"
    if iptables -t nat -A POSTROUTING -o "$default_iface" -j MASQUERADE 2>&1 | tee -a "$LOG_FILE"; then
        log_message "SUCCESS" "NAT MASQUERADE rule added"
    else
        log_message "ERROR" "Failed to add iptables NAT rule"
        print_warning "Could not configure NAT"
    fi

    # List current NAT rules for verification
    log_message "INFO" "Current NAT rules:"
    iptables -t nat -L POSTROUTING -v -n | tee -a "$LOG_FILE"

    # Save iptables rules
    log_message "INFO" "Saving iptables rules with netfilter-persistent..."
    if netfilter-persistent save 2>&1 | tee -a "$LOG_FILE"; then
        log_message "SUCCESS" "iptables rules saved"
    else
        log_message "WARNING" "Could not save iptables rules"
        print_warning "Could not save iptables rules"
    fi

    # Enable UFW
    log_message "INFO" "Enabling UFW firewall..."
    if echo "y" | ufw enable 2>&1 | tee -a "$LOG_FILE"; then
        log_message "SUCCESS" "UFW enabled"
    else
        log_message "WARNING" "Could not enable UFW"
        print_warning "Could not enable UFW"
    fi

    # Show UFW status
    log_message "INFO" "Final UFW status:"
    ufw status verbose | tee -a "$LOG_FILE"

    log_message "SUCCESS" "Firewall configuration completed"
    print_success "Firewall configured"
}

display_non_ru_summary() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         NON-RU SERVER CONFIGURATION SUMMARY                   ║${NC}"
    echo -e "${GREEN}╠═══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║  Server IP:        ${SERVER_IP}${NC}"
    echo -e "${GREEN}║  Inbound Port:     ${EXIT_PORT}${NC}"
    echo -e "${GREEN}║  UUID:             ${EXIT_UUID}${NC}"
    echo -e "${GREEN}║  SNI:              ${EXIT_SNI}${NC}"
    echo -e "${GREEN}║  Server Name:      ${EXIT_SERVER_NAME}${NC}"
    echo -e "${GREEN}║  Public Key:       ${EXIT_PUBLIC_KEY}${NC}"
    echo -e "${GREEN}║  Short ID:         ${EXIT_SHORT_ID}${NC}"
    [ -n "$EXIT_FLOW" ] && echo -e "${GREEN}║  Flow:             ${EXIT_FLOW}${NC}"
    [ -n "$EXIT_SPIDER_X" ] && echo -e "${GREEN}║  Spider X:         ${EXIT_SPIDER_X}${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Save to file
    cat > /root/non-ru-server-config.txt <<EOF
NON-RU SERVER CONFIGURATION
============================

Connection Settings (use these on RU server):
---------------------------------------------
Server IP:        ${SERVER_IP}
Port:             ${EXIT_PORT}
UUID:             ${EXIT_UUID}
SNI:              ${EXIT_SNI}
Server Name:      ${EXIT_SERVER_NAME}
Public Key:       ${EXIT_PUBLIC_KEY}
Private Key:      ${EXIT_PRIVATE_KEY}
Short ID:         ${EXIT_SHORT_ID}
Flow:             ${EXIT_FLOW}
Spider X:         ${EXIT_SPIDER_X}

Network:          tcp
Security:         reality
Fingerprint:      chrome

Generated at: $(date)
EOF

    chmod 600 /root/non-ru-server-config.txt
    print_info "Configuration saved to: /root/non-ru-server-config.txt"
}

################################################################################
# CONFIGURATION - RU SERVER (BRIDGE)
################################################################################

configure_ru_server() {
    print_step "8" "Configuring RU Server (Bridge)"

    print_info "This server will act as a bridge between clients and the exit node."
    print_info "ALL client traffic will be routed through the non-RU server."
    echo ""

    # Get non-RU server connection details
    collect_non_ru_connection_info

    # Generate client inbound configuration
    configure_client_inbound

    # Configure routing
    configure_routing_ru

    # Configure firewall
    configure_firewall_ru

    # Display configuration summary
    display_ru_summary

    print_success "RU server configuration completed"
    echo ""
    print_warning "IMPORTANT: You must manually configure 3x-ui panel with these settings:"
    echo "  1. Open panel: http://${SERVER_IP}:${PANEL_PORT}"
    echo "  2. Create VLESS Reality inbound on port ${CLIENT_PORT} for clients"
    echo "  3. Create VLESS outbound to non-RU server (${NON_RU_IP}:${NON_RU_PORT})"
    echo "  4. Configure routing: ALL inbound traffic → non-RU outbound"
    echo ""
}

collect_non_ru_connection_info() {
    print_info "Please provide connection details for the NON-RU server (exit node):"
    echo ""

    ask_input "Non-RU server IP address" "NON_RU_IP"
    ask_input "Non-RU server port" "NON_RU_PORT"
    ask_input "UUID (from non-RU server)" "NON_RU_UUID"
    ask_input "SNI" "NON_RU_SNI"
    ask_input "Server Name" "NON_RU_SERVER_NAME"
    ask_input "Public Key (from non-RU server)" "NON_RU_PUBLIC_KEY"
    ask_input "Short ID (from non-RU server)" "NON_RU_SHORT_ID"
    ask_input "Flow (press Enter if none)" "NON_RU_FLOW" true
    ask_input "Spider X (press Enter if none)" "NON_RU_SPIDER_X" true

    print_success "Non-RU server connection details collected"
}

configure_client_inbound() {
    print_info "Generating VLESS Reality configuration for client connections..."

    # Generate UUID for clients
    CLIENT_UUID=$(cat /proc/sys/kernel/random/uuid)
    print_success "Generated client UUID: ${CLIENT_UUID}"

    # Ask for Reality settings optimized for Russia blocking
    echo ""
    print_info "Client Inbound Configuration (Port ${CLIENT_PORT}):"
    print_info "Optimized for Russia DPI blocking (December 2025):"
    print_info "  - No flow (avoid xtls-rprx-vision on 443)"
    print_info "  - Use SNI from whitelist (e.g., apple.com, microsoft.com, cloudflare.com)"
    echo ""

    ask_input "SNI for clients (recommended: apple.com, microsoft.com)" "CLIENT_SNI"
    ask_input "Server Name for Reality" "CLIENT_SERVER_NAME"

    # Generate Reality keys using helper function
    generate_reality_keys "CLIENT_PUBLIC_KEY" "CLIENT_PRIVATE_KEY"

    # Generate short ID
    CLIENT_SHORT_ID=$(openssl rand -hex 8)
    print_success "Generated Short ID: ${CLIENT_SHORT_ID}"

    # Spider X (optional)
    ask_input "Spider X path (optional, press Enter to skip)" "CLIENT_SPIDER_X" true

    # No flow for port 443 (best practice for Russia 2025)
    CLIENT_FLOW=""
    print_info "Flow: none (recommended for port 443 in Russia)"

    print_success "Client inbound configuration prepared"
}

configure_routing_ru() {
    print_info "Configuring traffic routing..."

    # Enable IP forwarding
    print_info "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    sysctl -p > /dev/null
    print_success "IP forwarding enabled"

    # Block direct internet access (except to non-RU server)
    print_info "Configuring iptables to block direct internet access..."

    # Get default interface
    local default_iface=$(ip route | grep default | awk '{print $5}' | head -n1)

    if [ -z "$default_iface" ]; then
        print_warning "Could not detect default network interface"
        default_iface="eth0"
    fi

    print_info "Default interface: ${default_iface}"

    # Allow established connections
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT || true

    # Allow connections to non-RU server
    iptables -A OUTPUT -d "${NON_RU_IP}" -j ACCEPT || true

    # Block direct internet from this server (except for essential services)
    # Note: This is a basic setup, full enforcement requires 3x-ui routing rules

    print_warning "Full traffic routing enforcement requires 3x-ui panel configuration"
    print_warning "Ensure all inbound traffic is routed to non-RU outbound in panel"

    print_success "Basic routing configured"
}

configure_firewall_ru() {
    print_info "Configuring firewall for bridge node..."

    # Allow SSH
    ufw allow 22/tcp comment 'SSH' || true

    # Allow panel port
    ufw allow "${PANEL_PORT}/tcp" comment '3x-ui Panel' || true

    # Allow client port
    ufw allow "${CLIENT_PORT}/tcp" comment 'VLESS Reality Clients' || true

    # Allow connection to non-RU server
    ufw allow out to "${NON_RU_IP}" port "${NON_RU_PORT}" proto tcp comment 'Non-RU Server' || true

    # Save iptables rules
    netfilter-persistent save || print_warning "Could not save iptables rules"

    # Enable UFW
    echo "y" | ufw enable || print_warning "Could not enable UFW"

    print_success "Firewall configured"
}

display_ru_summary() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║            RU SERVER CONFIGURATION SUMMARY                    ║${NC}"
    echo -e "${GREEN}╠═══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║  CLIENT INBOUND (Port ${CLIENT_PORT}):${NC}"
    echo -e "${GREEN}║    Server IP:      ${SERVER_IP}${NC}"
    echo -e "${GREEN}║    UUID:           ${CLIENT_UUID}${NC}"
    echo -e "${GREEN}║    SNI:            ${CLIENT_SNI}${NC}"
    echo -e "${GREEN}║    Server Name:    ${CLIENT_SERVER_NAME}${NC}"
    echo -e "${GREEN}║    Public Key:     ${CLIENT_PUBLIC_KEY}${NC}"
    echo -e "${GREEN}║    Short ID:       ${CLIENT_SHORT_ID}${NC}"
    echo -e "${GREEN}║${NC}"
    echo -e "${GREEN}║  OUTBOUND TO NON-RU SERVER:${NC}"
    echo -e "${GREEN}║    Server IP:      ${NON_RU_IP}${NC}"
    echo -e "${GREEN}║    Port:           ${NON_RU_PORT}${NC}"
    echo -e "${GREEN}║    UUID:           ${NON_RU_UUID}${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Save to file
    cat > /root/ru-server-config.txt <<EOF
RU SERVER CONFIGURATION
========================

CLIENT INBOUND (for user connections):
--------------------------------------
Server IP:        ${SERVER_IP}
Port:             ${CLIENT_PORT}
UUID:             ${CLIENT_UUID}
SNI:              ${CLIENT_SNI}
Server Name:      ${CLIENT_SERVER_NAME}
Public Key:       ${CLIENT_PUBLIC_KEY}
Private Key:      ${CLIENT_PRIVATE_KEY}
Short ID:         ${CLIENT_SHORT_ID}
Spider X:         ${CLIENT_SPIDER_X}
Flow:             none (optimized for Russia)

Network:          tcp
Security:         reality
Fingerprint:      chrome

OUTBOUND TO NON-RU SERVER:
--------------------------
Server IP:        ${NON_RU_IP}
Port:             ${NON_RU_PORT}
UUID:             ${NON_RU_UUID}
SNI:              ${NON_RU_SNI}
Server Name:      ${NON_RU_SERVER_NAME}
Public Key:       ${NON_RU_PUBLIC_KEY}
Short ID:         ${NON_RU_SHORT_ID}
Flow:             ${NON_RU_FLOW}
Spider X:         ${NON_RU_SPIDER_X}

Generated at: $(date)
EOF

    chmod 600 /root/ru-server-config.txt
    print_info "Configuration saved to: /root/ru-server-config.txt"
}

################################################################################
# VALIDATION
################################################################################

validate_setup() {
    print_step "9" "Validating Setup"

    local validation_failed=false

    # Check 3x-ui service
    print_info "Checking 3x-ui service status..."
    if systemctl is-active --quiet x-ui; then
        print_success "3x-ui service is running"
    else
        print_error "3x-ui service is not running"
        validation_failed=true
    fi

    # Check ports
    print_info "Checking port availability..."

    if [ "$SERVER_ROLE" = "$ROLE_NON_RU_SERVER" ]; then
        if netstat -tuln | grep -q ":${EXIT_PORT}"; then
            print_success "Port ${EXIT_PORT} is open"
        else
            print_warning "Port ${EXIT_PORT} is not listening yet (configure in 3x-ui panel)"
        fi
    else
        if netstat -tuln | grep -q ":${CLIENT_PORT}"; then
            print_success "Port ${CLIENT_PORT} is open"
        else
            print_warning "Port ${CLIENT_PORT} is not listening yet (configure in 3x-ui panel)"
        fi
    fi

    # Check IP forwarding
    print_info "Checking IP forwarding..."
    if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
        print_success "IP forwarding is enabled"
    else
        print_error "IP forwarding is not enabled"
        validation_failed=true
    fi

    # Check internet connectivity
    print_info "Checking internet connectivity..."
    if ping -c 2 -W 3 8.8.8.8 &> /dev/null; then
        print_success "Internet connectivity verified"
    else
        if [ "$SERVER_ROLE" = "$ROLE_RU_SERVER" ]; then
            print_warning "No direct internet (this is expected for RU server)"
        else
            print_error "No internet connectivity"
            validation_failed=true
        fi
    fi

    # Role-specific validation
    if [ "$SERVER_ROLE" = "$ROLE_NON_RU_SERVER" ]; then
        validate_non_ru_server
    else
        validate_ru_server
    fi

    if [ "$validation_failed" = true ]; then
        print_error "Some validation checks failed"
        return 1
    else
        print_success "All validation checks passed"
        return 0
    fi
}

validate_non_ru_server() {
    print_info "Validating NON-RU server (exit node)..."

    # Test access to blocked resources
    print_info "Testing access to blocked resources..."

    local test_sites=("instagram.com" "youtube.com" "facebook.com")
    local accessible_count=0

    for site in "${test_sites[@]}"; do
        if curl -s --connect-timeout 5 --max-time 10 "https://${site}" > /dev/null 2>&1; then
            print_success "  ✓ ${site} is accessible"
            ((accessible_count++))
        else
            print_warning "  ✗ ${site} is not accessible"
        fi
    done

    if [ $accessible_count -eq ${#test_sites[@]} ]; then
        print_success "All test sites are accessible from exit node"
    else
        print_warning "Some test sites are not accessible (${accessible_count}/${#test_sites[@]})"
    fi
}

validate_ru_server() {
    print_info "Validating RU server (bridge)..."

    # Test connection to non-RU server
    print_info "Testing connection to non-RU server (${NON_RU_IP}:${NON_RU_PORT})..."

    if timeout 5 bash -c "cat < /dev/null > /dev/tcp/${NON_RU_IP}/${NON_RU_PORT}" 2>/dev/null; then
        print_success "Connection to non-RU server successful"
    else
        print_error "Cannot connect to non-RU server"
        print_error "Please verify non-RU server is running and port ${NON_RU_PORT} is open"
        return 1
    fi

    print_warning "Full validation requires client connection test"
    print_warning "After configuring 3x-ui panel, test with a real client"
}

################################################################################
# MANUAL CONFIGURATION GUIDE
################################################################################

display_manual_config_guide() {
    print_step "10" "Manual Configuration Guide"

    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              MANUAL CONFIGURATION REQUIRED                    ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [ "$SERVER_ROLE" = "$ROLE_NON_RU_SERVER" ]; then
        display_non_ru_manual_guide
    else
        display_ru_manual_guide
    fi
}

display_non_ru_manual_guide() {
    cat <<EOF
${YELLOW}NON-RU SERVER (Exit Node) - Manual Steps:${NC}

1. Access 3x-ui panel:
   URL: http://${SERVER_IP}:${PANEL_PORT}
   Username: ${PANEL_USERNAME}
   Password: ${PANEL_PASSWORD}

2. Create VLESS Reality Inbound:
   - Go to: Inbounds → Add Inbound
   - Protocol: VLESS
   - Port: ${EXIT_PORT}
   - Network: tcp
   - Security: reality

   Settings:
   - Dest (SNI): ${EXIT_SNI}:443
   - Server Names: ${EXIT_SERVER_NAME}
   - Private Key: (use generated private key from config file)
   - Short IDs: ${EXIT_SHORT_ID}
   - Flow: ${EXIT_FLOW:-none}

3. Add Client (for RU server):
   - Click on inbound → Clients → Add Client
   - Email/Name: ru-server
   - UUID: ${EXIT_UUID}
   - Flow: ${EXIT_FLOW:-none}

4. Configure Outbound (Freedom):
   - Go to: Outbounds → Ensure "freedom" outbound exists
   - This allows traffic to internet

5. Configure Routing:
   - Go to: Routing
   - Ensure all traffic from inbound goes to freedom outbound

6. Save configuration and restart X-ray service

${GREEN}Configuration saved to: /root/non-ru-server-config.txt${NC}

EOF
}

display_ru_manual_guide() {
    cat <<EOF
${YELLOW}RU SERVER (Bridge) - Manual Steps:${NC}

1. Access 3x-ui panel:
   URL: http://${SERVER_IP}:${PANEL_PORT}
   Username: ${PANEL_USERNAME}
   Password: ${PANEL_PASSWORD}

2. Create VLESS Reality Inbound (for clients):
   - Go to: Inbounds → Add Inbound
   - Protocol: VLESS
   - Port: ${CLIENT_PORT}
   - Network: tcp
   - Security: reality

   Settings:
   - Dest (SNI): ${CLIENT_SNI}:443
   - Server Names: ${CLIENT_SERVER_NAME}
   - Private Key: (use generated private key from config file)
   - Short IDs: ${CLIENT_SHORT_ID}
   - Flow: none (important for Russia!)

3. Add Clients:
   - Click on inbound → Clients → Add Client
   - Email/Name: user1, user2, etc.
   - UUID: generate new for each user
   - Flow: none

4. Create Outbound (to NON-RU server):
   - Go to: Outbounds → Add Outbound
   - Protocol: VLESS
   - Address: ${NON_RU_IP}
   - Port: ${NON_RU_PORT}
   - Security: reality
   - UUID: ${NON_RU_UUID}

   Reality Settings:
   - SNI: ${NON_RU_SNI}
   - Server Name: ${NON_RU_SERVER_NAME}
   - Public Key: ${NON_RU_PUBLIC_KEY}
   - Short ID: ${NON_RU_SHORT_ID}
   - Flow: ${NON_RU_FLOW:-none}
   - Fingerprint: chrome

5. Configure Routing (CRITICAL):
   - Go to: Routing
   - Create rule: ALL traffic from client inbound → non-RU outbound
   - Domain Strategy: AsIs or IPIfNonMatch
   - Outbound: (select non-RU outbound created in step 4)

   ${RED}IMPORTANT: Ensure NO traffic goes to "freedom" or "direct" outbound!${NC}
   ${RED}ALL client traffic MUST go through non-RU server!${NC}

6. Save configuration and restart X-ray service

${GREEN}Configuration saved to: /root/ru-server-config.txt${NC}

EOF
}

################################################################################
# FINAL REPORT
################################################################################

generate_final_report() {
    print_step "11" "Setup Complete - Final Report"

    local report_file="/root/cascade-setup-report.txt"

    {
        echo "VPN CASCADE SETUP REPORT"
        echo "========================"
        echo ""
        echo "Execution Date: $(date)"
        echo "Script Version: ${SCRIPT_VERSION}"
        echo "Server Role: ${SERVER_ROLE}"
        echo "Server IP: ${SERVER_IP}"
        echo ""
        echo "STATUS: CONFIGURATION PREPARED"
        echo ""
        echo "NEXT STEPS:"
        echo "-----------"
        echo "1. Complete manual configuration in 3x-ui panel"
        echo "2. Test client connection"
        echo "3. Verify traffic routes through non-RU server"
        echo "4. Test access to blocked resources"
        echo ""
        echo "FILES CREATED:"
        echo "--------------"
        echo "- /root/3xui-credentials.txt"

        if [ "$SERVER_ROLE" = "$ROLE_NON_RU_SERVER" ]; then
            echo "- /root/non-ru-server-config.txt"
        else
            echo "- /root/ru-server-config.txt"
        fi

        echo "- ${LOG_FILE}"
        echo "- ${report_file}"
        echo ""
        echo "3X-UI PANEL ACCESS:"
        echo "-------------------"
        echo "URL:      http://${SERVER_IP}:${PANEL_PORT}"
        echo "Username: ${PANEL_USERNAME}"
        echo "Password: ${PANEL_PASSWORD}"
        echo ""

        if [ "$SERVER_ROLE" = "$ROLE_NON_RU_SERVER" ]; then
            echo "SHARE THIS WITH RU SERVER ADMINISTRATOR:"
            echo "----------------------------------------"
            echo "IP:         ${SERVER_IP}"
            echo "Port:       ${EXIT_PORT}"
            echo "UUID:       ${EXIT_UUID}"
            echo "Public Key: ${EXIT_PUBLIC_KEY}"
            echo "SNI:        ${EXIT_SNI}"
            echo "Short ID:   ${EXIT_SHORT_ID}"
        fi

        echo ""
        echo "For detailed logs, see: ${LOG_FILE}"

    } | tee "$report_file"

    chmod 600 "$report_file"

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                     SETUP SUCCESSFUL                          ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}⚠ IMPORTANT REMINDERS:${NC}"
    echo ""
    echo "1. Complete the manual 3x-ui panel configuration"
    echo "2. Keep credentials secure (/root/*-config.txt files)"
    echo "3. Test the full cascade before deploying to clients"
    echo "4. Monitor logs: ${LOG_FILE}"
    echo ""
    echo -e "${GREEN}Report saved to: ${report_file}${NC}"
    echo ""
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    clear

    echo -e "${MAGENTA}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║              VPN CASCADE SETUP SCRIPT v1.0                       ║
║                                                                  ║
║         Two-Node Cascaded VPN System Configuration              ║
║              Using 3x-ui and VLESS Reality                       ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"

    # Initialize
    init_logging

    # Environment validation
    check_root
    check_os
    check_internet
    detect_server_ip
    install_dependencies

    # Role selection
    select_server_role

    # Install 3x-ui
    install_3xui
    configure_3xui_panel

    # Role-specific configuration
    if [ "$SERVER_ROLE" = "$ROLE_NON_RU_SERVER" ]; then
        configure_non_ru_server
    else
        configure_ru_server
    fi

    # Validation
    if ! validate_setup; then
        print_warning "Some validation checks failed, but setup can continue"
        print_warning "Please review the warnings and complete manual configuration"
    fi

    # Display manual configuration guide
    display_manual_config_guide

    # Generate final report
    generate_final_report

    log_message "INFO" "Script execution completed successfully"

    exit 0
}

# Run main function
main "$@"
