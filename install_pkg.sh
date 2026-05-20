#!/bin/bash
# =============================================================================
# install_pkg.sh — Instalação de dependências para ambiente OpenRAN/srsRAN
# =============================================================================

set -euo pipefail  # Aborta em erro, trata variáveis não definidas, propaga falhas em pipes

# -----------------------------------------------------------------------------
# Cores e utilitários de log
# -----------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; RESET='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${RESET}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
log_warn()    { echo -e "${YELLOW}[AVISO]${RESET} $*"; }
log_error()   { echo -e "${RED}[ERRO]${RESET}  $*" >&2; }
log_section() { echo -e "\n${CYAN}══════════════════════════════════════${RESET}"; \
                echo -e "${CYAN}  $*${RESET}"; \
                echo -e "${CYAN}══════════════════════════════════════${RESET}"; }

# -----------------------------------------------------------------------------
# Verificação de pré-requisitos
# -----------------------------------------------------------------------------
check_root() {
    if [[ "$EUID" -eq 0 ]]; then
        log_error "Não execute este script como root. Use um usuário comum com sudo."
        exit 1
    fi
    # Valida que sudo está disponível e que o usuário tem permissão
    if ! sudo -v; then
        log_error "Usuário sem permissão sudo. Abortando."
        exit 1
    fi
}

check_ubuntu() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Não foi possível detectar o sistema operacional."
        exit 1
    fi
    # shellcheck source=/dev/null
    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        log_warn "Este script foi testado apenas em Ubuntu. Sistema detectado: $ID $VERSION_ID"
        read -r -p "Deseja continuar mesmo assim? [s/N] " resposta
        [[ "$resposta" =~ ^[Ss]$ ]] || { log_info "Abortado pelo usuário."; exit 0; }
    fi
}

# -----------------------------------------------------------------------------
# Instalação do Docker
# -----------------------------------------------------------------------------
install_docker() {
    log_section "Instalando Docker"

    if command -v docker &>/dev/null && docker --version &>/dev/null; then
        log_ok "Docker já instalado: $(docker --version)"
        add_user_to_docker_group
        return 0
    fi

    log_info "Adicionando chave GPG e repositório do Docker..."

    sudo apt-get update -qq
    sudo apt-get install -y ca-certificates curl

    sudo install -m 0755 -d /etc/apt/keyrings

    # Baixa a chave GPG apenas se ainda não existir
    if [[ ! -f /etc/apt/keyrings/docker.asc ]]; then
        sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
            -o /etc/apt/keyrings/docker.asc
        sudo chmod a+r /etc/apt/keyrings/docker.asc
    fi

    # Configura o repositório de forma idempotente
    # shellcheck source=/dev/null
    source /etc/os-release
    local codename="${UBUNTU_CODENAME:-$VERSION_CODENAME}"
    local arch
    arch="$(dpkg --print-architecture)"

    sudo tee /etc/apt/sources.list.d/docker.sources > /dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${codename}
Components: stable
Architectures: ${arch}
Signed-By: /etc/apt/keyrings/docker.asc
EOF

    sudo apt-get update -qq
    sudo apt-get install -y \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin

    add_user_to_docker_group

    log_ok "Docker instalado com sucesso."
}

# -----------------------------------------------------------------------------
# Adiciona o usuário atual ao grupo docker
# Separado para ser invocado mesmo quando o Docker já estava instalado
# -----------------------------------------------------------------------------
add_user_to_docker_group() {
    log_section "Configurando permissões Docker para '$USER'"

    # Garante que o grupo docker existe (pode não existir em edge cases)
    if ! getent group docker &>/dev/null; then
        log_warn "Grupo 'docker' não encontrado. O Docker foi instalado corretamente?"
        return 1
    fi

    if groups "$USER" | grep -q '\bdocker\b'; then
        log_ok "Usuário '$USER' já pertence ao grupo 'docker'."
        return 0
    fi

    sudo usermod -aG docker "$USER"
    log_ok "Usuário '$USER' adicionado ao grupo 'docker'."

    # Tenta aplicar o grupo na sessão atual sem exigir logout
    if command -v newgrp &>/dev/null; then
        log_info "Aplicando grupo na sessão atual via 'newgrp docker'..."
        # newgrp abre um subshell — exec garante que substitui o processo atual
        exec newgrp docker
    else
        log_warn "'newgrp' não disponível. Faça logout/login para aplicar as permissões."
    fi
}

# -----------------------------------------------------------------------------
# Instalação de dependências de sistema
# -----------------------------------------------------------------------------
install_system_deps() {
    log_section "Instalando dependências de sistema"

    # Lista centralizada — fácil de manter/auditar
    local packages=(
        gnuradio tmux
        libzmq3-dev libfftw3-dev libmbedtls-dev libsctp-dev
        libyaml-cpp-dev libboost-program-options-dev libconfig++-dev
        cmake make gcc g++ pkg-config build-essential
        git curl jq
    )

    sudo apt-get update -qq
    sudo apt-get install -y "${packages[@]}"

    log_ok "Dependências de sistema instaladas."
}

# -----------------------------------------------------------------------------
# Compilação genérica de projeto CMake
# Uso: build_cmake_project <NOME> <DIR_FONTE> <FLAGS_CMAKE...>
# -----------------------------------------------------------------------------
build_cmake_project() {
    local name="$1"
    local src_dir="$2"
    shift 2
    local cmake_flags=("$@")

    if [[ ! -d "$src_dir" ]]; then
        log_error "Diretório não encontrado: $src_dir"
        log_error "Verifique se o repositório '${name}' foi clonado corretamente."
        return 1
    fi

    local build_dir="${src_dir}/build"
    mkdir -p "$build_dir"
    cd "$build_dir"

    log_info "cmake: configurando ${name}..."
    cmake ../ "${cmake_flags[@]}"

    local nproc_count
    nproc_count="$(nproc)"
    log_info "make: compilando ${name} com ${nproc_count} threads..."
    make -j"${nproc_count}"

    cd - > /dev/null  # Retorna ao diretório anterior sem poluir stdout
}

# -----------------------------------------------------------------------------
# Instalação do srsRAN_Project (gNB — 5G)
# -----------------------------------------------------------------------------
install_gnb() {
    log_section "Verificando gNB (srsRAN_Project)"

    if sudo gnb --version &>/dev/null; then
        log_ok "'gnb' já disponível: $(sudo gnb --version 2>&1 | head -n1)"
        return 0
    fi

    log_warn "'gnb' não encontrado. Compilando srsRAN_Project..."

    local srsran_dir="${MAIN_DIR}/openran/srsRAN_Project"

    if ! build_cmake_project "srsRAN_Project" "$srsran_dir" \
        -DENABLE_EXPORT=ON -DENABLE_ZEROMQ=ON; then
        return 1
    fi

    local gnb_bin="${srsran_dir}/build/apps/gnb/gnb"

    if [[ ! -f "$gnb_bin" ]]; then
        log_error "Binário 'gnb' não encontrado após compilação: $gnb_bin"
        return 1
    fi

    sudo cp "$gnb_bin" /usr/bin/gnb

    if sudo gnb --version &>/dev/null; then
        log_ok "srsRAN_Project compilado e instalado: $(sudo gnb --version 2>&1 | head -n1)"
    else
        log_error "'gnb' não acessível após instalação. Verifique o PATH ou execute 'sudo make install' em ${srsran_dir}/build"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Instalação do srsRAN_4G (srsUE — 4G/LTE)
# -----------------------------------------------------------------------------
install_srsue() {
    log_section "Verificando srsUE (srsRAN_4G)"

    if srsue --version &>/dev/null; then
        log_ok "'srsue' já disponível: $(srsue --version 2>&1 | head -n1)"
        return 0
    fi

    log_warn "'srsue' não encontrado. Compilando srsRAN_4G..."

    local srsran4g_dir="${MAIN_DIR}/openran/srsRAN_4G"

    if ! build_cmake_project "srsRAN_4G" "$srsran4g_dir" \
        -DENABLE_EXPORT=ON -DENABLE_ZEROMQ=ON; then
        return 1
    fi

    local srsue_bin="${srsran4g_dir}/build/srsue/src/srsue"

    if [[ ! -f "$srsue_bin" ]]; then
        log_error "Binário 'srsue' não encontrado após compilação: $srsue_bin"
        return 1
    fi

    sudo cp "$srsue_bin" /usr/bin/srsue

    # Copia as bibliotecas RF — glob explícito para evitar falha silenciosa
    local rf_libs
    rf_libs=( "${srsran4g_dir}/build/lib/src/phy/rf/libsrsran_rf"* )

    if [[ ${#rf_libs[@]} -eq 0 || ! -f "${rf_libs[0]}" ]]; then
        log_warn "Bibliotecas RF não encontradas em ${srsran4g_dir}/build/lib/src/phy/rf/"
        log_warn "Verifique manualmente se libsrsran_rf foi compilada."
    else
        sudo cp "${rf_libs[@]}" /usr/lib/
        sudo ldconfig  # Atualiza o cache de bibliotecas compartilhadas
        log_info "${#rf_libs[@]} biblioteca(s) RF copiada(s) para /usr/lib/."
    fi

    if srsue --version &>/dev/null; then
        log_ok "srsRAN 4G compilado e instalado: $(srsue --version 2>&1 | head -n1)"
    else
        log_error "'srsue' não acessível após instalação."
        log_error "Binário esperado em: ${srsue_bin}"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Resumo final
# -----------------------------------------------------------------------------
print_summary() {
    log_section "Resumo da Instalação"

    local items=(
        "docker:docker --version"
        "gnb:sudo gnb --version"
        "srsue:srsue --version"
    )

    for item in "${items[@]}"; do
        local label="${item%%:*}"
        local cmd="${item##*:}"
        if eval "$cmd" &>/dev/null; then
            log_ok "${label}: $(eval "$cmd" 2>&1 | head -n1)"
        else
            log_warn "${label}: não disponível"
        fi
    done

}

# =============================================================================
# MAIN
# =============================================================================
main() {
    MAIN_DIR="$PWD"

    log_section "Iniciando instalação — $(date '+%Y-%m-%d %H:%M:%S')"

    check_root
    check_ubuntu
    install_docker
    install_system_deps
    install_gnb
    install_srsue
    print_summary

    log_ok "Instalação concluída."
}

main "$@"
