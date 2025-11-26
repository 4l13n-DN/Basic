#!/usr/bin/env bash
#
#   TTL & Web Enum Scanner :: by 0xAlienSec
#   v2.1 - CTF Turbo Mode + ENUMWEB + LOG + Tips + Droid Vuln
#
set -euo pipefail

# --- [0] Configuración ---
C_RST="\e[0m"
C_RED="\e[31m"
C_GRN="\e[32m"
C_YEL="\e[33m"
C_BLU="\e[34m"
C_CYN="\e[36m"
C_PUR="\e[35m"
C_BOLD="\e[1m"

TARGET_IP=""
MACHINE_NAME=""
MACHINE_DIR=""
OUTPUT_DIR=""          # MACHINE_DIR/nmap
OPEN_PORTS_CSV=""      # Puertos abiertos detectados (fase rápida)
LOG_FILE=""            # resultado_<maquina>.txt
SV_RUN=0               # Flag: se ejecutó -sV/-sC

trap 'echo -e "\n\n${C_YEL}[!] Abortado.${C_RST}"; exit 1' INT

# --- [1] Helpers didácticos ---
imprimir_explicacion() {
    echo -e "${C_PUR}  [i] CTF TIP:${C_RST} $1"
}

imprimir_comando() {
    echo -e "${C_PUR}  [>] COMANDO:${C_RST}"
    echo -e "      ${C_CYN}$1${C_RST}"
    echo
}

show_banner() {
    clear
    echo -e "${C_BLU}=========================================================${C_RST}"
    echo -e "   ${C_BOLD}TTL & Web Enum Scanner${C_RST} :: ${C_YEL}v2.1 CTF Droid Edition${C_RST}"
    echo -e "${C_BLU}=========================================================${C_RST}"
    echo
}

# --- [2] Validaciones ---
check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo -e "${C_RED}[!] Se requiere sudo para escaneos SYN rápidos.${C_RST}"
        exit 1
    fi
}

check_deps() {
    for cmd in ping nmap awk grep cut sudo xsltproc; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${C_RED}[-] Falta: $cmd${C_RST}"
            exit 1
        fi
    done
}

check_web_deps() {
    for cmd in whatweb gobuster curl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${C_RED}[-] Falta (ENUMWEB): $cmd${C_RST}"
            exit 1
        fi
    done
}

preparar_salida() {
    local base_name="$1"
    if [[ ! -d "$OUTPUT_DIR" ]]; then mkdir -p "$OUTPUT_DIR"; fi
    local full_path="${OUTPUT_DIR}/${base_name}"
    if ls "${full_path}".* 1> /dev/null 2>&1; then rm -f "${full_path}".*; fi
}

# --- [2.1] Menú inicial / Máquina & IP ---
configurar_maquina() {
    echo -e "${C_BLU}[*] CONFIGURACIÓN INICIAL${C_RST}"
    echo -e -n "${C_YEL}[?] Nombre de la máquina (sin espacios, ej: mrrobot, vulnversity): ${C_RST}"
    read -r MACHINE_NAME

    if [[ -z "${MACHINE_NAME}" ]]; then
        echo -e "${C_RED}[!] El nombre no puede estar vacío.${C_RST}"
        exit 1
    fi

    if [[ "${MACHINE_NAME}" =~ [[:space:]] ]]; then
        echo -e "${C_RED}[!] No se permiten espacios en el nombre de la máquina.${C_RST}"
        exit 1
    fi

    MACHINE_DIR="${MACHINE_NAME}"

    if [[ -d "${MACHINE_DIR}" ]]; then
        echo -e "${C_YEL}[i] La carpeta ${MACHINE_DIR} ya existe, se reutilizará la estructura.${C_RST}"
    else
        mkdir -p "${MACHINE_DIR}"/{nmap,exploit,otros}
        echo -e "${C_GRN}[+] Estructura creada: ${MACHINE_DIR}/{nmap,exploit,otros}${C_RST}"
    fi

    OUTPUT_DIR="${MACHINE_DIR}/nmap"
    LOG_FILE="${MACHINE_DIR}/resultado_${MACHINE_NAME}.txt"

    # Inicializar log con timestamp
    {
        echo "Nombre de la máquina: ${MACHINE_NAME}"
        echo "======================================="
        echo "Fecha/Hora de ejecución: $(date)"
        echo
    } > "${LOG_FILE}"

    echo -e "${C_GRN}[+] Directorio de salida Nmap_
