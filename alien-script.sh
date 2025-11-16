#!/usr/bin/env bash
#
#   TTL & Port Scanner :: by 0xAlienSec (v4)
#
#   Un scanner rápido de dos fases:
#   1. Detección de OS (por TTL) y escaneo SYN ultra-rápido.
#   2. (Opcional) Escaneo profundo (-sV -sC) solo en puertos abiertos.
#
set -euo pipefail

# --- [0] Configuración Global ---
C_RST="\e[0m"
C_RED="\e[31m"
C_GRN="\e[32m"
C_YEL="\e[33m"
C_BLU="\e[34m"
C_CYN="\e[36m"

# Variables de flags
AGGRESSIVE_SCAN=0
TARGET_IP=""

trap 'echo -e "\n\n${C_YEL}[!] Escaneo interrumpido.${C_RST}"; exit 1' INT

# --- [1] Funciones de Ayuda y Banner ---
show_help() {
    echo -e "${C_GRN}Uso:${C_RST} sudo $0 [opciones] <IP_OBJETIVO>"
    echo
    echo -e "${C_YEL}Opciones:${C_RST}"
    echo -e "  ${C_CYN}-a${C_RST}         Activa el 'Escaneo Agresivo' (Versión y Scripts) sobre los puertos encontrados."
    echo -e "  ${C_CYN}-h${C_RST}         Muestra este menú de ayuda."
    echo
    echo -e "${C_YEL}Ejemplo:${C_RST}"
    echo -e "  sudo $0 10.10.10.5"
    echo -e "  sudo $0 -a 10.10.10.5"
    exit 0
}

show_banner() {
    echo -e "${C_BLU}===============================================${C_RST}"
    echo -e "   ${C_GRN}TTL & Port Scanner${C_RST} :: ${C_YEL}by 0xAlienSec${C_RST}"
    echo -e "${C_BLU}===============================================${C_RST}"
    echo
}

# --- [2] Funciones de Validación ---
check_deps() {
    for cmd in ping nmap awk grep cut sudo; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${C_RED}[-] Comando requerido no encontrado: $cmd${C_RST}"
            exit 1
        fi
    done
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo -e "${C_RED}[-] Este script requiere privilegios de root para -sS (SYN Scan).${C_RST}"
        echo -e "${C_YEL}[*] Por favor, ejecútalo con 'sudo'${C_RST}"
        exit 1
    fi
}

# --- [3] Funciones de Escaneo ---
detectar_ttl_y_os() {
    local host="$1"
    local ttl
    echo -e "${C_BLU}[*] FASE 1: Identificación de TTL y SO...${C_RST}"

    ttl=$(ping -c1 -W1 "$host" 2>/dev/null | awk -F'ttl=' '/ttl=/{split($2,a," "); print a[1]; exit}')

    if [[ -z "${ttl}" ]]; then
        echo -e "${C_YEL}[!] Sin respuesta ICMP (Host discovery -Pn será usado por Nmap).${C_RST}"
        return
    fi

    local os="Desconocido"
    if   (( ttl <= 64 ));  then os="Unix/Linux (TTL: ${ttl})"
    elif (( ttl <= 128 )); then os="Windows (TTL: ${ttl})"
    else                       os="Router/Dispositivo (TTL: ${ttl})"
    fi
    echo -e "${C_GRN}[+] SO Probable: ${os}${C_RST}"
}

# --- [MODIFICADA] ---
escaneo_nmap_rapido() {
    local host="$1"
    local nmap_out
    
    echo -e "${C_BLU}[*] FASE 2: Escaneo SYN rápido de puertos...${C_RST}"
    echo -e "    ${C_CYN}nmap -T4 -sS --open -p- -n -Pn --min-rate 3000 ${host}${C_RST}"
    echo

    nmap_out=$(nmap -T4 -sS --open -p- -n -Pn --min-rate 3000 "${host}" 2>/dev/null)

    # Parser simple y robusto
    local puertos_nl
    puertos_nl=$(echo "${nmap_out}" | grep '^[0-9]' | cut -d'/' -f1)

    if [[ -z "${puertos_nl}" ]]; then
        echo -e "${C_GRN}[+] No se detectaron puertos abiertos.${C_RST}"
        return
    fi

    # --- Salida Formato 1 (Lista) ---
    echo -e "${C_GRN}[+] Puertos Abiertos (Listado):${C_RST}"
    echo "puerto"
    echo "${puertos_nl}"
    echo

    # --- Salida Formato 2 (CSV) ---
    local puertos_csv
    puertos_csv=$(echo "${puertos_nl}" | paste -sd ',' -)
    echo -e "${C_GRN}[+] Puertos Abiertos (CSV):${C_RST}"
    echo "puerto ${puertos_csv}"
    
    # --- [LÓGICA MOVIDA AQUÍ] ---
    # Comprueba la bandera global y llama a FASE 3 si es necesario
    if [[ "${AGGRESSIVE_SCAN}" -eq 1 ]]; then
        escaneo_nmap_agresivo "${host}" "${puertos_csv}"
    fi
}

escaneo_nmap_agresivo() {
    local host="$1"
    local port_list="$2"

    if [[ -z "${port_list}" ]]; then
        return # No hay puertos que escanear
    fi

    echo
    echo -e "${C_BLU}[*] FASE 3: Escaneo Agresivo (Versión y Scripts)...${C_RST}"
    echo -e "    ${C_CYN}nmap -sV -sC -p${port_list} ${host}${C_RST}"
    echo
    
    nmap -sV -sC -Pn -p"${port_list}" "${host}"
}

# --- [4] Flujo Principal ---
# --- [MODIFICADO] ---
main() {
    # Parseo de Opciones
    while getopts "ha" opt; do
        case $opt in
            h) show_help ;;
            a) AGGRESSIVE_SCAN=1 ;;
            *) show_help ;;
        esac
    done
    shift $((OPTIND - 1)) # Mueve los argumentos para que $1 sea la IP

    # --- Validaciones ---
    check_deps
    check_root
    show_banner

    # --- Obtener IP ---
    if [[ $# -eq 0 ]]; then
        echo -e "${C_RED}[-] No se proporcionó IP objetivo.${C_RST}"
        show_help
    fi
    TARGET_IP="$1"
    echo -e "${C_YEL}[*] Objetivo: ${TARGET_IP}${C_RST}"
    echo

    # --- Ejecución ---
    detectar_ttl_y_os "${TARGET_IP}"
    echo

    # [FIX] Simplemente llama a la función. No captures la salida.
    escaneo_nmap_rapido "${TARGET_IP}"
    
    # [YA NO ES NECESARIO] La lógica agresiva se movió a la función anterior
    # if [[ "${AGGRESSIVE_SCAN}" -eq 1 ]]; then ...

    echo
    echo -e "${C_BLU}===============================================${C_RST}"
    echo -e "   ${C_GRN}Escaneo Finalizado${C_RST}"
    echo -e "${C_BLU}===============================================${C_RST}"
}

main "$@"
