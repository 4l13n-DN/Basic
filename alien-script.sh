#!/usr/bin/env bash
#
#   TTL & Port Scanner :: by 0xAlienSec (v8 - Organized)
#
#   1. Detección de OS (TTL) y escaneo SYN.
#   2. Escaneo de Servicios y Vulnerabilidades interactivo.
#   3. Gestión automática de carpeta 'nmap' y limpieza de archivos previos.
#   4. Reportes HTML automáticos.
#
set -euo pipefail

# --- [0] Configuración Global ---
C_RST="\e[0m"
C_RED="\e[31m"
C_GRN="\e[32m"
C_YEL="\e[33m"
C_BLU="\e[34m"
C_CYN="\e[36m"

TARGET_IP=""
OUTPUT_DIR="nmap" # Nombre de la carpeta de salida

trap 'echo -e "\n\n${C_YEL}[!] Escaneo interrumpido.${C_RST}"; exit 1' INT

# --- [1] Funciones de Ayuda y Banner ---
show_help() {
    echo -e "${C_GRN}Uso:${C_RST} sudo $0 <IP_OBJETIVO>"
    echo
    exit 0
}

show_banner() {
    echo -e "${C_BLU}===============================================${C_RST}"
    echo -e "   ${C_GRN}TTL & Port Scanner${C_RST} :: ${C_YEL}by 0xAlienSec${C_RST}"
    echo -e "${C_BLU}===============================================${C_RST}"
    echo
}

# --- [2] Funciones de Validación y Preparación ---
check_deps() {
    for cmd in ping nmap awk grep cut sudo xsltproc; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${C_RED}[-] Falta comando: $cmd${C_RST}"
            exit 1
        fi
    done
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo -e "${C_RED}[-] Se requiere root (sudo).${C_RST}"
        exit 1
    fi
}

# [NUEVO] Función para gestionar carpeta y limpieza
preparar_salida() {
    local base_name="$1" # Ej: 10.10.10.5_version_scan
    
    # 1. Crear carpeta si no existe
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        echo -e "${C_YEL}[*] Carpeta '$OUTPUT_DIR' no encontrada. Creándola...${C_RST}"
        mkdir -p "$OUTPUT_DIR"
    fi

    # 2. Ruta completa del archivo base
    local full_path="${OUTPUT_DIR}/${base_name}"

    # 3. Limpiar archivos viejos si existen
    # Borra .xml, .nmap, .gnmap y .html asociados a ese nombre
    if ls "${full_path}".* 1> /dev/null 2>&1; then
        echo -e "${C_YEL}[*] Detectados resultados previos para ${base_name}. Eliminando...${C_RST}"
        rm -f "${full_path}".*
    fi
}

# --- [3] Funciones de Escaneo ---
detectar_ttl_y_os() {
    local host="$1"
    local ttl
    echo -e "${C_BLU}[*] FASE 1: Identificación de TTL y SO...${C_RST}"

    ttl=$(ping -c1 -W1 "$host" 2>/dev/null | awk -F'ttl=' '/ttl=/{split($2,a," "); print a[1]; exit}')

    if [[ -z "${ttl}" ]]; then
        echo -e "${C_YEL}[!] Sin respuesta ICMP.${C_RST}"
        return
    fi

    local os="Desconocido"
    if    (( ttl <= 64 ));  then os="Unix/Linux (TTL: ${ttl})"
    elif (( ttl <= 128 )); then os="Windows (TTL: ${ttl})"
    else                        os="Router/Dispositivo (TTL: ${ttl})"
    fi
    echo -e "${C_GRN}[+] SO Probable: ${os}${C_RST}"
}

escaneo_nmap_rapido() {
    local host="$1"
    local nmap_out
    
    echo -e "${C_BLU}[*] FASE 2: Escaneo SYN rápido de puertos...${C_RST}"
    # Este escaneo es rápido y no se guarda en disco, solo muestra en pantalla
    # para identificar qué atacar después.
    
    nmap_out=$(nmap -T4 -sS --open -p- -n -Pn --min-rate 3000 "${host}" 2>/dev/null)

    local puertos_nl
    puertos_nl=$(echo "${nmap_out}" | grep '^[0-9]' | cut -d'/' -f1)

    if [[ -z "${puertos_nl}" ]]; then
        echo -e "${C_GRN}[+] No se detectaron puertos abiertos.${C_RST}"
        return
    fi

    local puertos_csv
    puertos_csv=$(echo "${puertos_nl}" | paste -sd ',' -)
    
    echo -e "${C_GRN}[+] Puertos encontrados:${C_RST} ${puertos_csv}"
    echo
    
    # --- Flujo Interactivo ---
    
    # 1. Escaneo de Servicios
    local choice_ver
    echo -e -n "${C_YEL}[?] ¿Escanear versiones (-sV -sC)? (s/N): ${C_RST}"
    read -r choice_ver
    if [[ "${choice_ver,,}" =~ ^(s|si|y|yes|1)$ ]]; then
        escaneo_nmap_agresivo "${host}" "${puertos_csv}"
    fi
    echo

    # 2. Escaneo de Vulnerabilidades
    local choice_vuln
    echo -e -n "${C_YEL}[?] ¿Escanear vulnerabilidades (--script vuln)? (s/N): ${C_RST}"
    read -r choice_vuln
    if [[ "${choice_vuln,,}" =~ ^(s|si|y|yes|1)$ ]]; then
        escaneo_vuln "${host}" "${puertos_csv}"
    fi
}

escaneo_nmap_agresivo() {
    local host="$1"
    local port_list="$2"

    # Nombre base del archivo (sin extensión ni carpeta)
    local base_name="${host}_version_scan"
    
    # [MODIFICADO] Prepara carpeta y limpia archivos viejos
    preparar_salida "${base_name}"

    # Definimos rutas completas incluyendo la carpeta
    local output_base="${OUTPUT_DIR}/${base_name}"
    local xml_input="${output_base}.xml"
    local html_output="${output_base}.html"

    echo
    echo -e "${C_BLU}[*] FASE 3A: Escaneo de Servicios...${C_RST}"
    # Nota: Usamos ${output_base} con -oA. Nmap añadirá las extensiones automáticamente dentro de la carpeta.
    echo -e "    ${C_CYN}Guardando en: ${OUTPUT_DIR}/${C_RST}"
    
    nmap -sV -sC -vvv -Pn -p"${port_list}" -oA "${output_base}" "${host}"

    generar_html "${xml_input}" "${html_output}"
}

escaneo_vuln() {
    local host="$1"
    local port_list="$2"

    local base_name="${host}_vuln_scan"
    
    # [MODIFICADO] Prepara carpeta y limpia archivos viejos
    preparar_salida "${base_name}"

    local output_base="${OUTPUT_DIR}/${base_name}"
    local xml_input="${output_base}.xml"
    local html_output="${output_base}.html"

    echo
    echo -e "${C_BLU}[*] FASE 3B: Escaneo de Vulnerabilidades...${C_RST}"
    echo -e "    ${C_CYN}Guardando en: ${OUTPUT_DIR}/${C_RST}"
    
    nmap --script vuln -Pn -p"${port_list}" -oA "${output_base}" "${host}"

    generar_html "${xml_input}" "${html_output}"
}

generar_html() {
    local xml_in="$1"
    local html_out="$2"

    echo -e "${C_BLU}[*] Generando reporte HTML...${C_RST}"
    if [[ -f "${xml_in}" ]]; then
        xsltproc "${xml_in}" -o "${html_out}" 2>/dev/null
        echo -e "${C_GRN}[+] Reporte guardado: ${html_out}${C_RST}"
    else
        echo -e "${C_RED}[-] Error: No se encontró ${xml_in}${C_RST}"
    fi
}

# --- [4] Flujo Principal ---
main() {
    check_deps
    check_root
    show_banner

    if [[ $# -eq 0 ]]; then
        echo -e "${C_RED}[-] Debes indicar la IP.${C_RST}"
        show_help
    fi
    TARGET_IP="$1"
    echo -e "${C_YEL}[*] Objetivo: ${TARGET_IP}${C_RST}"
    echo

    detectar_ttl_y_os "${TARGET_IP}"
    echo
    escaneo_nmap_rapido "${TARGET_IP}"
    
    echo
    echo -e "${C_BLU}=== FINALIZADO ===${C_RST}"
}

main "$@"
