#!/usr/bin/env bash
#
#   TTL & Port Scanner :: by 0xAlienSec (v6)
#
#   Scanner interactivo con reporte HTML automático:
#   1. Detección de OS (TTL) y escaneo SYN ultra-rápido.
#   2. Pregunta interactiva para escaneo profundo (-sV -sC).
#   3. Generación de reporte HTML automático (vía xsltproc).
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

trap 'echo -e "\n\n${C_YEL}[!] Escaneo interrumpido.${C_RST}"; exit 1' INT

# --- [1] Funciones de Ayuda y Banner ---
show_help() {
    echo -e "${C_GRN}Uso:${C_RST} sudo $0 <IP_OBJETIVO>"
    echo
    echo -e "${C_YEL}Opciones:${C_RST}"
    echo -e "  ${C_CYN}-h${C_RST}         Muestra este menú de ayuda."
    echo
    echo -e "${C_YEL}Ejemplo:${C_RST}"
    echo -e "  sudo $0 10.10.10.5"
    exit 0
}

show_banner() {
    echo -e "${C_BLU}===============================================${C_RST}"
    echo -e "   ${C_GRN}TTL & Port Scanner${C_RST} :: ${C_YEL}by 0xAlienSec${C_RST}"
    echo -e "${C_BLU}===============================================${C_RST}"
    echo
}

# --- [2] Funciones de Validación ---
# --- [MODIFICADA] ---
check_deps() {
    # [NUEVO] Se añade 'xsltproc' a la lista
    for cmd in ping nmap awk grep cut sudo xsltproc; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${C_RED}[-] Comando requerido no encontrado: $cmd${C_RST}"
            # [NUEVO] Sugerencia de instalación
            if [[ "$cmd" == "xsltproc" ]]; then
                echo -e "${C_YEL}[*] Sugerencia: prueba 'sudo apt install xsltproc' (Debian/Ubuntu) o 'sudo dnf install libxslt' (Fedora)${C_RST}"
            fi
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

escaneo_nmap_rapido() {
    local host="$1"
    local nmap_out
    
    echo -e "${C_BLU}[*] FASE 2: Escaneo SYN rápido de puertos...${C_RST}"
    echo -e "    ${C_CYN}nmap -T4 -sS --open -p- -n -Pn --min-rate 3000 ${host}${C_RST}"
    echo

    nmap_out=$(nmap -T4 -sS --open -p- -n -Pn --min-rate 3000 "${host}" 2>/dev/null)

    local puertos_nl
    puertos_nl=$(echo "${nmap_out}" | grep '^[0-9]' | cut -d'/' -f1)

    if [[ -z "${puertos_nl}" ]]; then
        echo -e "${C_GRN}[+] No se detectaron puertos abiertos.${C_RST}"
        return
    fi

    echo -e "${C_GRN}[+] Puertos Abiertos (Listado):${C_RST}"
    echo "puerto"
    echo "${puertos_nl}"
    echo

    local puertos_csv
    puertos_csv=$(echo "${puertos_nl}" | paste -sd ',' -)
    echo -e "${C_GRN}[+] Puertos Abiertos (CSV):${C_RST}"
    echo "puerto ${puertos_csv}"
    echo
    
    local choice
    echo -e -n "${C_YEL}[?] ¿Deseas buscar la versión de los servicios descubiertos? (s/N): ${C_RST}"
    read -r choice

    case "${choice,,}" in
        s|si|y|yes|1)
            escaneo_nmap_agresivo "${host}" "${puertos_csv}"
            ;;
        *)
            echo -e "${C_YEL}[*] Omitiendo escaneo de versión.${C_RST}"
            ;;
    esac
}

# --- [MODIFICADA] ---
escaneo_nmap_agresivo() {
    local host="$1"
    local port_list="$2"

    if [[ -z "${port_list}" ]]; then
        return
    fi

    # Definimos los nombres de archivo
    local output_filename="${host}_version_scan"
    local xml_input="${output_filename}.xml"
    local html_output="${output_filename}.html"

    echo
    echo -e "${C_BLU}[*] FASE 3: Escaneo Agresivo (Versión, Scripts, Verbose)...${C_RST}"
    echo -e "    ${C_CYN}nmap -sV -sC -vvv -Pn -p${port_list} -oA ${output_filename} ${host}${C_RST}"
    echo
    
    # Ejecuta el escaneo Nmap
    nmap -sV -sC -vvv -Pn -p"${port_list}" -oA "${output_filename}" "${host}"

    echo
    echo -e "${C_GRN}[+] ¡Escaneo agresivo completado!${C_RST}"
    echo -e "${C_GRN}[+] Resultados Nmap guardados en: ${output_filename}.(nmap|xml|gnmap)${C_RST}"

    # --- [NUEVO] FASE 4: Generación de Reporte HTML ---
    echo
    echo -e "${C_BLU}[*] FASE 4: Generando reporte HTML desde XML...${C_RST}"
    
    # Comprueba si el archivo XML se creó correctamente
    if [[ -f "${xml_input}" ]]; then
        echo -e "    ${C_CYN}xsltproc ${xml_input} -o ${html_output}${C_RST}"
        # Ejecuta la conversión
        xsltproc "${xml_input}" -o "${html_output}"
        
        echo -e "${C_GRN}[+] ¡Reporte HTML generado!${C_RST}"
        echo -e "${C_GRN}[+] Archivo: ${html_output}${C_RST}"
    else
        echo -e "${C_RED}[-] No se encontró el archivo ${xml_input}. No se pudo generar el reporte HTML.${C_RST}"
    fi
}

# --- [4] Flujo Principal ---
main() {
    while getopts "h" opt; do
        case $opt in
            h) show_help ;;
            *) show_help ;;
        esac
    done
    shift $((OPTIND - 1))

    # --- Validaciones ---
    check_deps # <-- Ahora comprueba xsltproc
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

    escaneo_nmap_rapido "${TARGET_IP}"
    
    echo
    echo -e "${C_BLU}===============================================${C_RST}"
    echo -e "   ${C_GRN}Escaneo Finalizado${C_RST}"
    echo -e "${C_BLU}===============================================${C_RST}"
}

main "$@"
