#!/usr/bin/env bash
#
#   TTL & Port Scanner :: by 0xAlienSec (v4 - CTF Turbo Mode)
#
#   OPTIMIZACIÓN CTF:
#   - Se prioriza la velocidad extrema (--min-rate 3000).
#   - Se desactiva resolución DNS (-n).
#   - Ideal para HackTheBox, TryHackMe, VulnHub.
#
set -euo pipefail

# --- [0] Configuración ---
C_RST="\e[0m"
C_RED="\e[31m"
C_GRN="\e[32m"
C_YEL="\e[33m"
C_BLU="\e[34m"
C_CYN="\e[36m"
C_PUR="\e[35m"     # Explicaciones Didácticas
C_BOLD="\e[1m"

TARGET_IP=""
OUTPUT_DIR="nmap"

trap 'echo -e "\n\n${C_YEL}[!] Abortado.${C_RST}"; exit 1' INT

# --- [1] Ayudas ---
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
    echo -e "   ${C_BOLD}TTL & Port Scanner${C_RST} :: ${C_YEL}v11 CTF Edition (Fast)${C_RST}"
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
            echo -e "${C_RED}[-] Falta: $cmd${C_RST}"; exit 1
        fi
    done
}

preparar_salida() {
    local base_name="$1"
    if [[ ! -d "$OUTPUT_DIR" ]]; then mkdir -p "$OUTPUT_DIR"; fi
    local full_path="${OUTPUT_DIR}/${base_name}"
    if ls "${full_path}".* 1> /dev/null 2>&1; then rm -f "${full_path}".*; fi
}

# --- [3] Fases ---
detectar_ttl_y_os() {
    local host="$1"
    echo -e "${C_BLU}[*] FASE 1: Detectando OS (TTL)${C_RST}"
    local ttl=$(ping -c1 -W1 "$host" 2>/dev/null | awk -F'ttl=' '/ttl=/{split($2,a," "); print a[1]; exit}')

    if [[ -z "${ttl}" ]]; then
        echo -e "${C_YEL}[!] Host no responde a ping (usando -Pn por defecto).${C_RST}"
        return
    fi

    local os="Desconocido"
    if    (( ttl <= 64 ));  then os="Linux/Unix (TTL: ${ttl})"
    elif (( ttl <= 128 )); then os="Windows (TTL: ${ttl})"
    else                        os="Otro (TTL: ${ttl})"
    fi
    echo -e "${C_GRN}[+] Target: ${os}${C_RST}"
}

escaneo_nmap_rapido() {
    local host="$1"
    echo
    echo -e "${C_BLU}[*] FASE 2: Discovery Rápido (SYN)${C_RST}"
    
    local cmd="nmap -n -Pn -T4 -sS --open -p- --min-rate 3000 ${host}"
    imprimir_comando "$cmd"

    local nmap_out
    nmap_out=$(nmap -n -Pn -T4 -sS --open -p- --min-rate 3000 "${host}" 2>/dev/null)

    local puertos_nl=$(echo "${nmap_out}" | grep '^[0-9]' | cut -d'/' -f1)

    if [[ -z "${puertos_nl}" ]]; then
        echo -e "${C_RED}[-] 0 puertos abiertos.${C_RST}"; return
    fi

    local puertos_csv=$(echo "${puertos_nl}" | paste -sd ',' -)
    echo -e "${C_GRN}[+] Puertos:${C_RST} ${puertos_csv}"
    echo

    # Preguntas rápidas
    echo -e -n "${C_YEL}[?] ¿Versiones (-sV)? [s/N]: ${C_RST}"
    read -r choice_ver
    if [[ "${choice_ver,,}" =~ ^(s|si|y|yes|1)$ ]]; then
        escaneo_nmap_agresivo "${host}" "${puertos_csv}"
    fi
    echo

    echo -e -n "${C_YEL}[?] ¿Vulns (--script vuln)? [s/N]: ${C_RST}"
    read -r choice_vuln
    if [[ "${choice_vuln,,}" =~ ^(s|si|y|yes|1)$ ]]; then
        escaneo_vuln "${host}" "${puertos_csv}"
    fi
}

escaneo_nmap_agresivo() {
    local host="$1"
    local port_list="$2"
    local base_name="${host}_version_scan"
    
    preparar_salida "${base_name}"
    local output_base="${OUTPUT_DIR}/${base_name}"

    echo
    echo -e "${C_BLU}[*] FASE 3A: Fingerprinting de Servicios${C_RST}"
    imprimir_explicacion "Usamos --min-rate 3000 para acelerar la detección de versiones."
    
    # AQUI TAMBIEN APLICAMOS VELOCIDAD
    local cmd="nmap -n -Pn -sV -sC -vv --min-rate 3000 -p${port_list} -oA ${output_base} ${host}"
    imprimir_comando "$cmd"
    
    nmap -n -Pn -sV -sC -vv --min-rate 3000 -p"${port_list}" -oA "${output_base}" "${host}"

    generar_html "${output_base}.xml" "${output_base}.html"
}

escaneo_vuln() {
    local host="$1"
    local port_list="$2"
    local base_name="${host}_vuln_scan"
    
    preparar_salida "${base_name}"
    local output_base="${OUTPUT_DIR}/${base_name}"

    echo
    echo -e "${C_BLU}[*] FASE 3B: Escaneo de Vulnerabilidades (Modo CTF)${C_RST}"
    
    imprimir_explicacion "Buscando CVEs con velocidad agresiva (-min-rate 3000)."
    echo -e "      ${C_CYN}-n${C_RST} : Sin DNS."
    echo -e "      ${C_CYN}-Pn${C_RST} : Asumir host online."
    echo -e "      ${C_CYN}--min-rate 3000${C_RST} : Fuerza bruta de velocidad."
    echo
    
    # --- [MODIFICADO SEGUN TU PEDIDO] ---
    local cmd="nmap -n -Pn --min-rate 3000 -vv --script vuln -p${port_list} -oA ${output_base} ${host}"
    imprimir_comando "$cmd"
    
    nmap -n -Pn --min-rate 3000 -vv --script vuln -p"${port_list}" -oA "${output_base}" "${host}"
    # ------------------------------------

    generar_html "${output_base}.xml" "${output_base}.html"
}

generar_html() {
    local xml_in="$1"
    local html_out="$2"
    echo
    if [[ -f "${xml_in}" ]]; then
        xsltproc "${xml_in}" -o "${html_out}" 2>/dev/null
        echo -e "${C_GRN}[OK] HTML Generado: ${html_out}${C_RST}"
    else
        echo -e "${C_RED}[ERROR] Falló Nmap, no hay XML.${C_RST}"
    fi
}

# --- [4] Main ---
main() {
    check_deps; check_root; show_banner
    if [[ $# -eq 0 ]]; then echo -e "${C_RED}[!] Uso: sudo $0 <IP>${C_RST}"; exit 1; fi
    TARGET_IP="$1"
    echo -e "${C_YEL}[TARGET]: ${TARGET_IP}${C_RST}"
    echo
    detectar_ttl_y_os "${TARGET_IP}"
    escaneo_nmap_rapido "${TARGET_IP}"
    echo
    echo -e "${C_BLU}=== DONE ===${C_RST}"
}

main "$@"
