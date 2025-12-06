#!/usr/bin/env bash
#
#    TTL & Web Enum Scanner :: by 0xAlienSec
#    v2.5 - Instructor Edition (Full Logs + Full Tips + Command Echo)
#
set -euo pipefail

# --- [0] Colores & globals ---
C_RST="\e[0m"
C_RED="\e[31m"
C_GRN="\e[32m"
C_YEL="\e[33m"
C_BLU="\e[34m"
C_CYN="\e[36m"
C_PUR="\e[35m"
C_BOLD="\e[1m"

TARGET_IP=""
ATTACKER_IP=""          # Tu IP (tun0 o eth0)
MACHINE_NAME=""
MACHINE_DIR=""
OUTPUT_DIR=""           # MACHINE_DIR/nmap
OPEN_PORTS_CSV=""       # Puertos abiertos detectados (fase rápida)
LOG_FILE=""             # resultado_<maquina>.txt

# Usuario original que lanzó sudo
ORIG_USER="${SUDO_USER:-$USER}"

trap 'echo -e "\n\n${C_YEL}[!] Abortado.${C_RST}"; exit 1' INT

# --- [1] Helpers genéricos ---
imprimir_explicacion() {
    echo -e "${C_PUR}  [i] CTF TIP:${C_RST} $1"
}

imprimir_comando() {
    echo -e "${C_PUR}  [>] COMANDO EJECUTADO:${C_RST}"
    echo -e "      ${C_CYN}$1${C_RST}"
    echo
}

log() {
    [[ -n "${LOG_FILE}" ]] && echo "$1" >> "${LOG_FILE}"
}

log_block() {
    [[ -n "${LOG_FILE}" ]] && printf '%s\n' "$@" >> "${LOG_FILE}"
}

ask_yes_no() {
    local prompt="$1"
    local ans
    echo -en "${C_YEL}[?] ${prompt} [s/N]: ${C_RST}"
    read -r ans
    [[ "${ans,,}" =~ ^(s|si|y|yes|1)$ ]]
}

# --- [1.1] Detección de IP Atacante ---
detectar_mi_ip() {
    local ip=""
    if ip addr show tun0 >/dev/null 2>&1; then
        ip=$(ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        echo -e "${C_GRN}[VPN] Interfaz tun0 detectada.${C_RST}"
    elif ip addr show eth0 >/dev/null 2>&1; then
        ip=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        echo -e "${C_YEL}[LAN] Interfaz tun0 no existe. Usando eth0.${C_RST}"
    else
        ip=$(hostname -I | awk '{print $1}')
        echo -e "${C_YEL}[UNK] Usando hostname -I.${C_RST}"
    fi
    ATTACKER_IP="${ip}"
}

show_banner() {
    clear
    detectar_mi_ip
    echo -e "${C_BLU}=========================================================${C_RST}"
    echo -e "    ${C_BOLD}TTL & Web Enum Scanner${C_RST} :: ${C_YEL}v2.5 Instructor Edition${C_RST}"
    echo -e "               by 0xAlienSec"
    echo -e "${C_BLU}=========================================================${C_RST}"
    echo -e "    ${C_PUR}MI IP (Atacante):${C_RST} ${ATTACKER_IP}"
    echo -e "${C_BLU}=========================================================${C_RST}"
    echo
}

# --- [2] Validaciones ---
check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo -e "${C_RED}[!] Este script debe ejecutarse con sudo o como root.${C_RST}"
        exit 1
    fi
}

check_deps() {
    local deps=(ping nmap awk grep cut sudo xsltproc curl)
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${C_RED}[-] Falta dependencia vital: $cmd${C_RST}"
            exit 1
        fi
    done
}

# --- [2.1] Configuración ---
configurar_maquina() {
    echo -e "${C_BLU}[*] CONFIGURACIÓN INICIAL${C_RST}"
    echo -en "${C_YEL}[?] Nombre de la máquina (sin espacios): ${C_RST}"
    read -r MACHINE_NAME

    if [[ -z "${MACHINE_NAME}" || "${MACHINE_NAME}" =~ [[:space:]] ]]; then
        echo -e "${C_RED}[!] Nombre inválido.${C_RST}"
        exit 1
    fi

    MACHINE_DIR="${MACHINE_NAME}"

    if [[ -d "${MACHINE_DIR}" ]]; then
        echo -e "${C_YEL}[i] Carpeta existente: ${MACHINE_DIR}.${C_RST}"
        if ask_yes_no "¿Deseas usar esta estructura existente?"; then
            echo -e "${C_GRN}[+] OK. Reutilizando estructura.${C_RST}"
        else
            echo -e "${C_RED}[!] Abortado.${C_RST}"
            exit 1
        fi
    else
        mkdir -p "${MACHINE_DIR}"/{nmap,exploit,otros}
        echo -e "${C_GRN}[+] Estructura creada.${C_RST}"
    fi

    OUTPUT_DIR="${MACHINE_DIR}/nmap"
    LOG_FILE="${MACHINE_DIR}/resultado_${MACHINE_NAME}.txt"

    cat > "${LOG_FILE}" <<EOF
Nombre de la máquina: ${MACHINE_NAME}
IP Atacante (Tu IP): ${ATTACKER_IP}
=======================================

EOF

    chown -R "${ORIG_USER}:${ORIG_USER}" "${MACHINE_DIR}"
    chmod -R 775 "${MACHINE_DIR}"
}

leer_ip_objetivo() {
    echo -en "${C_YEL}[?] Ingresa la IP o dominio a analizar: ${C_RST}"
    read -r TARGET_IP

    if [[ -z "${TARGET_IP}" ]]; then
        echo -e "${C_RED}[!] IP inválida.${C_RST}"
        exit 1
    fi

    echo -e "${C_BLU}[*] Comprobando conectividad (ping)...${C_RST}"
    if ! ping -c 1 -W 1 "${TARGET_IP}" >/dev/null 2>&1; then
        echo -e "${C_RED}[!] La máquina (${TARGET_IP}) NO responde a ping.${C_RST}"
        echo -e "${C_YEL}[!] REVERSANDO: Revisa tu conexión (VPN/Red) o si la máquina está encendida.${C_RST}"
        echo -e "${C_CYN}[i] La carpeta ${MACHINE_DIR} se mantiene para reintentos.${C_RST}"
        exit 1
    fi
    
    echo -e "${C_GRN}[+] Conectividad OK.${C_RST}"
    echo -e "${C_YEL}[TARGET]: ${TARGET_IP}${C_RST}"
    echo
    log "IP Objetivo: ${TARGET_IP}"
}

# --- [3] Nmap Fases ---
detectar_ttl_y_os() {
    local host="$1"
    echo -e "${C_BLU}[*] FASE 1: Detectando OS (TTL)${C_RST}"
    local ttl
    ttl=$(ping -c1 -W1 "$host" 2>/dev/null | awk -F'ttl=' '/ttl=/{split($2,a," "); print a[1]; exit}')

    local os="Desconocido"
    [[ -n "$ttl" ]] && {
        if   (( ttl <= 64 ));  then os="Linux/Unix (TTL: ${ttl})"
        elif (( ttl <= 128 )); then os="Windows (TTL: ${ttl})"
        else                       os="Otro (TTL: ${ttl})"
        fi
    }
    echo -e "${C_GRN}[+] Target: ${os}${C_RST}"
    log "OS (TTL): ${os}"
}

escaneo_nmap_rapido() {
    local host="$1"
    echo
    echo -e "${C_BLU}[*] FASE 2: Discovery Rápido (SYN)${C_RST}"
    local cmd="nmap -n -Pn -T4 -sS --open -p- --min-rate 3000 ${host}"
    imprimir_comando "$cmd"

    local nmap_out
    nmap_out=$(nmap -n -Pn -T4 -sS --open -p- --min-rate 3000 "${host}" 2>/dev/null)
    local puertos_nl
    puertos_nl=$(echo "${nmap_out}" | grep '^[0-9]' | cut -d'/' -f1)

    if [[ -z "${puertos_nl}" ]]; then
        echo -e "${C_RED}[-] 0 puertos abiertos.${C_RST}"
        log "Puertos abiertos: 0"
        return
    fi

    OPEN_PORTS_CSV=$(echo "${puertos_nl}" | paste -sd ',' -)
    echo -e "${C_GRN}[+] Puertos descubiertos:${C_RST} ${OPEN_PORTS_CSV}"
    echo
}

escaneo_nmap_agresivo() {
    local host="$1"
    local port_list="$2"
    local base_name="${host}_version_scan"
    local output_base="${OUTPUT_DIR}/${base_name}"
    
    rm -f "${output_base}".* 2>/dev/null

    echo
    echo -e "${C_BLU}[*] FASE 3: Fingerprinting de Servicios (-sV -sC)${C_RST}"
    local cmd="nmap -n -Pn -sV -sC -vv --min-rate 3000 -p${port_list} -oA ${output_base} ${host}"
    imprimir_comando "$cmd"
    
    nmap -n -Pn -sV -sC -vv --min-rate 3000 -p"${port_list}" -oA "${output_base}" "${host}"
    generar_html "${output_base}.xml" "${output_base}.html"
    
    if [[ -f "${output_base}.nmap" ]]; then
        log ""
        log "--- Detalle Puertos ---"
        awk '/^[0-9]+\/tcp/ {print $0}' "${output_base}.nmap" >> "${LOG_FILE}"
    fi
}

generar_html() {
    local xml_in="$1"
    local html_out="$2"
    if [[ -f "${xml_in}" ]]; then
        xsltproc "${xml_in}" -o "${html_out}" 2>/dev/null
        echo -e "${C_GRN}[OK] HTML: ${html_out}${C_RST}"
    fi
}

# --- [3B] Generar droide AUTO-DESTRUCT ---
generar_droide_vuln() {
    local host="$1"
    local port_list="$2"
    [[ -z "${port_list}" ]] && return

    local droid_path="${MACHINE_DIR}/droid.sh"

    cat > "${droid_path}" <<EOF
#!/usr/bin/env bash
# Droide de Vulnerabilidades - AutoDestruct Edition
set -euo pipefail

C_GRN="\e[32m"
C_CYN="\e[36m"
C_RST="\e[0m"

if [[ "\${EUID}" -ne 0 ]]; then
    echo "Ejecuta con sudo."
    exit 1
fi

HOST="${host}"
PORT_LIST="${port_list}"
OUTPUT_DIR="nmap"
BASE_NAME="\${HOST}_vuln_scan"

echo -e "\${C_CYN}[*] Ejecutando escaneo vuln sobre \${HOST}...\${C_RST}"
nmap -n -Pn --min-rate 3000 -T4 --script vuln --script-timeout 60s -vv -p"\${PORT_LIST}" -oA "\${OUTPUT_DIR}/\${BASE_NAME}" "\${HOST}"

if [[ -f "\${OUTPUT_DIR}/\${BASE_NAME}.xml" ]]; then
    xsltproc "\${OUTPUT_DIR}/\${BASE_NAME}.xml" -o "\${OUTPUT_DIR}/\${BASE_NAME}.html"
fi

echo -e "\${C_GRN}[OK] Escaneo de vulnerabilidades finalizado. Revisa: \${OUTPUT_DIR}/\${BASE_NAME}.*\${C_RST}"
echo -e "\${C_CYN}[i] Auto-destruyendo este script (droid.sh)...\${C_RST}"

rm -- "\$0"
EOF

    chmod +x "${droid_path}"
    echo -e "${C_GRN}[+] Droide generado: ${droid_path} (Se borrará tras ejecutarse)${C_RST}"
    echo -e "${C_YEL}[VULNS] Ejecutar manual: cd ${MACHINE_DIR} && sudo ./droid.sh${C_RST}"
    log "Droide generado: ${droid_path}"
}

# --- [4] ENUMWEB + Validaciones ---
validar_puerto_web() {
    local host="$1"
    local port="$2"
    if ! curl -s --head --connect-timeout 3 "http://${host}:${port}" >/dev/null; then
        return 1
    fi
    return 0
}

enum_web_port() {
    local host="$1"
    local port="$2"
    local web_dir="${MACHINE_DIR}/otros/enum_${host}_${port}"
    local base_url="http://${host}:${port}"

    echo
    echo -e "${C_BLU}[*] FASE 4: ENUMWEB sobre ${host}:${port}${C_RST}"
    
    echo -en "${C_YEL}[?] Validando si el puerto ${port} es HTTP... ${C_RST}"
    if ! validar_puerto_web "${host}" "${port}"; then
        echo -e "${C_RED}NO.${C_RST}"
        echo -e "${C_YEL}[!] El puerto ${port} no responde a HTTP/HTML. Saltando análisis web.${C_RST}"
        log "ENUMWEB: Puerto ${port} omitido (no pasó validación HTTP)."
        return
    fi
    echo -e "${C_GRN}SÍ.${C_RST}"

    mkdir -p "${web_dir}"
    log ""
    log "=== ENUMWEB ${base_url} ==="

    # --- Whatweb ---
    echo "--- Whatweb ---"
    local cmd_whatweb="whatweb ${base_url}"
    
    if command -v whatweb >/dev/null 2>&1; then
        imprimir_comando "$cmd_whatweb"
        whatweb "${base_url}" | tee "${web_dir}/whatweb.txt" || echo -e "${C_RED}[!] Error al ejecutar whatweb${C_RST}"
    else
        echo -e "${C_YEL}[!] 'whatweb' no está instalado. Omitiendo.${C_RST}"
    fi

    # --- Gobuster ---
    echo
    echo "--- Gobuster ---"
    if command -v gobuster >/dev/null 2>&1; then
        local wordlist="/usr/share/wordlists/dirb/common.txt"
        
        if [[ ! -f "${wordlist}" ]]; then
            echo -e "${C_RED}[!] No se encuentra el diccionario ($wordlist). Saltando Gobuster.${C_RST}"
        else
            # 1. Definimos el comando explícito
            local cmd_gobuster="gobuster dir -u ${base_url} -w ${wordlist} -x txt,php,zip -s 200,204,301,302,307,403 -b '' -t 50 -k --no-error -o ${web_dir}/gobuster.txt"
            
            # 2. Mostramos el comando al alumno
            imprimir_comando "$cmd_gobuster"
            log "CMD: $cmd_gobuster"
            
            # 3. Ejecutamos (la salida se guarda en archivo por el -o)
            gobuster dir -u "${base_url}" -w "${wordlist}" -x txt,php,zip \
                -s 200,204,301,302,307,403 -b "" -t 50 -k --no-error -o "${web_dir}/gobuster.txt" >/dev/null || true
            
            # 4. Extraemos resultados reales para el LOG
            if [[ -f "${web_dir}/gobuster.txt" ]]; then
                local hits
                hits=$(grep -c "Status:" "${web_dir}/gobuster.txt" || true)
                echo -e "${C_GRN}[+] Gobuster finalizado. Hits: ${hits}${C_RST}"
                
                log "--- Resultados Gobuster ---"
                # Copia las líneas interesantes al log principal
                grep "Status:" "${web_dir}/gobuster.txt" >> "${LOG_FILE}"
            fi
        fi
    else
        echo -e "${C_YEL}[!] 'gobuster' no está instalado. Omitiendo.${C_RST}"
    fi

    # --- Archivos Sensibles ---
    echo "--- Archivos Sensibles ---"
    local SENSITIVE=("robots.txt" "sitemap.xml")
    for file in "${SENSITIVE[@]}"; do
        local url="${base_url}/${file}"
        local status
        status=$(curl -o /dev/null --silent -Iw "%{http_code}" "${url}" || echo "ERR")
        if [[ "$status" == "200" ]]; then
            echo -e "${C_GRN}[+] Encontrado: ${url}${C_RST}"
            log "Sensible encontrado: ${url}"
        fi
    done
    echo -e "${C_GRN}[OK] Resultados en: ${web_dir}${C_RST}"
}

# --- [5] Sugerencias Restauradas ---
sugerencias_puertos() {
    [[ -z "${OPEN_PORTS_CSV}" ]] && return

    # Parsear puertos a flags
    local has_ssh=0 has_ftp=0 has_http=0 has_smb=0 has_rdp=0 has_mysql=0 has_mssql=0 has_smtp=0 has_redis=0
    IFS=',' read -r -a PORT_ARRAY <<< "${OPEN_PORTS_CSV}"

    for p in "${PORT_ARRAY[@]}"; do
        case "${p}" in
            22)    has_ssh=1 ;;
            21)    has_ftp=1 ;;
            80|443|8080|8000|8443) has_http=1 ;;
            139|445) has_smb=1 ;;
            3389) has_rdp=1 ;;
            3306) has_mysql=1 ;;
            1433) has_mssql=1 ;;
            25|587) has_smtp=1 ;;
            6379) has_redis=1 ;;
        esac
    done

    log ""
    log "=== Sugerencias de próximos pasos (no obligatorias) ==="
    log "DISCLAIMER: Estas sugerencias son orientativas para laboratorio/CTF."
    log "No son comandos que deban ejecutarse siempre en un entorno real."
    log ""

    if (( has_ssh )); then
        log "- Puerto 22 (SSH, típico Linux):"
        log "  TIP: Probar conexión directa (ssh usuario@${TARGET_IP}) o usar Hydra para fuerza bruta controlada."
        log "        También puedes usar ssh-audit o enum de claves débiles."
        log ""
    fi

    if (( has_ftp )); then
        log "- Puerto 21 (FTP):"
        log "  TIP: Probar acceso anónimo (ftp ${TARGET_IP}), revisar permisos de lectura/escritura."
        log "        Usar nmap --script ftp-anon, ftp-brute o Hydra para usuarios/contraseñas."
        log ""
    fi

    if (( has_http )); then
        log "- Puertos HTTP/HTTPS (80,443,8080,8000,8443):"
        log "  TIP: Navegar con el navegador o Burp Suite, usar whatweb/wappalyzer para fingerprint,"
        log "        aplicar fuzzing de rutas con gobuster/ffuf y buscar paneles de login o backups."
        log ""
    fi

    if (( has_smb )); then
        log "- Puertos 139/445 (SMB en Linux/Windows):"
        log "  TIP: Usar smbclient, enum4linux-ng o crackmapexec/netexec para enumerar shares, usuarios y sesiones."
        log "        Revisar permisos débiles en recursos compartidos y probar autenticación con credenciales conocidas."
        log ""
    fi

    if (( has_rdp )); then
        log "- Puerto 3389 (RDP, típico Windows):"
        log "  TIP: Probar conexión con xfreerdp / rdesktop, revisar si exige NLA."
        log "        En escenarios de password spraying, usar Hydra o crowbar con mucho cuidado."
        log ""
    fi

    if (( has_mysql )); then
        log "- Puerto 3306 (MySQL):"
        log "  TIP: Probar conexión con mysql -h ${TARGET_IP} -u root -p o usuarios comunes."
        log "        Usar nmap --script mysql-* para enum de cuentas, bases de datos y configuraciones débiles."
        log ""
    fi

    if (( has_mssql )); then
        log "- Puerto 1433 (MSSQL):"
        log "  TIP: Usar impacket-mssqlclient para conectarte con credenciales válidas."
        log "        Revisar si existe xp_cmdshell habilitado para ejecución de comandos."
        log ""
    fi

    if (( has_smtp )); then
        log "- Puertos 25/587 (SMTP):"
        log "  TIP: Hacer VRFY/EXPN (si están habilitados) para enum de usuarios."
        log "        Usar smtp-user-enum y revisar banners para identificar software y versión."
        log ""
    fi

    if (( has_redis )); then
        log "- Puerto 6379 (Redis):"
        log "  TIP: Intentar conexión sin autenticación con redis-cli -h ${TARGET_IP}."
        log "        Revisar si es posible escribir claves o abusar de configuraciones por defecto."
        log ""
    fi
}

# --- [6] Main ---
main() {
    check_deps
    check_root
    show_banner
    configurar_maquina
    leer_ip_objetivo

    detectar_ttl_y_os "${TARGET_IP}"
    escaneo_nmap_rapido "${TARGET_IP}"

    if [[ -n "${OPEN_PORTS_CSV}" ]]; then
        if ask_yes_no "¿Escanear versiones (-sV -sC)?"; then
            escaneo_nmap_agresivo "${TARGET_IP}" "${OPEN_PORTS_CSV}"
        fi
        generar_droide_vuln "${TARGET_IP}" "${OPEN_PORTS_CSV}"
    fi

    echo
    echo -e "${C_GRN}[i] Puertos detectados:${C_RST} ${OPEN_PORTS_CSV:-Ninguno}"

    if ask_yes_no "¿Ejecutar ENUMWEB en puertos específicos?"; then
        echo -en "${C_YEL}[?] Puertos (ej: 80,8080): ${C_RST}"
        read -r http_ports_input
        
        http_ports_input="${http_ports_input// /}"
        IFS=',' read -r -a HTTP_PORTS <<< "${http_ports_input}"

        for port in "${HTTP_PORTS[@]}"; do
            [[ -z "${port}" ]] && continue
            if [[ ! "${port}" =~ ^[0-9]+$ ]]; then
                echo -e "${C_RED}[!] ${port} no es un número de puerto válido.${C_RST}"
                continue
            fi
            enum_web_port "${TARGET_IP}" "${port}"
        done
    fi

    sugerencias_puertos

    echo
    echo -e "${C_GRN}[i] Log final: ${LOG_FILE}${C_RST}"
    echo -e "${C_BLU}=== HACK THE PLANET ===${C_RST}"
}

main "$@"
