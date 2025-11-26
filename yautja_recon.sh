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

    echo -e "${C_GRN}[+] Directorio de salida Nmap: ${OUTPUT_DIR}${C_RST}"
    echo -e "${C_GRN}[+] Log de resultados: ${LOG_FILE}${C_RST}"
    echo
}

leer_ip_objetivo() {
    echo -e -n "${C_YEL}[?] Ingresa la IP o dominio a analizar: ${C_RST}"
    read -r TARGET_IP

    if [[ -z "${TARGET_IP}" ]]; then
        echo -e "${C_RED}[!] Debes ingresar una IP o dominio válido.${C_RST}"
        exit 1
    fi

    echo -e "${C_YEL}[TARGET]: ${TARGET_IP}${C_RST}"
    echo

    {
        echo "IP objetivo: ${TARGET_IP}"
        echo
    } >> "${LOG_FILE}"
}

# --- [3] Fases principales de Nmap ---
detectar_ttl_y_os() {
    local host="$1"
    echo -e "${C_BLU}[*] FASE 1: Detectando OS (TTL)${C_RST}"
    local ttl
    ttl=$(ping -c1 -W1 "$host" 2>/dev/null | awk -F'ttl=' '/ttl=/{split($2,a," "); print a[1]; exit}')

    if [[ -z "${ttl}" ]]; then
        echo -e "${C_YEL}[!] Host no responde a ping (usando -Pn por defecto).${C_RST}"
        echo "Detección de OS (TTL): sin respuesta a ping." >> "${LOG_FILE}"
        return
    fi

    local os="Desconocido"
    if    (( ttl <= 64 ));  then os="Linux/Unix (TTL: ${ttl})"
    elif (( ttl <= 128 )); then os="Windows (TTL: ${ttl})"
    else                        os="Otro (TTL: ${ttl})"
    fi

    echo -e "${C_GRN}[+] Target: ${os}${C_RST}"

    {
        echo "Detección de OS (TTL): ${os}"
    } >> "${LOG_FILE}"
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
        echo "Puertos abiertos: ninguno detectado." >> "${LOG_FILE}"
        return
    fi

    local puertos_csv
    puertos_csv=$(echo "${puertos_nl}" | paste -sd ',' -)
    OPEN_PORTS_CSV="${puertos_csv}"

    echo -e "${C_GRN}[+] Puertos descubiertos:${C_RST} ${puertos_csv}"
    echo
}

escaneo_nmap_agresivo() {
    local host="$1"
    local port_list="$2"
    local base_name="${host}_version_scan"
    
    preparar_salida "${base_name}"
    local output_base="${OUTPUT_DIR}/${base_name}"

    echo
    echo -e "${C_BLU}[*] FASE 3A: Fingerprinting de Servicios (-sV -sC)${C_RST}"
    imprimir_explicacion "Esta fase detecta servicios y versiones. El resultado se guarda y se genera un HTML legible."

    local cmd="nmap -n -Pn -sV -sC -vv --min-rate 3000 -p${port_list} -oA ${output_base} ${host}"
    imprimir_comando "$cmd"
    
    nmap -n -Pn -sV -sC -vv --min-rate 3000 -p"${port_list}" -oA "${output_base}" "${host}"
    SV_RUN=1

    generar_html "${output_base}.xml" "${output_base}.html"

    # Log de puertos con servicio + versión
    if [[ -f "${output_base}.nmap" ]]; then
        {
            echo
            echo "Puertos abiertos:"
            # Ej: 22/tcp open ssh OpenSSH 7.6p1 Ubuntu
            awk '/^[0-9]+\/tcp/ {
                port=$1; state=$2; service=$3;
                $1=""; $2=""; $3="";
                sub(/^ +/, "");
                print port" "service" "$0
            }' "${output_base}.nmap"
            echo
        } >> "${LOG_FILE}"
    fi
}

generar_html() {
    local xml_in="$1"
    local html_out="$2"
    echo
    if [[ -f "${xml_in}" ]]; then
        local cmd="xsltproc ${xml_in} -o ${html_out}"
        imprimir_comando "$cmd"
        xsltproc "${xml_in}" -o "${html_out}" 2>/dev/null
        echo -e "${C_GRN}[OK] HTML Generado: ${html_out}${C_RST}"
        echo "Reporte HTML generado: ${html_out}" >> "${LOG_FILE}"
    else
        echo -e "${C_RED}[ERROR] Falló Nmap, no hay XML para generar HTML.${C_RST}"
        echo "Reporte HTML: NO generado (no se encontró XML)." >> "${LOG_FILE}"
    fi
}

# --- [3B] Generar droide para escaneo de vulnerabilidades ---
generar_droide_vuln() {
    local host="$1"
    local port_list="$2"

    if [[ -z "${port_list}" ]]; then
        return
    fi

    local droid_path="${MACHINE_DIR}/droid.sh"

    cat > "${droid_path}" <<EOF
#!/usr/bin/env bash
#
# droid.sh - Escáner de vulnerabilidades (Nmap --script vuln) generado por 0xAlienSec
# Ejecutar en otra terminal: ./droid.sh (dentro de la carpeta de la máquina)
#
set -euo pipefail

C_GRN="\e[32m"
C_CYN="\e[36m"
C_RST="\e[0m"

HOST="${host}"
PORT_LIST="${port_list}"
OUTPUT_DIR="nmap"
BASE_NAME="\${HOST}_vuln_scan"

echo -e "\${C_CYN}[*] Ejecutando escaneo de vulnerabilidades (Modo CTF Rápido) sobre \${HOST} (puertos: \${PORT_LIST})\${C_RST}"

echo -e "\${C_GRN}[>] Comando:\${C_RST} nmap -n -Pn --min-rate 3000 -T4 --script vuln --script-timeout 20s -vv -p\${PORT_LIST} -oA \${OUTPUT_DIR}/\${BASE_NAME} \${HOST}"

nmap -n -Pn --min-rate 3000 -T4 --script vuln --script-timeout 20s -vv -p"\${PORT_LIST}" -oA "\${OUTPUT_DIR}/\${BASE_NAME}" "\${HOST}"

if [[ -f "\${OUTPUT_DIR}/\${BASE_NAME}.xml" ]]; then
    echo -e "\${C_GRN}[>] Generando HTML:\${C_RST} xsltproc \${OUTPUT_DIR}/\${BASE_NAME}.xml -o \${OUTPUT_DIR}/\${BASE_NAME}.html"
    xsltproc "\${OUTPUT_DIR}/\${BASE_NAME}.xml" -o "\${OUTPUT_DIR}/\${BASE_NAME}.html"
fi

echo -e "\${C_GRN}[OK] Escaneo de vulnerabilidades finalizado. Revisa: \${OUTPUT_DIR}/\${BASE_NAME}.*\${C_RST}"
EOF

    chmod +x "${droid_path}"

    echo -e "${C_GRN}[+] Droide de vulnerabilidades generado: ${droid_path}${C_RST}"
    {
        echo
        echo "Droide de vulnerabilidades generado: ${droid_path}"
        echo "Para ejecutarlo: cd ${MACHINE_DIR} && ./droid.sh"
    } >> "${LOG_FILE}"

    echo
    echo -e "${C_YEL}[VULNS] Para un escaneo más profundo de vulnerabilidades te recomendamos ejecutar el droide:${C_RST}"
    echo -e "        cd ${MACHINE_DIR} && ./droid.sh"
    echo
}

# --- [4] ENUMWEB por puerto HTTP ---
enum_web_port() {
    local host="$1"
    local port="$2"

    check_web_deps

    local web_dir="${MACHINE_DIR}/otros/enum_${host}_${port}"
    echo
    echo -e "${C_BLU}[*] FASE 4: ENUMWEB sobre ${host}:${port}${C_RST}"
    echo -e "${C_GRN}[+] Carpeta de resultados: ${web_dir}${C_RST}"
    mkdir -p "${web_dir}"

    local base_url="http://${host}:${port}"

    {
        echo
        echo "=== ENUMWEB sobre ${host}:${port} ==="
        echo "Base URL: ${base_url}"
    } >> "${LOG_FILE}"

    echo ""
    echo "============================"
    echo "[1] Escaneo de versión (whatweb)"
    echo "============================"
    local cmd1="whatweb ${base_url}"
    imprimir_comando "$cmd1"

    # Manejo suave por si whatweb falla
    set +e
    whatweb "${base_url}" | tee "${web_dir}/whatweb.txt"
    local ww_status=$?
    set -e

    if (( ww_status != 0 )); then
        echo -e "${C_RED}[-] Error ejecutando whatweb (exit code ${ww_status}). Revisa la instalación de whatweb.${C_RST}"
        echo "whatweb: fallo de ejecución (exit code ${ww_status})." >> "${LOG_FILE}"
    fi

    echo ""
    echo "============================"
    echo "[2] Enumeración de Directorios (Gobuster)"
    echo "============================"
    imprimir_explicacion "Fuzzing de rutas web. Ajusta el diccionario según el contexto (CTF / real)."

    local default_wordlist="/usr/share/wordlists/dirb/common.txt"
    local wordlist=""
    local gobuster_file="${web_dir}/gobuster.txt"

    echo -e -n "${C_YEL}[?] ¿Deseas usar el diccionario por defecto (${default_wordlist})? [s/N]: ${C_RST}"
    read -r use_default

    if [[ "${use_default,,}" =~ ^(s|si|y|yes|1)$ ]]; then
        wordlist="${default_wordlist}"
    else
        echo -e -n "${C_YEL}[?] Ruta del diccionario a usar (ej: /usr/share/wordlists/dirb/common.txt): ${C_RST}"
        read -r wordlist
    fi

    if [[ ! -f "${wordlist}" ]]; then
        echo -e "${C_RED}[-] Archivo inexistente o ruta inválida: ${wordlist}${C_RST}"
        echo "Fuzzing (Gobuster) en ${host}:${port}: NO ejecutado (wordlist inválida: ${wordlist})." >> "${LOG_FILE}"
    else
        local cmd2="gobuster dir -u ${base_url} -w ${wordlist} -x txt,php,zip -s 200,204,301,302,307,401,403 -b \"\" -t 80 -k -o ${gobuster_file}"
        imprimir_comando "$cmd2"
        gobuster dir -u "${base_url}" -w "${wordlist}" -x txt,php,zip \
            -s 200,204,301,302,307,401,403 -b "" -t 80 -k -o "${gobuster_file}"

        local hits_count
        hits_count=$(grep -E 'Status:' "${gobuster_file}" 2>/dev/null | wc -l || true)

        if (( hits_count > 0 )); then
            {
                echo "Fuzzing (Gobuster) en ${host}:${port}: ${hits_count} URLs encontradas."
                echo "URLs principales:"
                grep -E 'Status:' "${gobuster_file}" 2>/dev/null | head -5
            } >> "${LOG_FILE}"
        else
            echo "Fuzzing (Gobuster) en ${host}:${port}: sin resultados relevantes." >> "${LOG_FILE}"
        fi
    fi

    echo ""
    echo "============================"
    echo "[3] Buscando archivos sensibles"
    echo "============================"

    local SENSITIVE=( "robots.txt" ".git" ".env" "sitemap.xml" "server-status" )
    local any_sensitive=0

    for file in "${SENSITIVE[@]}"; do
        local url="${base_url}/${file}"
        local status
        status=$(curl -o /dev/null --silent -Iw "%{http_code}" "${url}")
        
        if [ "${status}" != "404" ]; then
            any_sensitive=1
            echo "[+] Encontrado: ${url} (Status: ${status})" | tee -a "${web_dir}/sensitive_files.txt"
            echo "Archivo sensible: ${url} (Status: ${status})" >> "${LOG_FILE}"
        fi
    done

    if (( any_sensitive == 0 )); then
        echo "No se identificaron archivos sensibles en ${host}:${port}." >> "${LOG_FILE}"
    fi

    echo ""
    echo -e "${C_GRN}[+] ENUMWEB completado sobre ${host}:${port}. Revisa: ${web_dir}${C_RST}"
}

# --- [5] Sugerencias según puertos abiertos ---
sugerencias_puertos() {
    if [[ -z "${OPEN_PORTS_CSV}" ]]; then
        return
    fi

    local has_ssh=0 has_ftp=0 has_http=0 has_smb=0 has_rdp=0 has_mysql=0 has_mssql=0 has_smtp=0 has_redis=0

    IFS=',' read -r -a PORT_ARRAY <<< "${OPEN_PORTS_CSV}"

    for p in "${PORT_ARRAY[@]}"; do
        case "${p}" in
            22)   has_ssh=1 ;;
            21)   has_ftp=1 ;;
            80|443|8080|8000|8443) has_http=1 ;;
            139|445) has_smb=1 ;;
            3389) has_rdp=1 ;;
            3306) has_mysql=1 ;;
            1433) has_mssql=1 ;;
            25|587) has_smtp=1 ;;
            6379) has_redis=1 ;;
        esac
    done

    {
        echo
        echo "=== Sugerencias de próximos pasos (no obligatorias) ==="
        echo "DISCLAIMER: Estas sugerencias son orientativas para laboratorio/CTF."
        echo "No son comandos que deban ejecutarse siempre en un entorno real."
        echo

        if (( has_ssh )); then
            echo "- Puerto 22 (SSH, típico Linux):"
            echo "  TIP: Probar conexión directa (ssh usuario@${TARGET_IP}) o usar Hydra para fuerza bruta controlada."
            echo "       También puedes usar ssh-audit o enum de claves débiles."
            echo
        fi

        if (( has_ftp )); then
            echo "- Puerto 21 (FTP):"
            echo "  TIP: Probar acceso anónimo (ftp ${TARGET_IP}), revisar permisos de lectura/escritura."
            echo "       Usar nmap --script ftp-anon, ftp-brute o Hydra para usuarios/contraseñas."
            echo
        fi

        if (( has_http )); then
            echo "- Puertos HTTP/HTTPS (80,443,8080,8000,8443):"
            echo "  TIP: Navegar con el navegador o Burp Suite, usar whatweb/wappalyzer para fingerprint,"
            echo "       aplicar fuzzing de rutas con gobuster/ffuf y buscar paneles de login o backups."
            echo
        fi

        if (( has_smb )); then
            echo "- Puertos 139/445 (SMB en Linux/Windows):"
            echo "  TIP: Usar smbclient, enum4linux-ng o crackmapexec/netexec para enumerar shares, usuarios y sesiones."
            echo "       Revisar permisos débiles en recursos compartidos y probar autenticación con credenciales conocidas."
            echo
        fi

        if (( has_rdp )); then
            echo "- Puerto 3389 (RDP, típico Windows):"
            echo "  TIP: Probar conexión con xfreerdp / rdesktop, revisar si exige NLA."
            echo "       En escenarios de password spraying, usar Hydra o crowbar con mucho cuidado."
            echo
        fi

        if (( has_mysql )); then
            echo "- Puerto 3306 (MySQL):"
            echo "  TIP: Probar conexión con mysql -h ${TARGET_IP} -u root -p o usuarios comunes."
            echo "       Usar nmap --script mysql-* para enum de cuentas, bases de datos y configuraciones débiles."
            echo
        fi

        if (( has_mssql )); then
            echo "- Puerto 1433 (MSSQL):"
            echo "  TIP: Usar impacket-mssqlclient para conectarte con credenciales válidas."
            echo "       Revisar si existe xp_cmdshell habilitado para ejecución de comandos."
            echo
        fi

        if (( has_smtp )); then
            echo "- Puertos 25/587 (SMTP):"
            echo "  TIP: Hacer VRFY/EXPN (si están habilitados) para enum de usuarios."
            echo "       Usar smtp-user-enum y revisar banners para identificar software y versión."
            echo
        fi

        if (( has_redis )); then
            echo "- Puerto 6379 (Redis):"
            echo "  TIP: Intentar conexión sin autenticación con redis-cli -h ${TARGET_IP}."
            echo "       Revisar si es posible escribir claves o abusar de configuraciones por defecto."
            echo
        fi
    } >> "${LOG_FILE}"
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
        echo -e -n "${C_YEL}[?] ¿Escanear versiones (-sV -sC) sobre estos puertos? [s/N]: ${C_RST}"
        read -r choice_ver
        if [[ "${choice_ver,,}" =~ ^(s|si|y|yes|1)$ ]]; then
            escaneo_nmap_agresivo "${TARGET_IP}" "${OPEN_PORTS_CSV}"
        else
            {
                echo
                echo "Puertos abiertos (sin -sV): ${OPEN_PORTS_CSV}"
                echo
            } >> "${LOG_FILE}"
        fi
        echo

        generar_droide_vuln "${TARGET_IP}" "${OPEN_PORTS_CSV}"
    fi

    echo
    echo -e "${C_GRN}[i] Puertos abiertos detectados:${C_RST} ${OPEN_PORTS_CSV:-N/D}"
    echo -e -n "${C_YEL}[?] ¿Ejecutar ENUMWEB (whatweb + gobuster + archivos sensibles) sobre uno o varios puertos HTTP? [s/N]: ${C_RST}"
    read -r choice_web

    if [[ "${choice_web,,}" =~ ^(s|si|y|yes|1)$ ]]; then
        echo -e -n "${C_YEL}[?] Indica el/los puertos HTTP a analizar (ej: 80,8080,8000,8443): ${C_RST}"
        read -r http_ports_input

        http_ports_input="${http_ports_input// /}"
        IFS=',' read -r -a HTTP_PORTS <<< "${http_ports_input}"

        for port in "${HTTP_PORTS[@]}"; do
            if [[ -z "${port}" ]]; then
                continue
            fi
            if [[ ! "${port}" =~ ^[0-9]+$ ]]; then
                echo -e "${C_RED}[-] Puerto inválido: ${port}${C_RST}"
                continue
            fi
            enum_web_port "${TARGET_IP}" "${port}"
        done
    fi

    sugerencias_puertos

    echo
    echo -e "${C_GRN}[i] Log resumido de resultados disponible en: ${LOG_FILE}${C_RST}"
    echo -e "${C_BLU}=== DONE ===${C_RST}"
}

main "$@"
