#!/usr/bin/env bash
# Scanner rápido: TTL + Nmap
set -euo pipefail

# --- [0] Validación de dependencias ---
check_deps() {
    for cmd in ping nmap awk; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "[-] Comando requerido no encontrado: $cmd"
            exit 1
        fi
    done
}

# --- [1] Obtener IP objetivo (por argumento o pregunta) ---
obtener_ip() {
    if [[ $# -ge 1 ]]; then
        TARGET_IP="$1"
    else
        read -rp "Ingresa la IP objetivo: " TARGET_IP
    fi

    if [[ -z "${TARGET_IP}" ]]; then
        echo "[-] No ingresaste una IP. Saliendo."
        exit 1
    fi
}

# --- [2] Detectar TTL y sistema operativo probable ---
detectar_ttl_y_os() {
    local host="$1"
    local ttl

    echo "[*] Ping a ${host} para obtener TTL..."
    ttl=$(ping -c1 -W1 "$host" 2>/dev/null | awk -F'ttl=' '/ttl=/{split($2,a," "); print a[1]; exit}')

    if [[ -z "${ttl}" ]]; then
        echo "[!] Sin respuesta ICMP desde ${host}. No se pudo obtener TTL."
        return 1
    fi

    local os="Desconocido"
    if   (( ttl <= 64 ));  then os="Unix/Linux (TTL ≤ 64)"
    elif (( ttl <= 128 )); then os="Windows (TTL ≤ 128)"
    else                       os="Router/Dispositivo de red (TTL > 128)"
    fi

    echo "[+] TTL: ${ttl}"
    echo "[+] SO probable: ${os}"
}

# --- [3] Ejecutar Nmap y extraer puertos abiertos ---
escaneo_nmap_puertos() {
    local host="$1"
    local puertos

    echo "[*] Ejecutando Nmap (T4, SYN, solo puertos abiertos)..."
    echo "    nmap -T4 -sS --open ${host}"
    echo

    puertos=$(nmap -T4 -sS --open -oG - "$host" 2>/dev/null | \
        awk '
        /Ports:/ {
            sub(/.*Ports: /, "")
            n = split($0, a, ",")
            for (i = 1; i <= n; i++) {
                gsub(/^ +/, "", a[i])
                split(a[i], b, "/")
                if (b[2] == "open") {
                    if (puertos != "") {
                        puertos = puertos "," b[1]
                    } else {
                        puertos = b[1]
                    }
                }
            }
        }
        END { print puertos }')

    if [[ -z "${puertos}" ]]; then
        echo "[+] No se detectaron puertos abiertos en ${host}."
    else
        echo "[+] Puertos abiertos (formato limpio):"
        echo "puerto ${puertos}"
    fi
}

# --- [4] Flujo principal ---
main() {
    echo "===== ZT-TOOL: TTL + Nmap Scanner ====="
    check_deps
    obtener_ip "$@"
    echo

    detectar_ttl_y_os "${TARGET_IP}" || echo "[!] Continuando sin info de TTL/OS..."
    echo

    escaneo_nmap_puertos "${TARGET_IP}"
    echo "===== Escaneo finalizado ====="
}

main "$@"
