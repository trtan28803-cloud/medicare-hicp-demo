#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="/home/trtan/hicp-demo"
if [ ! -d "$PROJECT_DIR" ]; then
  PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
fi

TLS_DIR="/etc/hicp-tls"
WAZUH_DASHBOARD_CFG="/etc/wazuh-dashboard/opensearch_dashboards.yml"
SYSTEMD_UNIT="/etc/systemd/system/hicp-ehr.service"
NGINX_SITE_AVAIL="/etc/nginx/sites-available/medicare-https.conf"
NGINX_SITE_ENABLED="/etc/nginx/sites-enabled/medicare-https.conf"

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Vui lòng chạy script với quyền root (sudo):"
    echo "    sudo bash $0 $*"
    exit 1
  fi
}

usage() {
  cat <<'EOF'
==============================================================================
HƯỚNG DẪN SỬ DỤNG: deploy-domain-https.sh (Hệ thống MediCare v2.2)
==============================================================================
1. Bật HTTPS nội bộ ngay trên máy Lab (Self-Signed SAN TLS + Tách cổng Wazuh):
   sudo bash scripts/deploy-domain-https.sh --lab-https

2. Triển khai với Tên miền thật theo Phương án A (Cloudflare Tunnel Zero Trust):
   sudo bash scripts/deploy-domain-https.sh --cloudflare-domain <ten-mien> [TUNNEL_TOKEN]
   Ví dụ:
     sudo bash scripts/deploy-domain-https.sh --cloudflare-domain medicare-hicp.id.vn
     sudo bash scripts/deploy-domain-https.sh --cloudflare-domain medicare-hicp.id.vn eyJhIjoi...

3. Triển khai trên VPS Cloud có IP Public tĩnh (Nginx + Let's Encrypt Certbot):
   sudo bash scripts/deploy-domain-https.sh --letsencrypt-domain <ten-mien> <email>

4. Khôi phục (Rollback) về cấu hình HTTP cổng 80 ban đầu:
   sudo bash scripts/deploy-domain-https.sh --rollback-http
==============================================================================
EOF
}

# Bước A: Chuyển Wazuh Dashboard từ cổng 443 sang 127.0.0.1:5601 để nhường 443
move_wazuh_dashboard_to_5601() {
  echo "[*] Kiểm tra cấu hình Wazuh Dashboard tại $WAZUH_DASHBOARD_CFG..."
  if [ -f "$WAZUH_DASHBOARD_CFG" ]; then
    cp -a "$WAZUH_DASHBOARD_CFG" "${WAZUH_DASHBOARD_CFG}.bak.$(date +%s)"
    # Cập nhật server.port: 5601
    if grep -qE '^\s*server\.port:' "$WAZUH_DASHBOARD_CFG"; then
      sed -i 's/^\s*server\.port:.*/server.port: 5601/' "$WAZUH_DASHBOARD_CFG"
    else
      echo "server.port: 5601" >> "$WAZUH_DASHBOARD_CFG"
    fi
    # Cập nhật server.host: 127.0.0.1 (chỉ cho phép truy cập qua Reverse Proxy / Tunnel)
    if grep -qE '^\s*server\.host:' "$WAZUH_DASHBOARD_CFG"; then
      sed -i 's/^\s*server\.host:.*/server.host: "127.0.0.1"/' "$WAZUH_DASHBOARD_CFG"
    else
      echo 'server.host: "127.0.0.1"' >> "$WAZUH_DASHBOARD_CFG"
    fi
    echo "[+] Đã chuyển Wazuh Dashboard sang lắng nghe tại https://127.0.0.1:5601"
    systemctl restart wazuh-dashboard 2>/dev/null || true
  else
    echo "[i] Không tìm thấy $WAZUH_DASHBOARD_CFG (bỏ qua bước chuyển cổng Wazuh)."
  fi
}

# Bước B: Cấu hình dịch vụ hicp-ehr chạy nội bộ tại 127.0.0.1:8080
#         và bật TRUST_LOCAL_PROXY=1 để nhận IP thật từ Nginx / Cloudflare
configure_backend_proxy_mode() {
  echo "[*] Cấu hình dịch vụ hicp-ehr lắng nghe tại 127.0.0.1:8080 (TRUST_LOCAL_PROXY=1)..."
  cat > "$SYSTEMD_UNIT" <<EOF
[Unit]
Description=Hệ thống Bệnh viện MediCare (HICP EHR Backend - Proxy Mode)
After=network.target

[Service]
Type=simple
User=hicp-ehr
Group=hicp-ehr
WorkingDirectory=${PROJECT_DIR}
Environment="HICP_HOST=127.0.0.1"
Environment="HICP_PORT=8080"
Environment="TRUST_LOCAL_PROXY=1"
ExecStart=/usr/bin/python3 ${PROJECT_DIR}/app.py
Restart=always
RestartSec=3

ProtectSystem=strict
ProtectHome=false
PrivateTmp=true
ReadWritePaths=/var/lib/hicp-ehr
NoNewPrivileges=true
UMask=0027

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now hicp-ehr
  systemctl restart hicp-ehr
  echo "[+] Dịch vụ hicp-ehr đã chạy tại http://127.0.0.1:8080 (TRUST_LOCAL_PROXY=1)."
}

# Bước C: Khởi tạo chứng chỉ SSL/TLS (Self-Signed SAN) cho Lab & Nginx
generate_self_signed_tls() {
  local domain_extra="${1:-medicare.local}"
  echo "[*] Khởi tạo chứng chỉ TLS tại $TLS_DIR (Hỗ trợ SAN cho 10.20.10.50 & $domain_extra)..."
  mkdir -p "$TLS_DIR"
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout "$TLS_DIR/server.key" \
    -out "$TLS_DIR/server.crt" \
    -subj "/C=VN/ST=HCMC/L=HCMC/O=MediCare-HICP/CN=10.20.10.50" \
    -addext "subjectAltName=IP:10.20.10.50,DNS:localhost,DNS:medicare.local,DNS:siem.medicare.local,DNS:medicare.${domain_extra},DNS:siem.${domain_extra}"
  chmod 600 "$TLS_DIR/server.key"
  chmod 644 "$TLS_DIR/server.crt"
  echo "[+] Đã tạo chứng chỉ TLS: $TLS_DIR/server.crt & $TLS_DIR/server.key"
}

# Bước D: Cấu hình Nginx Reverse Proxy cho cả MediCare EHR & Wazuh SIEM
configure_nginx_reverse_proxy() {
  local base_domain="${1:-medicare.local}"
  local medicare_host="medicare.${base_domain}"
  local siem_host="siem.${base_domain}"
  if [ "$base_domain" = "medicare.local" ]; then
    medicare_host="10.20.10.50 medicare.local"
    siem_host="siem.medicare.local"
  fi

  if ! command -v nginx >/dev/null 2>&1; then
    echo "[*] Đang cài đặt Nginx..."
    apt-get update -y && apt-get install -y nginx
  fi

  cat > "$NGINX_SITE_AVAIL" <<EOF
# Tự động sinh bởi deploy-domain-https.sh
server {
    listen 80;
    server_name 10.20.10.50 ${medicare_host} _;

    # Giữ nguyên endpoint /demo/ids-probe chạy HTTP thuần để Suricata IDS (VLAN 20)
    # đọc được chuỗi "HICP-IDS-TEST" và kích hoạt cảnh báo SID 1001001.
    location = /demo/ids-probe {
        proxy_pass http://127.0.0.1:8080/demo/ids-probe;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto http;
    }

    location = /health {
        proxy_pass http://127.0.0.1:8080/health;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

# Subdomain 1: Hệ thống Bệnh viện MediCare (HTTPS 443 -> 127.0.0.1:8080)
server {
    listen 443 ssl http2;
    server_name 10.20.10.50 ${medicare_host};

    ssl_certificate     ${TLS_DIR}/server.crt;
    ssl_certificate_key ${TLS_DIR}/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    client_max_body_size 32k;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header CF-Connecting-IP \$http_cf_connecting_ip;
        proxy_set_header X-Client-MAC \$http_x_client_mac;
    }
}

# Subdomain 2 & Cổng 8443: Wazuh SIEM Dashboard (HTTPS -> 127.0.0.1:5601)
server {
    listen 443 ssl http2;
    listen 8443 ssl http2;
    server_name ${siem_host};

    ssl_certificate     ${TLS_DIR}/server.crt;
    ssl_certificate_key ${TLS_DIR}/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass https://127.0.0.1:5601;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

  rm -f /etc/nginx/sites-enabled/default
  ln -sf "$NGINX_SITE_AVAIL" "$NGINX_SITE_ENABLED"
  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx
  echo "[+] Đã kích hoạt Nginx Reverse Proxy trên cổng 80, 443 và 8443."
}

# Bước E: Cài đặt & Cấu hình Cloudflare Tunnel (Phương án A cho tên miền thật)
setup_cloudflare_tunnel() {
  local domain="$1"
  local token="${2:-}"

  echo "[*] Kiểm tra công cụ cloudflared (Cloudflare Zero Trust Tunnel)..."
  if ! command -v cloudflared >/dev/null 2>&1; then
    echo "[*] Đang tải và cài đặt gói cloudflared cho Ubuntu (amd64)..."
    curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o /tmp/cloudflared.deb
    dpkg -i /tmp/cloudflared.deb
    rm -f /tmp/cloudflared.deb
  fi

  mkdir -p /etc/cloudflared
  cat > /etc/cloudflared/config.yml.example <<EOF
# File cấu hình mẫu Cloudflare Tunnel (/etc/cloudflared/config.yml)
# Tên miền của bạn: ${domain}
tunnel: <TUNNEL_UUID_CUA_BAN>
credentials-file: /root/.cloudflared/<TUNNEL_UUID_CUA_BAN>.json

ingress:
  # 1. Cổng thông tin Bệnh viện MediCare -> Backend Python nội bộ
  - hostname: medicare.${domain}
    service: http://127.0.0.1:8080
    originRequest:
      noTLSVerify: true

  # 2. Cổng giám sát Wazuh SIEM Dashboard -> Wazuh nội bộ cổng 5601
  - hostname: siem.${domain}
    service: https://127.0.0.1:5601
    originRequest:
      noTLSVerify: true

  # 3. Rule mặc định bắt buộc của Cloudflare Tunnel
  - service: http_status:404
EOF

  if [ -n "$token" ]; then
    echo "[*] Đang đăng ký dịch vụ Cloudflare Tunnel bằng Token..."
    cloudflared service install "$token" || true
    systemctl enable --now cloudflared
    echo "[+] Đã kích hoạt dịch vụ cloudflared thành công!"
  else
    cat <<EOF
==============================================================================
[+] ĐÃ CHUẨN BỊ XONG HẠ TẦNG CHO TÊN MIỀN: ${domain}
------------------------------------------------------------------------------
Khi bạn đã mua tên miền "${domain}" và thêm vào tài khoản Cloudflare miễn phí,
bạn chỉ cần thực hiện 1 trong 2 cách sau:

CÁCH 1 (Nhanh nhất - Qua giao diện Web Cloudflare Zero Trust):
  1. Vào https://one.dash.cloudflare.com -> Networks -> Tunnels -> Create a tunnel
  2. Đặt tên tunnel: "medicare-hq-tunnel" -> Copy chuỗi TOKEN mà Cloudflare cấp.
  3. Chạy lại lệnh:
       sudo bash scripts/deploy-domain-https.sh --cloudflare-domain ${domain} <TOKEN>
  4. Trong tab "Public Hostname" trên Cloudflare, thêm 2 dòng:
       - Subdomain: medicare | Domain: ${domain} | Service: HTTP://127.0.0.1:8080
       - Subdomain: siem     | Domain: ${domain} | Service: HTTPS://127.0.0.1:5601 (Bật No TLS Verify)

CÁCH 2 (Qua dòng lệnh CLI trên Ubuntu Server):
  1. Đăng nhập Cloudflare:   cloudflared tunnel login
  2. Tạo tunnel:             cloudflared tunnel create medicare-lab
  3. Trỏ DNS tự động:
       cloudflared tunnel route dns medicare-lab medicare.${domain}
       cloudflared tunnel route dns medicare-lab siem.${domain}
  4. Chỉnh UUID trong /etc/cloudflared/config.yml.example -> lưu thành /etc/cloudflared/config.yml
  5. Chạy dịch vụ:           sudo cloudflared service install && sudo systemctl start cloudflared
==============================================================================
EOF
  fi
}

# Bước F: Khôi phục (Rollback) về cấu hình HTTP cổng 80 mặc định
rollback_to_http() {
  echo "[*] Đang khôi phục về chế độ HTTP cổng 80 trực tiếp..."
  systemctl stop nginx 2>/dev/null || true
  rm -f "$NGINX_SITE_ENABLED"
  install -m 644 "$PROJECT_DIR/deploy/hicp-ehr.service" "$SYSTEMD_UNIT"
  systemctl daemon-reload
  systemctl restart hicp-ehr
  echo "[+] Đã khôi phục dịch vụ hicp-ehr lắng nghe trực tiếp trên cổng 80 (HTTP)."
}

# ĐIỀU PHỐI THAM SỐ DÒNG LỆNH
MODE="${1:-}"
case "$MODE" in
  --lab-https)
    require_root "$@"
    move_wazuh_dashboard_to_5601
    configure_backend_proxy_mode
    generate_self_signed_tls "medicare.local"
    configure_nginx_reverse_proxy "medicare.local"
    echo "======================================================================"
    echo "[+] HOÀN TẤT BẬT HTTPS TRONG MÔI TRƯỜNG LAB!"
    echo "    - Web Bệnh viện MediCare : https://10.20.10.50"
    echo "    - Wazuh SIEM Dashboard   : https://10.20.10.50:8443 (hoặc https://siem.medicare.local)"
    echo "    - Suricata IDS Probe     : http://10.20.10.50/demo/ids-probe (HTTP cổng 80)"
    echo "======================================================================"
    ;;

  --cloudflare-domain)
    require_root "$@"
    DOMAIN="${2:-}"
    CF_TOKEN="${3:-}"
    if [ -z "$DOMAIN" ]; then
      echo "[!] Thiếu tên miền. Ví dụ: sudo bash $0 --cloudflare-domain medicare-hicp.id.vn"
      exit 1
    fi
    move_wazuh_dashboard_to_5601
    configure_backend_proxy_mode
    generate_self_signed_tls "$DOMAIN"
    configure_nginx_reverse_proxy "$DOMAIN"
    setup_cloudflare_tunnel "$DOMAIN" "$CF_TOKEN"
    ;;

  --letsencrypt-domain)
    require_root "$@"
    DOMAIN="${2:-}"
    EMAIL="${3:-}"
    if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
      echo "[!] Thiếu tên miền hoặc email. Ví dụ: sudo bash $0 --letsencrypt-domain medicare-hicp.id.vn admin@gmail.com"
      exit 1
    fi
    move_wazuh_dashboard_to_5601
    configure_backend_proxy_mode
    generate_self_signed_tls "$DOMAIN"
    configure_nginx_reverse_proxy "$DOMAIN"
    apt-get update -y && apt-get install -y certbot python3-certbot-nginx
    certbot --nginx -d "medicare.${DOMAIN}" -d "siem.${DOMAIN}" --non-interactive --agree-tos -m "$EMAIL" --redirect
    echo "[+] Đã cấp chứng chỉ Let's Encrypt thành công cho medicare.${DOMAIN} và siem.${DOMAIN}!"
    ;;

  --rollback-http)
    require_root "$@"
    rollback_to_http
    ;;

  *)
    usage
    exit 0
    ;;
esac
