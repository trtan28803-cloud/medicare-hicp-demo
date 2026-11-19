#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Vui lòng chạy với quyền sudo: sudo bash scripts/install-ubuntu.sh"
  exit 1
fi

command -v python3 >/dev/null || { echo "Cần cài đặt Python 3 trước."; exit 1; }
SOURCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="/home/trtan/hicp-demo"
DATA_DIR="/var/lib/hicp-ehr"

echo "[1/6] Dừng dịch vụ hicp-ehr cũ (nếu đang chạy)..."
systemctl stop hicp-ehr 2>/dev/null || true
systemctl disable hicp-ehr 2>/dev/null || true

echo "[2/6] Xóa dữ liệu và thư mục cài đặt cũ để làm sạch môi trường..."
rm -rf /opt/hicp-demo "$DATA_DIR"
if [ "$SOURCE_DIR" != "$TARGET_DIR" ]; then
  rm -rf "$TARGET_DIR"
  mkdir -p "$TARGET_DIR"
  cp -R "$SOURCE_DIR"/. "$TARGET_DIR"/
fi
rm -rf "$TARGET_DIR"/__pycache__

echo "[3/6] Khởi tạo user hệ thống hicp-ehr và thư mục dữ liệu $DATA_DIR..."
id hicp-ehr >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin hicp-ehr
mkdir -p "$DATA_DIR"

echo "[4/6] Khởi tạo 4 tài khoản RBAC mặc định (admin, doctor, nurse, patient)..."
HICP_DATA_DIR="$DATA_DIR" HICP_NONINTERACTIVE="${HICP_NONINTERACTIVE:-1}" python3 "$TARGET_DIR/scripts/setup.py"

chown -R trtan:hicp-ehr "$TARGET_DIR" 2>/dev/null || chown -R root:hicp-ehr "$TARGET_DIR"
chmod -R 750 "$TARGET_DIR"
chmod +x "$TARGET_DIR/app.py" "$TARGET_DIR"/scripts/* "$TARGET_DIR"/deploy/*.sh
[ -d /home/trtan ] && chmod 755 /home/trtan

chown -R hicp-ehr:hicp-ehr "$DATA_DIR"
chmod 750 "$DATA_DIR"
touch "$DATA_DIR/audit.jsonl"
chown hicp-ehr:hicp-ehr "$DATA_DIR/audit.jsonl"
chmod 640 "$DATA_DIR/audit.jsonl"

echo "[5/6] Cấp quyền đọc log cho Wazuh SIEM và cập nhật bộ Rule 100510-100523..."
if id wazuh >/dev/null 2>&1; then
  usermod -aG hicp-ehr wazuh 2>/dev/null || true
  setfacl -m u:wazuh:r "$DATA_DIR/audit.jsonl" 2>/dev/null || true
  if [ -d /var/ossec/etc/rules ]; then
    cp "$TARGET_DIR/deploy/wazuh-lab-rules.xml" /var/ossec/etc/rules/local_rules.xml
    chown root:wazuh /var/ossec/etc/rules/local_rules.xml
    chmod 640 /var/ossec/etc/rules/local_rules.xml
  fi
  # Khai báo nguồn log (audit.jsonl + Suricata eve.json) trong ossec.conf nếu chưa có
  if [ -f /var/ossec/etc/ossec.conf ] && ! grep -q "/var/lib/hicp-ehr/audit.jsonl" /var/ossec/etc/ossec.conf; then
    cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak-hicp
    TARGET_DIR="$TARGET_DIR" python3 - <<'PYEOF'
import os, re
conf = "/var/ossec/etc/ossec.conf"
block = open(os.environ["TARGET_DIR"] + "/deploy/wazuh-localfile.xml", encoding="utf-8").read()
block = re.sub(r"<!--.*?-->", "", block, flags=re.S)
text = open(conf, encoding="utf-8").read()
idx = text.rfind("</ossec_config>")
if idx != -1:
    open(conf, "w", encoding="utf-8").write(text[:idx] + block + chr(10) + text[idx:])
PYEOF
  fi
  systemctl restart wazuh-manager 2>/dev/null || true
fi

echo "[6/6] Kích hoạt dịch vụ Systemd hicp-ehr trên cổng 80..."
install -m 644 "$TARGET_DIR/deploy/hicp-ehr.service" /etc/systemd/system/hicp-ehr.service
systemctl daemon-reload
systemctl enable --now hicp-ehr
systemctl --no-pager status hicp-ehr

echo "======================================================================"
echo "[+] CÀI ĐẶT THÀNH CÔNG MEDICARE EHR v2.2!"
echo "    - Kiểm tra nhanh: wget -qO- http://127.0.0.1/health"
echo "    - Tài khoản mặc định:"
echo "      * admin   / Admin@Hicp2026!   (Quản trị hạ tầng & SIEM - Cấm xem PHI)"
echo "      * doctor  / Doctor@Hicp2026!  (Bác sĩ - Toàn quyền Thêm/Xem/Sửa/Xóa)"
echo "      * nurse   / Nurse@Hicp2026!   (Y tá - Chỉ đọc bệnh án & xem lịch trình)"
echo "      * patient / Patient@Hicp2026! (Bệnh nhân - Cá nhân & Đặt lịch 07h-15h)"
echo "      * doctor_timmach / doctor_noitiet / doctor_tmh (Bác sĩ chuyên khoa - mật khẩu như doctor)"
echo "======================================================================"
