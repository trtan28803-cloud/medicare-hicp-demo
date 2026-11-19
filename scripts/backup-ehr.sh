#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${HICP_DATA_DIR:-/var/lib/hicp-ehr}"
BACKUP_DIR="${HICP_BACKUP_DIR:-/var/backups/hicp-ehr-vault}"
PASSPHRASE="${HICP_BACKUP_KEY:-HICP-Hospital-Offline-Vault-Key-2026}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")

sudo mkdir -p "$BACKUP_DIR"
sudo chmod 700 "$BACKUP_DIR"

TMP_DB="/tmp/ehr_snapshot_${TIMESTAMP}.db"
sqlite3 "${DATA_DIR}/ehr.db" ".backup '${TMP_DB}'"

sudo openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 \
  -in "$TMP_DB" \
  -out "${BACKUP_DIR}/ehr_${TIMESTAMP}.db.enc" \
  -pass "pass:${PASSPHRASE}"

rm -f "$TMP_DB"
sudo chmod 400 "${BACKUP_DIR}/ehr_${TIMESTAMP}.db.enc"
echo "[+] Đã sao lưu và mã hóa AES-256 thành công: ${BACKUP_DIR}/ehr_${TIMESTAMP}.db.enc"