# MediCare EHR (HICP & Zero Trust) — Tài liệu duy nhất của dự án

Đồ án tốt nghiệp: mô hình mạng y tế an toàn đa chi nhánh (Site-to-Site VPN, IDS/IPS, DLP, SIEM) theo khung **HICP (HHS 405(d))** và **Zero Trust / Least Privilege**.
Ứng dụng là một máy chủ EHR giả lập viết bằng **Python thuần (chỉ thư viện chuẩn, không cần `pip install`)**, lưu dữ liệu bằng SQLite, giao diện HTML/CSS/JS thuần.

---

## 1. Cấu trúc thư mục

```text
hicp-demo/
├── app.py                 # Backend (HTTP server, Auth, RBAC, IDS/IPS theo MAC, OTP, Audit, Lịch hẹn, IoMT, DLP)
├── static/                # Giao diện: index.html, app.js, style.css
├── data_vault/users.json  # Tài khoản mẫu (ehr.db và audit.jsonl do app tự tạo khi chạy)
├── scripts/
│   ├── install-ubuntu.sh        # Cài trọn gói lên Ubuntu Server (systemd + Wazuh)
│   ├── setup.py                 # Khởi tạo 7 tài khoản mặc định
│   ├── test-app.py              # Bộ kiểm thử end-to-end
│   ├── deploy-domain-https.sh   # Bật HTTPS lab / Cloudflare Tunnel / Let's Encrypt
│   ├── dns-lab.py               # Giả lập DNS Tunneling (60 truy vấn *.hicp-demo.invalid)
│   └── backup-ehr.sh            # Sao lưu SQLite mã hóa AES-256
├── deploy/                # Cấu hình hạ tầng: systemd, nginx, Suricata, Wazuh, schema Postgres/MySQL
└── graphify-out/          # Đồ thị tri thức sinh tự động (không thuộc ứng dụng)
```

## 2. Chạy nhanh

Yêu cầu: Python 3.9+ (đã thử trên 3.13).

```bash
# Chạy thử trên máy cá nhân (Windows/Linux)
HICP_PORT=8080 HICP_DATA_DIR=./data python3 app.py     # mở http://127.0.0.1:8080
# PowerShell: $env:HICP_PORT=8080; $env:HICP_DATA_DIR=".\data"; python app.py

# Kiểm thử tự động (tự chọn cổng trống và thư mục tạm, không đụng dữ liệu thật)
python3 scripts/test-app.py        # kết quả mong đợi: dòng "PASS: ..."

# Cài lên Ubuntu Server (VMware) — chạy cổng 80 qua systemd
sudo bash scripts/install-ubuntu.sh
wget -qO- http://127.0.0.1/health  # {"status": "ok", ...}
```

### Biến môi trường

| Biến | Mặc định | Ý nghĩa |
| :-- | :-- | :-- |
| `HICP_HOST` / `HICP_PORT` | `0.0.0.0` / `80` | Địa chỉ và cổng lắng nghe |
| `HICP_DATA_DIR` | `/var/lib/hicp-ehr` | Nơi lưu `ehr.db`, `users.json`, `audit.jsonl` |
| `HICP_PASS_ADMIN/DOCTOR/NURSE/PATIENT` | xem mục 3 | Mật khẩu khởi tạo (**nên đặt lại khi triển khai thật**) |
| `HICP_IOMT_KEY`, `HICP_MFA_SECRET`, `REQUIRE_MFA` | khoá mẫu trong mã, `0` | Khoá thiết bị IoMT, bí mật MFA |
| `TRUST_LOCAL_PROXY` | `0` | `1` khi đứng sau nginx/Cloudflare: tin `X-Forwarded-For`/`CF-Connecting-IP`, bật cờ `Secure` + HSTS |
| `HICP_TLS_CERT`, `HICP_TLS_KEY` | rỗng | Bật HTTPS trực tiếp trong app |
| `HICP_SESSION_TIMEOUT` | `900` | Hết phiên (giây) |
| `HICP_IDS_WARN_WINDOW/THRESHOLD` | `300` / `2` | Cảnh báo IDS: ≥2 lần sai trong 5 phút |
| `HICP_IPS_FAIL_WINDOW/THRESHOLD` | `600` / `5` | Khóa IPS: ≥5 lần sai trong 10 phút |
| `HICP_IPS_BASE_BLOCK`, `HICP_IPS_RECIDIVISM_WINDOW` | `300`, `600` | Thời gian khóa cơ bản; tái phạm thì nhân đôi |
| `HICP_SAVE_COOLDOWN_SECONDS` | `60` | Cooldown giữa hai lần lưu bệnh án |
| `HICP_REVISION_RETENTION_DAYS`, `HICP_REVISION_MIN_KEEP_COUNT` | `15`, `2` | Lưu lịch sử sửa 15 ngày, quá hạn giữ 2 bản gần nhất |
| `HICP_APPOINTMENT_LEAD_MINUTES` | `30` | Đặt lịch trước tối thiểu |

## 3. Tài khoản mặc định (RBAC 4 vai trò)

| Tài khoản | Vai trò | Mật khẩu mặc định | Quyền hạn |
| :-- | :-- | :-- | :-- |
| `admin` | Quản trị | `Admin@Hicp2026!` | Quản lý tài khoản, xem lịch sử sửa (`/api/revisions`), danh sách đen MAC, nhật ký. **Cấm tuyệt đối chạm hồ sơ bệnh án (403, Rule 100517)** |
| `doctor`, `doctor_timmach`, `doctor_noitiet`, `doctor_tmh` | Bác sĩ (Nội TQ / Tim mạch / Nội tiết / TMH) | `Doctor@Hicp2026!` | CRUD bệnh án, xuất CSV, xác nhận/báo huỷ lịch hẹn, xem lịch tuần. Không xem lịch sử sửa |
| `nurse` | Y tá | `Nurse@Hicp2026!` | Chỉ đọc bệnh án và lịch bác sĩ; thêm/sửa/xoá bị 403 (Rule 100518) |
| `patient` | Bệnh nhân (`DEMO-001`) | `Patient@Hicp2026!` | Xem bệnh án của mình, sửa hồ sơ cá nhân, đặt lịch, tự khôi phục mật khẩu qua SĐT `0901000001` + OTP |

## 4. Tính năng bảo mật

| # | Tính năng | Chi tiết |
| :-: | :-- | :-- |
| 1 | IDS/IPS theo MAC | Sai ≥2 lần/5 phút: cảnh báo (Rule 100514). Sai 5 lần/10 phút: khóa thiết bị 300s, tái phạm nhân đôi (Rule 100515). Khóa theo thiết bị chứ không khóa tài khoản, nên bác sĩ vẫn đăng nhập được từ máy khác. MAC không hiển thị trên UI nhưng ghi vào `audit.jsonl` |
| 2 | Băm mật khẩu | PBKDF2-HMAC-SHA256, 200.000 vòng, so sánh hằng thời gian |
| 3 | RBAC và cô lập PHI | 4 vai trò, Admin bị chặn khỏi bệnh án |
| 4 | Y tá chỉ đọc | Mọi ghi vào bệnh án/lịch hẹn bị 403 |
| 5 | Quên mật khẩu bệnh nhân | SĐT + OTP 6 số (hiệu lực 180s, tối đa 5 lần thử), chỉ cho vai trò patient |
| 6 | Audit trail | Diff trước/sau, ghi user, IP, thời gian; chỉ Admin xem |
| 7 | Lưu trữ + cooldown | Giữ mọi bản sửa 15 ngày, quá hạn giữ 2 bản gần nhất; lưu liên tiếp <60s trả 429 |
| 8 | Đặt lịch | Khung 07:00–15:00, trước ≥30 phút, 1 lịch/ngày/tài khoản, chống trùng giờ bác sĩ (409) |
| 9 | Phiên và web | Cookie `HttpOnly` + `SameSite=Strict`, CSRF token, CSP, X-Frame-Options |
| 10 | Chống giả mạo IP | Bỏ qua `X-Real-IP` giả khi `TRUST_LOCAL_PROXY=0` |
| 11 | DLP | Xuất CSV >2 lần/5 phút bị 429; Suricata bắt DNS Tunneling (SID 1001003) |
| 12 | IoMT và sao lưu | Cổng `/api/iomt/telemetry` xác thực bằng `X-Medical-Device-Key`; backup AES-256 |

Sự kiện ghi ra `audit.jsonl` (JSON Lines) để Wazuh thu thập, ví dụ: `admin_phi_access_blocked`, `rbac_medical_record_violation`, `ids_bruteforce_warning`, `ips_mac_temp_blocked`, `record_save_cooldown_blocked`, `appointment_*`, `password_reset_*`, `iomt_alert`, `dlp_export_blocked`. Mật khẩu không bao giờ được ghi vào log (có kiểm thử).

## 5. Kiểm thử

`scripts/test-app.py` khởi động server thật trên cổng ngẫu nhiên với dữ liệu tạm, rồi kiểm tra: static file và chống path traversal, RBAC cả 4 vai trò, OTP, đặt lịch (khung giờ, giới hạn, xác nhận/huỷ), cooldown 429, retention 15 ngày, IDS/IPS (cảnh báo, khóa, tái phạm, tài khoản vẫn dùng được từ MAC khác), chống giả IP, IoMT sai khóa, và đủ 16 sự kiện audit cần thiết.
Lần chạy gần nhất (18/11/2026, Python 3.13): **PASS**. Chưa chạy `node --check static/app.js` vì máy chưa cài Node.

## 6. Hạ tầng lab (VMware)

### Địa chỉ

| Vùng | Thiết bị | Địa chỉ |
| :-- | :-- | :-- |
| WAN giả lập (VMnet tuỳ chỉnh, tắt DHCP) | pfSense HQ / Branch | `192.168.226.133/24` / `.134/24` |
| HQ quản trị | LAN pfSense HQ | `10.110.10.1/24` |
| HQ Staff (VLAN 10) | Gateway / Client | `10.10.10.1` / `10.10.10.100` |
| HQ Server (VLAN 20) | Gateway / Ubuntu (EHR + Wazuh) | `10.20.10.1` / `10.20.10.50` |
| Branch LAN | Gateway / Client | `10.30.10.1` / `10.30.10.100` |
| Đường hầm WireGuard | wg0 HQ / Branch | `10.99.99.1/30` / `10.99.99.2/30` |

### WireGuard Site-to-Site (pfSense 2.7.x)

1. Mỗi router: `VPN > WireGuard > Tunnels > Add`, cổng `51820`, sinh khoá, gán địa chỉ tunnel.
2. Thêm Peer (endpoint là WAN đối diện). Allowed IPs: HQ→Branch `10.99.99.2/32, 10.30.10.0/24`; Branch→HQ `10.99.99.1/32, 10.20.10.0/24, 10.10.10.0/24`.
3. Gán `tun_wg0` thành interface, tạo Gateway và Static Route cho mạng đối diện.
4. Ở WAN: cho phép UDP 51820, tắt *Block private networks* và *Block bogon networks*.
5. Kiểm tra: có *Latest Handshake*; từ Client Branch `curl http://10.20.10.50/health` trả 200.

### Firewall (Default Deny, thứ tự trên xuống, bật Log)

HQ (interface WG/IPsec): Pass TCP `10.30.10.0/24 → 10.20.10.50:80,443`; Pass UDP 53 tới `10.20.10.50`; **Block** `10.30.10.0/24 → 10.10.10.0/24`; Block any còn lại. Branch: chỉ Pass web tới `10.20.10.50` và Internet cần thiết, Block + Log phần còn lại. **Xoá mọi luật Allow-All trước khi demo.**

### Suricata (IDS)

Đặt trên pfSense HQ hoặc Ubuntu Server, lắng nghe interface VPN (thấy lưu lượng đã giải mã), `HOME_NET=[10.10.10.0/24,10.20.10.0/24,10.30.10.0/24]`, nạp `deploy/suricata-lab.rules` (chế độ alert; dùng `suricata-ips.rules` chỉ khi chạy Inline), bật EVE JSON. SID: `1001001` HTTP probe, `1001002` SYN burst, `1001003` DNS Tunneling (≥50 truy vấn/60s), `1001004` ICMP flood. Kiểm tra cú pháp: `suricata -T -c /etc/suricata/suricata.yaml -S deploy/suricata-lab.rules`.

### Wazuh SIEM (trên Ubuntu `10.20.10.50`)

- `scripts/install-ubuntu.sh` chép `deploy/wazuh-lab-rules.xml` thành `local_rules.xml` (Rule 100510–100523) và khai báo `audit.jsonl` + `eve.json` vào `ossec.conf`.
- Nếu Suricata chạy trên pfSense: bật Remote Syslog về `10.20.10.50:514/udp` và thêm khối `<remote>` syslog vào `ossec.conf`.
- Active Response: chép `deploy/wazuh-active-response-ips.sh` thành `/var/ossec/active-response/bin/hicp-ips-block.sh` (`chmod 750`, `chown root:wazuh`), khai báo `<command>` và `<active-response>` cho rule `100515,100516,100522`.
- Kiểm tra: dán một dòng `audit.jsonl` vào `/var/ossec/bin/wazuh-logtest` phải khớp Rule `1005xx`.

### Bản đồ Wazuh Rule

| Rule | Ý nghĩa |
| :-: | :-- |
| 100512 | Xuất CSV |
| 100513 | Đặt lịch ngoài khung giờ |
| 100514 | IDS: nhiều lần đăng nhập sai (Level 8) |
| 100515 | IPS khóa MAC / chặn DLP / cooldown / quá giới hạn đặt lịch (Level 11) |
| 100516 | Cảnh báo IoMT |
| 100517 | Admin chạm PHI (Level 10) |
| 100518 | Vi phạm RBAC (Level 8) |
| 100519 | Tạo/sửa/xoá bệnh án |
| 100520 / 100521 | Suricata: HTTP probe / SYN burst |
| 100522 | DNS Tunneling (Level 12) |
| 100523 | ICMP Ping Flood |

## 7. Ba kịch bản demo và checklist

1. **Zero Trust / phân đoạn mạng** (từ Client Branch): `curl http://10.20.10.50/health` trả 200 và đăng nhập `doctor` được; `ping 10.10.10.100` timeout; pfSense Firewall Log có dòng Block `10.30.10.100 → 10.10.10.100`.
2. **IDS**: `nmap -sS -p 1-1000 10.20.10.50` cho SID 1001002 (Rule 100521); `curl http://10.20.10.50/demo/ids-probe` cho Rule 100520; `ping -f -c 200 10.20.10.50` cho Rule 100523. Lưu ý: nếu firewall chặn ICMP thì Suricata sau firewall không thấy.
3. **DLP**: `python3 scripts/dns-lab.py --resolver 10.20.10.50` cho Rule 100522; Doctor xuất CSV 3 lần thì lần 3 bị 429; sai mật khẩu 5 lần từ Branch thì cảnh báo rồi khóa thiết bị, máy khác vẫn đăng nhập được.

**Checklist trước buổi bảo vệ:** `/health` 200; IDS/IPS MAC (401 rồi 429, không lộ MAC); OTP bệnh nhân; Admin bị 403 ở `/api/patients`; Doctor CRUD; Nurse chỉ đọc; đặt lịch pending → confirmed/cancelled; cooldown 429 và retention; DLP/DNS Tunneling; VPN + firewall + HTTPS (`scripts/deploy-domain-https.sh --lab-https`). Minh chứng nên chụp: VMware Virtual Network Editor, WireGuard handshake, firewall rules và log, Suricata alert, Wazuh Dashboard Rule 100520–100523, giao diện từng vai trò, và dòng `PASS` của `test-app.py`.

## 8. HTTPS và tên miền thật

```bash
sudo bash scripts/deploy-domain-https.sh --lab-https                       # HTTPS nội bộ (cert tự ký, nginx reverse proxy)
sudo bash scripts/deploy-domain-https.sh --cloudflare-domain <ten-mien> [TUNNEL_TOKEN]   # Cloudflare Tunnel
```

Khi đứng sau proxy, đặt `TRUST_LOCAL_PROXY=1`. nginx truyền `X-Client-MAC`, `X-Forwarded-For` tới app (xem `deploy/nginx-https.conf`).

## 9. Vấn đề đã biết và hướng cải tiến (kết quả kiểm tra 18/11/2026)

**Bảo mật**
- **IPS theo MAC có thể bị qua mặt**: MAC lấy từ header `X-Client-MAC` do client tự gửi. Thử 10 lần đăng nhập sai với 10 MAC giả, không lần nào bị khóa. Cần chỉ tin header này khi đến từ proxy/gateway đáng tin, và luôn khóa song song theo IP.
- Mật khẩu mặc định, `HICP_IOMT_KEY`, `HICP_MFA_SECRET` nằm cứng trong mã: cần bắt buộc đặt lại khi triển khai thật.

**Triển khai VMware**
- `install-ubuntu.sh`, `hicp-ehr.service`, `deploy-domain-https.sh` gắn cứng user `trtan`, đường dẫn `/home/trtan/hicp-demo` và IP `10.20.10.50`: cần tham số hoá.
- `install-ubuntu.sh` chạy `rm -rf /var/lib/hicp-ehr`, **mỗi lần cài lại sẽ xoá sạch dữ liệu**: cần tách thành chế độ cài mới và nâng cấp.

**Chạy trên cloud**
- Phiên đăng nhập, bộ đếm IDS/IPS, OTP, danh sách MAC bị khóa nằm trong RAM: không chạy được nhiều instance, mất khi khởi động lại. Cần Redis hoặc DB dùng chung.
- SQLite và `audit.jsonl` trên đĩa cục bộ: cần Postgres (đã có `deploy/schema_postgres_mysql.sql`) và đẩy audit ra stdout.
- Chưa có Dockerfile; chạy cổng 80 cần quyền đặc biệt (container nên dùng 8080); `/health` đã sẵn sàng làm healthcheck, TLS để load balancer đảm nhận.
