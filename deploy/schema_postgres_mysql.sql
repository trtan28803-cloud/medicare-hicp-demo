-- ============================================================================
-- HỆ THỐNG QUẢN LÝ BỆNH VIỆN MEDICARE (HICP & ZERO TRUST V2.1)
-- Database Schema (Compatible with PostgreSQL / MySQL / SQLite)
-- ============================================================================

-- 1. Bảng Người dùng & Phân quyền (Users & RBAC)
-- Bổ sung trường department (Khoa khám và điều trị cho Bác sĩ & Y tá)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(64) NOT NULL UNIQUE,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'doctor', 'nurse', 'patient')),
    password_salt VARCHAR(64) NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    full_name VARCHAR(120) NOT NULL DEFAULT '',
    department VARCHAR(80) NOT NULL DEFAULT '',
    birth_year INTEGER NOT NULL DEFAULT 1990,
    phone VARCHAR(32) NOT NULL DEFAULT '',
    address VARCHAR(255) NOT NULL DEFAULT '',
    linked_patient_id VARCHAR(32) DEFAULT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at VARCHAR(32) NOT NULL,
    updated_at VARCHAR(32) NOT NULL
);

-- 2. Bảng Hồ sơ Bệnh án Điện tử (Medical_Records)
-- Bổ sung trường attending_doctor (Tên Bác sĩ điều trị)
CREATE TABLE IF NOT EXISTS medical_records (
    id VARCHAR(32) PRIMARY KEY,
    patient_user_id INTEGER DEFAULT NULL,
    full_name VARCHAR(120) NOT NULL,
    birth_year INTEGER NOT NULL,
    phone VARCHAR(32) NOT NULL DEFAULT '',
    address VARCHAR(255) NOT NULL DEFAULT '',
    site VARCHAR(32) NOT NULL DEFAULT 'HQ',
    diagnosis TEXT NOT NULL,
    treatment_plan TEXT NOT NULL DEFAULT '',
    care_note TEXT NOT NULL DEFAULT '',
    attending_doctor VARCHAR(120) NOT NULL DEFAULT 'BS.CKI Trần Minh Quân',
    updated_at VARCHAR(32) NOT NULL,
    updated_by VARCHAR(64) NOT NULL,
    last_saved_epoch REAL NOT NULL DEFAULT 0,
    FOREIGN KEY (patient_user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- 3. Bảng Lịch sử Chỉnh sửa Hồ sơ Bệnh án (Record_Revisions - Diff & Retention Policy)
CREATE TABLE IF NOT EXISTS record_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id VARCHAR(32) NOT NULL,
    user_id INTEGER NOT NULL,
    username VARCHAR(64) NOT NULL,
    role VARCHAR(20) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    action VARCHAR(32) NOT NULL CHECK (action IN ('CREATE', 'UPDATE', 'DELETE')),
    changed_fields TEXT NOT NULL,
    old_values_json TEXT NOT NULL,
    new_values_json TEXT NOT NULL,
    diff_summary TEXT NOT NULL,
    edited_at VARCHAR(32) NOT NULL,
    edited_epoch REAL NOT NULL,
    FOREIGN KEY (record_id) REFERENCES medical_records(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_revisions_record_epoch ON record_revisions(record_id, edited_epoch DESC);

-- 4. Bảng Nhật ký Kiểm toán & Giám sát An ninh (Audit_Logs)
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp VARCHAR(32) NOT NULL,
    user_id INTEGER DEFAULT NULL,
    username VARCHAR(64) NOT NULL,
    role VARCHAR(20) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    event VARCHAR(64) NOT NULL,
    target VARCHAR(128) NOT NULL,
    status INTEGER NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_source_ip ON audit_logs(source_ip);

-- 5. Bảng Đặt lịch Khám bệnh & Lịch trình Bác sĩ (Appointments)
-- Trạng thái (status): 'pending' (Đang chờ xác nhận), 'confirmed' (Đã xác nhận), 'cancelled' (Lịch đã huỷ)
CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username VARCHAR(64) NOT NULL,
    patient_id VARCHAR(32) DEFAULT NULL,
    patient_name VARCHAR(120) NOT NULL,
    branch VARCHAR(32) NOT NULL DEFAULT 'HQ',
    department VARCHAR(80) NOT NULL DEFAULT 'Nội tổng quát',
    doctor_username VARCHAR(64) NOT NULL DEFAULT '',
    doctor_name VARCHAR(120) NOT NULL DEFAULT '',
    appointment_date VARCHAR(10) NOT NULL,
    appointment_time VARCHAR(5) NOT NULL,
    reason TEXT NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'pending',
    source_ip VARCHAR(45) NOT NULL,
    created_at VARCHAR(32) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, appointment_date)
);

CREATE INDEX IF NOT EXISTS idx_appointments_user_date ON appointments(user_id, appointment_date);
CREATE INDEX IF NOT EXISTS idx_appointments_doctor_date ON appointments(doctor_username, appointment_date);

-- 6. Bảng Danh sách đen IPS Khóa Thiết bị theo Địa chỉ MAC (mac_blacklist)
-- Dùng cho cơ chế IPS chống Brute-Force & DDoS:
--   + Không khóa tài khoản người dùng (để bác sĩ/bệnh nhân vẫn đăng nhập được trên thiết bị hợp lệ khác).
--   + Khóa thiết bị theo Địa chỉ MAC trong 5 phút (300s) khi nhập sai quá 5 lần trong 10 phút.
--   + Tăng gấp đôi thời gian khóa (lũy tiến: 5p -> 10p -> 20p...) nếu tái phạm trong vòng 10 phút kế tiếp.
CREATE TABLE IF NOT EXISTS mac_blacklist (
    mac_address VARCHAR(32) PRIMARY KEY,
    last_ip VARCHAR(45) NOT NULL DEFAULT '',
    last_username VARCHAR(64) NOT NULL DEFAULT '',
    strike_count INTEGER NOT NULL DEFAULT 1,
    fail_count INTEGER NOT NULL DEFAULT 0,
    blocked_until_epoch REAL NOT NULL DEFAULT 0,
    last_unlocked_epoch REAL NOT NULL DEFAULT 0,
    reason TEXT NOT NULL DEFAULT '',
    updated_at VARCHAR(32) NOT NULL
);
