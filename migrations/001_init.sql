CREATE TABLE IF NOT EXISTS users (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
  username VARCHAR(128) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin','operator','auditor') NOT NULL DEFAULT 'operator',
  status TINYINT NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_tenant_user (tenant_id, username)
);

CREATE TABLE IF NOT EXISTS tokens (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT NOT NULL,
  token_id VARCHAR(128) NOT NULL,
  refresh_hash VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  revoked TINYINT NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_token_id (token_id),
  KEY idx_user (user_id)
);

CREATE TABLE IF NOT EXISTS cloud_configs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
  cloud_provider VARCHAR(64) NOT NULL,
  cloud_drive_name VARCHAR(128) NOT NULL,
  base_url VARCHAR(512) NOT NULL,
  secure_enabled TINYINT NOT NULL DEFAULT 1,
  payload JSON NOT NULL,
  enabled TINYINT NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_tenant_drive (tenant_id, cloud_drive_name)
);

CREATE TABLE IF NOT EXISTS webdav_configs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
  cloud_drive_name VARCHAR(128) NOT NULL,
  path_regex VARCHAR(512) NOT NULL,
  username VARCHAR(128) NOT NULL,
  password_enc VARCHAR(512) NOT NULL,
  payload JSON NOT NULL,
  enabled TINYINT NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_tenant_drive (tenant_id, cloud_drive_name)
);

CREATE TABLE IF NOT EXISTS crypto_policies (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
  cloud_drive_name VARCHAR(128) NOT NULL,
  path_regex VARCHAR(512) NOT NULL,
  read_mode VARCHAR(32) NOT NULL,
  write_mode VARCHAR(32) NOT NULL DEFAULT 'aesctr',
  enc_name_enabled TINYINT NOT NULL DEFAULT 0,
  enc_suffix VARCHAR(32) NULL,
  password_ref VARCHAR(255) NOT NULL,
  enabled TINYINT NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_policy_match (tenant_id, cloud_drive_name)
);

CREATE TABLE IF NOT EXISTS timeout_profiles (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
  iface_name VARCHAR(128) NOT NULL,
  connect_ms INT NOT NULL,
  ttfb_ms INT NOT NULL,
  read_idle_ms INT NOT NULL,
  total_ms INT NOT NULL,
  enabled TINYINT NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_tenant_iface (tenant_id, iface_name)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
  request_id VARCHAR(64) NOT NULL,
  trace_id VARCHAR(64) NOT NULL,
  actor VARCHAR(128) NOT NULL,
  action VARCHAR(128) NOT NULL,
  target VARCHAR(255) NOT NULL,
  payload JSON NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_tenant_time (tenant_id, created_at),
  KEY idx_request (request_id),
  KEY idx_trace (trace_id)
);

CREATE TABLE IF NOT EXISTS runtime_kv (
  k VARCHAR(128) PRIMARY KEY,
  v JSON NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS file_meta_cache (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
  file_path VARCHAR(1024) NOT NULL,
  file_size BIGINT NOT NULL DEFAULT 0,
  enc_mode VARCHAR(32) NULL,
  hit_count BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_tenant_path (tenant_id, file_path),
  KEY idx_updated (updated_at)
);

CREATE TABLE IF NOT EXISTS cloud_strategy_stats (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
  cloud_drive_name VARCHAR(128) NOT NULL,
  strategy_name VARCHAR(64) NOT NULL,
  success_count BIGINT NOT NULL DEFAULT 0,
  fail_count BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_strategy (tenant_id, cloud_drive_name, strategy_name),
  KEY idx_strategy_updated (updated_at)
);

INSERT INTO timeout_profiles (tenant_id, iface_name, connect_ms, ttfb_ms, read_idle_ms, total_ms)
VALUES
  ('default', 'control.default', 300, 1200, 2000, 5000),
  ('default', 'metadata.default', 300, 2000, 4000, 12000),
  ('default', 'small-transfer.default', 300, 1500, 4000, 20000),
  ('default', 'large-stream.default', 300, 2500, 15000, 0)
ON DUPLICATE KEY UPDATE
  connect_ms = VALUES(connect_ms),
  ttfb_ms = VALUES(ttfb_ms),
  read_idle_ms = VALUES(read_idle_ms),
  total_ms = VALUES(total_ms);
