-- Settings table for nmap path and future settings
CREATE TABLE IF NOT EXISTS settings (
    `key` VARCHAR(128) PRIMARY KEY,
    `value` TEXT NOT NULL,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Default nmap path
INSERT INTO settings (`key`, `value`) VALUES ('nmap_path', '/usr/bin/nmap')
ON DUPLICATE KEY UPDATE `value` = `value`;