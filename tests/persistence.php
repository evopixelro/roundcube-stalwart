<?php

// Exercise persistence with an isolated SQLite database and no network or real mail.
if (PHP_SAPI !== 'cli') {
    exit;
}
ob_start();
date_default_timezone_set('UTC');
require dirname(__DIR__) . '/stalwart_persistent_login.php';
set_error_handler(function ($level, $message, $file, $line) {
    if (error_reporting() & $level) {
        throw new ErrorException($message, 0, $level, $file, $line);
    }
});
$checks = 0;
function verify($condition, $message)
{
    global $checks;
    if (!$condition) {
        throw new RuntimeException($message);
    }
    $checks++;
}
class rcube_utils
{
    const INPUT_GET = 1;
    const INPUT_POST = 2;
    static function get_input_string($name, $type) { return ($type === self::INPUT_GET ? $_GET : $_POST)[$name] ?? null; }
    static function https_check() { return true; }
}
class persistence_redirect extends Exception {}
class persistence_db
{
    public $pdo;
    public $before_claim;
    function __construct()
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->exec('CREATE TABLE test_cache (user_id INTEGER, cache_key TEXT, expires TEXT, data TEXT, PRIMARY KEY (user_id, cache_key))');
    }
    function table_name($name) { return 'test_' . $name; }
    function now() { return 'CURRENT_TIMESTAMP'; }
    function query($sql, ...$args)
    {
        if ($this->before_claim && strpos($sql, 'DELETE') === 0 && strpos($sql, 'AND data = ?') !== false) {
            $callback = $this->before_claim;
            $this->before_claim = null;
            $callback($this, $args);
        }
        $result = $this->pdo->prepare($sql);
        $result->execute($args);
        return $result;
    }
    function fetch_assoc($result) { return $result->fetch(PDO::FETCH_ASSOC); }
    function affected_rows($result) { return $result->rowCount(); }
    function rows() { return $this->pdo->query('SELECT * FROM test_cache')->fetchAll(PDO::FETCH_ASSOC); }
}
class persistence_oauth
{
    public $context = ['host' => 'ssl://mail.example.test:993', 'binding' => 'provider-a'];
    public $calls = 0;
    public $reject = false;
    public $last_refresh;
    public $on_refresh;
    function host() { return $this->context['host']; }
    function binding() { return $this->context['binding']; }
    function refresh_access_token($token)
    {
        $this->calls++;
        $this->last_refresh = $token['refresh_token'];
        if ($this->reject) { return false; }
        $token['refresh_token'] = 'encrypted-refresh-' . $this->calls;
        $token['access_token'] = 'encrypted-access-' . $this->calls;
        $token['expires'] = time() + 3600;
        $_SESSION['oauth_token'] = $token;
        if ($this->on_refresh) { ($this->on_refresh)($token); }
        return ['token' => $token, 'authorization' => 'Bearer fresh-access-token'];
    }
}
class persistence_rc
{
    public $config;
    public $db;
    public $oauth;
    public $user;
    public $session;
    public $plugins;
    public $output;
    public $csrf = true;
    public $login_ok = true;
    public $target_id = 7;
    public $logins = 0;
    public $logged = 0;
    function __construct()
    {
        $this->db = new persistence_db();
        $this->oauth = new persistence_oauth();
        $this->config = new class {
            public $values = ['des_key' => 'isolated-persistence-test-key-32'];
            function get($key, $default = null) { return $this->values[$key] ?? $default; }
            function set($key, $value) { $this->values[$key] = $value; }
        };
        $this->user = (object) ['ID' => 0, 'data' => []];
        $this->session = new class {
            public $rotations = 0;
            public $auth_cookies = 0;
            function remove($key) { unset($_SESSION[$key]); }
            function regenerate_id($destroy) { $this->rotations++; }
            function set_auth_cookie() { $this->auth_cookies++; }
        };
        $this->plugins = new class {
            public $helper;
            function get_plugin($name) { return null; }
            function exec_hook($name, $args) { return $this->helper->login_after($args); }
        };
        $this->output = new class {
            function redirect($args, ...$rest) { throw new persistence_redirect(); }
        };
    }
    function get_dbh() { return $this->db; }
    function check_request($mode = null) { return $this->csrf; }
    function login($username, $authorization, $host, $cookiecheck)
    {
        $this->logins++;
        verify($authorization === 'Bearer fresh-access-token', 'Restoration uses fresh authorization');
        verify($host === $this->oauth->context['host'], 'Restoration uses the selected server');
        if (!$this->login_ok) { return false; }
        $this->user = (object) ['ID' => $this->target_id, 'data' => ['username' => $username]];
        $_SESSION['user_id'] = $this->target_id;
        return true;
    }
    function log_login() { $this->logged++; }
    function kill_session() { $_SESSION = ['temp' => true]; $this->user = (object) ['ID' => 0, 'data' => []]; }
}
function fresh_helper($rc, $lifetime = 259200)
{
    $helper = new rcube_stalwart_persistent_login($rc, $rc->oauth, '_pt', $lifetime);
    $rc->plugins->helper = $helper;
    $rc->oauth->on_refresh = [$helper, 'refresh'];
    return $helper;
}
function fixture($remember = true, $refresh = true)
{
    $_COOKIE = $_GET = $_POST = [];
    $_SESSION = ['temp' => true];
    $rc = new persistence_rc();
    $helper = fresh_helper($rc);
    $_POST = ['_ifpl' => $remember ? '1' : '0'];
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $helper->startup(['task' => 'login', 'action' => 'login']);
    $_SESSION = [];
    $rc->user = (object) ['ID' => 7, 'data' => ['username' => 'alice@example.test']];
    $token = ['stalwart_login' => true, 'stalwart_server' => $rc->oauth->binding(), 'identity' => 'alice@example.test', 'auth_type' => 'XOAUTH2', 'access_token' => 'encrypted-access-initial', 'expires' => time() + 3600];
    if ($refresh) { $token['refresh_token'] = 'encrypted-refresh-initial'; }
    $_SESSION['oauth_token'] = $token;
    $helper->login_after([]);
    return [$rc, $helper];
}
function return_to_mail($rc)
{
    $rc->kill_session();
    $_POST = $_GET = [];
    $_SERVER['REQUEST_METHOD'] = 'GET';
    $helper = fresh_helper($rc);
    try { $helper->startup(['task' => 'login', 'action' => '']); return false; }
    catch (persistence_redirect $e) { return true; }
}

foreach ([0, 1] as $restore_case) {
    foreach (['provider-a', 'provider-b'] as $binding) {
        [$rc, $helper] = fixture();
        $rc->oauth->context['binding'] = $binding;
        $_SESSION['oauth_token']['stalwart_server'] = $binding;
        $helper = fresh_helper($rc);
        $rc->user->ID = 0;
        $helper->startup(['task' => 'login', 'action' => 'login']);
        $rc->user->ID = 7;
        $helper->login_after([]);
        $rows = $rc->db->rows();
        verify(count($rows) === 1, 'Exactly one record after successful login for each selected Stalwart server');
        $cookie = $_COOKIE['_pt_stalwart'];
        verify(strpos($cookie, 'refresh') === false && strpos($cookie, 'alice') === false, 'Cookie contains no identity or provider credentials');
        verify(strpos($rows[0]['data'], 'refresh') === false && strpos($rows[0]['data'], 'alice') === false, 'Stored record is encrypted');
        verify(strpos($rows[0]['cache_key'], $cookie) === false, 'Cookie secret is hashed in the database key');
        $expires = $rows[0]['expires'];
        verify(return_to_mail($rc), 'Remembered mailbox resumes after losing its PHP session');
        verify($rc->session->rotations === 1 && $rc->session->auth_cookies === 1, 'Restored sessions receive new session and auth cookies');
        verify($_COOKIE['_pt_stalwart'] !== $cookie && count($rc->db->rows()) === 1, 'Restoration rotates and consumes the identifier');
        verify($rc->db->rows()[0]['expires'] === $expires, 'Restoration does not extend the lifetime');
        $fresh_cookie = $_COOKIE['_pt_stalwart'];
        $_COOKIE['_pt_stalwart'] = $cookie;
        verify(!return_to_mail($rc) && $rc->oauth->calls === 1, 'Consumed identifier cannot replay the provider refresh');
        $_COOKIE['_pt_stalwart'] = $fresh_cookie;
        verify(return_to_mail($rc) && $rc->oauth->last_refresh === 'encrypted-refresh-1', 'Next return uses the rotated refresh token');
        $logout = fresh_helper($rc);
        $rc->kill_session();
        $logout->logout_after([]);
        verify(!$rc->db->rows() && empty($_COOKIE['_pt_stalwart']), 'Logout revokes the record even after the PHP session is cleared');
    }
}
[$rc] = fixture(false);
verify(!$rc->db->rows() && empty($_COOKIE['_pt_stalwart']), 'No persistence without opt-in');
[$rc] = fixture(true, false);
verify(!$rc->db->rows(), 'Providers without refresh tokens cannot be remembered');

[$rc, $helper] = fixture();
$_SESSION['oauth_token']['refresh_token'] = 'encrypted-rotated-active';
$helper->refresh([]);
verify(return_to_mail($rc) && $rc->oauth->last_refresh === 'encrypted-rotated-active', 'Active-session refresh updates the saved token');

[$rc, $helper] = fixture();
$rc->db->pdo->exec('DELETE FROM test_cache');
$helper->refresh([]);
verify(!$rc->db->rows() && !isset($_SESSION['stalwart_persistent_login']), 'Refresh never resurrects a revoked record');

[$rc] = fixture();
$rc->oauth->context['binding'] = 'other-provider';
verify(!return_to_mail($rc) && !$rc->oauth->calls, 'Changed provider never receives saved credentials');
[$rc] = fixture();
$rc->oauth->context['host'] = 'ssl://other.example.test:993';
verify(!return_to_mail($rc) && !$rc->oauth->calls, 'Changed mail server never receives saved credentials');
[$rc] = fixture();
$rc->config->set('des_key', str_repeat('changed', 6));
verify(!return_to_mail($rc) && !$rc->oauth->calls, 'Changed encryption key invalidates remembered data');

[$rc] = fixture();
$rc->db->pdo->exec("UPDATE test_cache SET data = 'tampered'");
verify(!return_to_mail($rc) && !$rc->oauth->calls, 'Corrupted ciphertext cannot authenticate');
[$rc] = fixture();
$rc->db->pdo->exec("UPDATE test_cache SET expires = '2000-01-01 00:00:00'");
verify(!return_to_mail($rc) && !$rc->oauth->calls && !$rc->db->rows(), 'Expired records are rejected and removed');
[$rc] = fixture();
$rc->oauth->reject = true;
verify(!return_to_mail($rc) && !$rc->user->ID && !$rc->db->rows(), 'Revoked provider token returns to login and removes persistence');
[$rc] = fixture();
$rc->login_ok = false;
verify(!return_to_mail($rc) && !$rc->user->ID && empty($_SESSION['oauth_token']), 'Failed mailbox authentication leaves no OAuth session');
[$rc] = fixture();
$rc->target_id = 8;
verify(!return_to_mail($rc) && !$rc->user->ID, 'A different local account cannot inherit the remembered login');
[$rc] = fixture();
$rc->db->before_claim = function ($db) { $db->pdo->exec('DELETE FROM test_cache'); };
verify(!return_to_mail($rc) && !$rc->oauth->calls, 'Only the request that claims the row can contact the provider');

[$rc] = fixture();
$rc->kill_session();
$_POST = [];
$_GET = ['code' => 'callback'];
$_SERVER['REQUEST_METHOD'] = 'GET';
$helper = fresh_helper($rc);
$helper->startup(['task' => 'login', 'action' => 'oauth']);
verify(!$rc->oauth->calls, 'Remembered cookies do not intercept OAuth callbacks');
$_GET = [];
$_SESSION['stalwart_login'] = ['pending' => true];
$helper->startup(['task' => 'login', 'action' => '']);
verify(!$rc->oauth->calls, 'Remembered cookies do not bypass a pending second factor');

foreach ([true, false] as $csrf) {
    [$rc] = fixture(false);
    $rc->kill_session();
    $rc->csrf = $csrf;
    $helper = fresh_helper($rc);
    $_POST = ['_ifpl' => '1'];
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $helper->startup(['task' => 'login', 'action' => 'login']);
    $rc->user = (object) ['ID' => 7, 'data' => ['username' => 'alice@example.test']];
    $_SESSION['oauth_token'] = ['identity' => 'alice@example.test', 'refresh_token' => 'saved',
        'stalwart_login' => true, 'stalwart_server' => $rc->oauth->binding()];
    $helper->login_after([]);
    verify((count($rc->db->rows()) === 1) === $csrf, 'Remember choice requires a valid CSRF token');
}

[$rc] = fixture();
$rc->kill_session();
$_POST = $_GET = [];
$_SERVER['REQUEST_METHOD'] = 'GET';
$helper = fresh_helper($rc, 0);
$helper->startup(['task' => 'login', 'action' => '']);
verify(!$rc->db->rows() && !$rc->oauth->calls, 'Disabling the lifetime rejects existing remembered logins');

[$rc] = fixture();
$rc->user->data['username'] = 'ALICE@example.test';
$helper = fresh_helper($rc);
$_SESSION['oauth_token']['refresh_token'] = 'normalized-refresh';
$helper->refresh([]);
verify(return_to_mail($rc), 'Canonical mailbox names may differ in case from the provider identity');

[$rc] = fixture();
$helper = fresh_helper($rc);
$rc->user->ID = 0;
$_POST = ['_ifpl' => '1'];
$_SERVER['REQUEST_METHOD'] = 'POST';
$helper->startup(['task' => 'login', 'action' => 'login']);
$rc->user->ID = 7;
unset($_SESSION['oauth_token']['stalwart_login']);
$helper->login_after([]);
verify(!$rc->db->rows(), 'Credentials belonging to other OAuth providers are never remembered');

ob_end_clean();
echo "Stalwart persistence: {$checks} checks passed.\n";
