<?php

// Exercise password changes and OAuth renewal without a live account or credentials.
if (PHP_SAPI !== 'cli') {
    exit;
}
$root = getenv('STALWART_ROOT') ?: dirname(__DIR__);
$roundcube_root = getenv('ROUNDCUBE_ROOT') ?: dirname($root, 2);
define('RCUBE_CHARSET', 'UTF-8');
require $roundcube_root . '/vendor/autoload.php';
require $roundcube_root . '/program/lib/Roundcube/rcube_utils.php';
require $roundcube_root . '/program/lib/Roundcube/rcube_charset.php';
require getenv('ROUNDCUBE_OAUTH_CLASS') ?: $roundcube_root . '/program/include/rcmail_oauth.php';
require $root . '/stalwart_oauth.php';
require $root . '/stalwart_page.php';
require $root . '/stalwart_password.php';

set_error_handler(function ($level, $message, $file, $line) {
    if (error_reporting() & $level) {
        throw new ErrorException($message, 0, $level, $file, $line);
    }
});
$checks = 0;
function session_check($value, $message)
{
    global $checks;
    if (!$value) {
        throw new RuntimeException($message);
    }
    $checks++;
}
class password_session_redirect extends Exception {}
class rcube
{
    public static function get_instance() { return rcmail::$instance; }
}
class rcmail extends rcube
{
    public static $instance;
    public $config;
    public $output;
    public $plugins;
    public $session;
    public $user;
    public $oauth;
    public $storage;
    public $events = [];
    public static function get_instance() { return self::$instance; }
    public function oauth_config() { return []; }
    public function get_cache_shared($name) { return null; }
    public function get_http_client($options) { return new GuzzleHttp\Client($options); }
    public function get_user_name() { return 'user@example.test'; }
    public function request_security_check() { $this->events[] = 'csrf'; }
    public function get_storage() { return $this->storage; }
    public function encrypt($value) { return 'encrypted:' . base64_encode($value); }
    public function decrypt($value) { return base64_decode(substr($value, 10)); }
    public function url($args) { return '/?' . http_build_query($args); }
    public function kill_session() { $this->events[] = 'kill'; $_SESSION = ['temp' => true]; }
}
class rcube_stalwart_client
{
    public static $instance;
    public $primary = false;
    public $reject = false;
    public $changes = [];
    public static function from_session($rc) { return self::$instance; }
    public function uses_account_password($current) { return $this->primary; }
    public function update($current, $code, $changes)
    {
        rcmail::$instance->events[] = 'update';
        if ($this->reject) {
            throw new RuntimeException('authenticationerror');
        }
        $this->changes[] = $changes;
    }
}
class password_session_auth
{
    public $mode = 'success';
    public $mfa = false;
    public $calls = [];
    public function binding() { return 'server-a'; }
    public function options() { return ['provider' => null, 'debug' => false]; }
    public function authorize($username, $password, $verifier, $code)
    {
        $this->calls[] = [$username, $password, $verifier, $code];
        session_check(rcmail::$instance->events[1] === 'update', 'Password is saved before new authorization');
        session_check($password === 'NewPassword1!', 'New authorization uses the new password');
        session_check((bool) preg_match('/^[A-Za-z0-9_-]{43}$/D', $verifier), 'New authorization has fresh PKCE');
        if ($this->mfa) {
            session_check($code === '123456', 'TOTP is passed to the server for verification');
        }
        if ($this->mode === 'failure') {
            throw new RuntimeException('connectionerror');
        }
        if ($this->mode === 'mfa') {
            return null;
        }
        $token = ['access_token' => 'new-access', 'expires_in' => 3600];
        if ($this->mode !== 'no-refresh') {
            $token['refresh_token'] = 'new-refresh';
        }
        return ['username' => $this->mode === 'identity' ? 'other@example.test' : $username, 'token' => $token];
    }
}
class password_session_page extends rcube_stalwart_password_page
{
    public function __construct($rc) { $this->rc = $rc; }
    public function available() { return true; }
}
function password_fixture($mode = 'embedded', $mfa = false)
{
    $rc = new rcmail();
    rcmail::$instance = $rc;
    $rc->config = new class {
        public function get($key, $default = null) { return $default; }
    };
    $rc->output = new class {
        public $ajax_call = false;
        public $framed = false;
        public $commands = [];
        public function get_charset() { return 'UTF-8'; }
        public function get_env($key) { return $key === 'framed' && $this->framed; }
        public function redirect($args) { throw new password_session_redirect($args['_task']); }
        public function command(...$args) { $this->commands[] = $args; }
        public function send($template) { throw new password_session_redirect($template); }
    };
    $rc->plugins = new class {
        public $hooks = [];
        public $remembered = 'old-refresh';
        public function register_hook($name, $callback) { $this->hooks[$name][] = $callback; }
        public function exec_hook($name, $args) {
            rcmail::$instance->events[] = $name;
            if ($name === 'oauth_refresh_token') {
                $this->remembered = isset($args['refresh_token']) ? rcmail::$instance->decrypt($args['refresh_token']) : null;
            }
            if ($name === 'logout_after') {
                $this->remembered = null;
            }
            return $args;
        }
    };
    $rc->session = new class {
        public $rotations = 0;
        public function remove($key) { unset($_SESSION[$key]); }
        public function regenerate_id($destroy) { $this->rotations++; }
    };
    $rc->storage = new class {
        public function check_connection() { return true; }
    };
    $rc->user = (object) ['ID' => 7, 'language' => 'en_US'];
    $auth = new password_session_auth();
    $auth->mfa = $mfa;
    $rc->oauth = new rcube_stalwart_oauth($auth);
    $api = new rcube_stalwart_client();
    $api->primary = $mode === 'password';
    rcube_stalwart_client::$instance = $api;
    $_SESSION = ['user_id' => 7, 'storage_host' => 'mail.example.test', 'password_expires' => 1,
        'password' => $rc->encrypt($mode === 'app' ? 'app-password' : 'OldPassword1!')];
    if ($mode === 'embedded' || $mode === 'native') {
        $_SESSION['oauth_token'] = $rc->oauth->prepare([
            'access_token' => 'old-access', 'refresh_token' => 'old-refresh', 'expires_in' => 3600,
        ], 'user@example.test');
        $_SESSION['password'] = $rc->encrypt('Bearer old-access');
        if ($mode === 'native') {
            unset($_SESSION['oauth_token']['stalwart_login']);
        }
    }
    $_POST = ['_curpasswd' => 'OldPassword1!', '_newpasswd' => 'NewPassword1!', '_confpasswd' => 'NewPassword1!',
        '_stalwart_code' => $mfa ? '123456' : ''];
    $_SERVER['REQUEST_METHOD'] = 'POST';
    return [new password_session_page($rc), $rc, $auth, $api];
}
function save_password($page)
{
    try {
        $page->save();
    }
    catch (password_session_redirect $e) {
        return $e->getMessage();
    }
    throw new RuntimeException('Expected response');
}
foreach ([false, true] as $mfa) {
    list($page, $rc, $auth, $api) = password_fixture('embedded', $mfa);
    session_check(save_password($page) === 'settings', 'Successful change returns to settings');
    session_check($_SESSION['user_id'] === 7 && !in_array('kill', $rc->events), 'Same mailbox remains signed in');
    session_check($rc->decrypt($_SESSION['password']) === 'Bearer new-access', 'Mail transport uses the new access token');
    session_check($rc->decrypt($_SESSION['oauth_token']['refresh_token']) === 'new-refresh', 'Old refresh token replaced');
    session_check($rc->plugins->remembered === 'new-refresh', 'Remember me receives the new refresh credential');
    session_check($rc->session->rotations === 1 && !isset($_SESSION['password_expires']), 'Session identifier rotated and expiry notice cleared');
    session_check(strpos(serialize($_SESSION), 'NewPassword1!') === false, 'New password is not stored in OAuth session');
    session_check($rc->oauth->storage_init(['driver' => 'imap'])['password'] === 'Bearer new-access', 'Next IMAP initialization uses the renewed authorization');
    session_check($rc->oauth->smtp_connect([])['smtp_auth_type'] === 'XOAUTH2', 'SMTP continues using OAuth');
}
foreach (['password', 'app'] as $mode) {
    list($page, $rc) = password_fixture($mode);
    session_check(save_password($page) === 'settings' && $_SESSION['user_id'] === 7, 'Non-OAuth sessions stay signed in');
    session_check($rc->decrypt($_SESSION['password']) === ($mode === 'password' ? 'NewPassword1!' : 'app-password'), 'Only the primary session password is changed');
}
list($page, $rc, $auth, $api) = password_fixture();
$api->reject = true;
$before = $_SESSION;
session_check(save_password($page) === 'settings' && !$auth->calls && $_SESSION['oauth_token'] === $before['oauth_token'], 'Rejected password change preserves existing authorization');
session_check($_SESSION['plugin.password-stalwart-notice']['message'] === 'authenticationerror', 'Rejected change is reported correctly');

foreach (['failure', 'mfa', 'identity', 'binding'] as $mode) {
    list($page, $rc, $auth, $api) = password_fixture();
    $auth->mode = $mode;
    if ($mode === 'binding') {
        $_SESSION['oauth_token']['stalwart_server'] = 'other-server';
    }
    session_check(save_password($page) === 'login', 'Unrecoverable authorization requests fresh sign-in');
    session_check(count($api->changes) === 1 && !empty($_SESSION['stalwart_password_changed']), 'Successful password change remains distinguishable from authorization failure');
    session_check(!isset($_SESSION['oauth_token'], $_SESSION['user_id']) && $rc->plugins->remembered === null, 'Revoked authorization cannot leave a broken authenticated session');
}
list($page, $rc, $auth) = password_fixture();
$auth->mode = 'no-refresh';
session_check(save_password($page) === 'settings' && !isset($_SESSION['oauth_token']['refresh_token']), 'A missing refresh token never falls back to the revoked one');
session_check($rc->plugins->remembered === null, 'Remember me is removed when new authorization cannot be refreshed');
foreach (['ajax_call', 'framed'] as $mode) {
    list($page, $rc, $auth) = password_fixture();
    $auth->mode = 'failure';
    $rc->output->$mode = true;
    session_check(save_password($page) === 'iframe' && $rc->output->commands[0][0] === 'session_error', 'Embedded requests notify the parent window of an expired session');
}
list($page, $rc, $auth) = password_fixture('native');
session_check(save_password($page) === 'login' && !$auth->calls, 'Native redirect OAuth does not expose the password to an embedded client');

echo "Password sessions: $checks checks passed.\n";
