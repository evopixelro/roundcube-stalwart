<?php

// Exercise challenge transitions and the real Roundcube OAuth base class offline.
$roundcube_root = getenv('ROUNDCUBE_ROOT') ?: dirname(__DIR__, 3);
define('RCUBE_CHARSET', 'UTF-8');
require $roundcube_root . '/vendor/autoload.php';
require $roundcube_root . '/program/lib/Roundcube/html.php';
require $roundcube_root . '/program/include/rcmail_oauth.php';
require dirname(__DIR__) . '/stalwart_auth.php';
require dirname(__DIR__) . '/stalwart_oauth.php';
require dirname(__DIR__) . '/stalwart_login.php';

set_error_handler(function ($level, $message, $file, $line) {
    if (error_reporting() & $level) {
        throw new ErrorException($message, 0, $level, $file, $line);
    }
});
$checks = 0;
function login_check($condition, $message)
{
    global $checks;
    if (!$condition) {
        throw new RuntimeException($message);
    }
    $checks++;
}
class login_redirect extends Exception {}
class rcube_utils
{
    const INPUT_POST = 1;
    const INPUT_GET = 2;
    public static function get_input_string($name, $source, ...$rest) { return $_POST[$name] ?? null; }
    public static function rep_specialchars_output($value, $mode = '', $replace_newlines = true) { return htmlspecialchars((string) $value, ENT_QUOTES); }
}
class rcube
{
    public static function Q($value) { return htmlspecialchars((string) $value, ENT_QUOTES); }
}
class rcmail extends rcube
{
    public static $instance;
    public $config;
    public $plugins;
    public $output;
    public $session;
    public $user;
    public $oauth;
    public $valid = true;
    public static function get_instance() { return self::$instance; }
    public function encrypt($value) { return 'encrypted:' . base64_encode($value); }
    public function decrypt($value) { return strpos($value, 'encrypted:') === 0 ? base64_decode(substr($value, 10)) : ''; }
    public function check_request() { return $this->valid; }
    public function request_security_check($source) { if (!$this->valid) { throw new login_redirect('invalid CSRF'); } }
    public function get_cache_shared($name) { return null; }
    public function get_http_client($options) { return new GuzzleHttp\Client($options); }
    public function get_request_token() { return 'csrf-test'; }
    public function gettext($text) { return $text; }
    public function url($params) { return '/?' . http_build_query($params); }
    public function kill_session() { $_SESSION = ['temp' => true]; }
}
class login_api
{
    public $calls = 0;
    public $mfa = true;
    public $refresh_error = false;
    public $server = 'binding';
    public function binding() { return $this->server; }
    public function host() { return 'ssl://mail.example.test:993'; }
    public function options() { return ['provider' => null, 'debug' => false]; }
    public function authorize($username, $password, $verifier, $code = '') {
        $this->calls++;
        if ($password !== 'dummy-password' || ($code !== '' && $code !== '123456')) {
            throw new RuntimeException('credentialserror');
        }
        if ($this->mfa && $code === '') { return null; }
        return ['username' => 'canonical@example.test', 'token' => [
            'access_token' => 'test-token', 'refresh_token' => 'test-refresh', 'expires_in' => 3600,
        ]];
    }
    public function refresh($token) {
        if ($this->refresh_error) { throw new RuntimeException('credentialserror'); }
        login_check($token === 'test-refresh', 'Refresh credential decrypted only for API use');
        return ['access_token' => 'new-token', 'refresh_token' => 'new-refresh', 'expires_in' => 3600];
    }
}
function login_fixture($mfa = true)
{
    $rc = new rcmail();
    rcmail::$instance = $rc;
    $rc->config = new class {
        public $values = [
            'stalwart_api_url' => 'https://mail.example.test/jmap', 'stalwart_login_client_id' => 'test',
            'stalwart_login_redirect_uri' => 'https://webmail.example.test/index.php/login/oauth',
            'imap_host' => 'ssl://mail.example.test:993',
        ];
        public function get($key, $default = null) { return $this->values[$key] ?? $default; }
        public function set($key, $value) { $this->values[$key] = $value; }
    };
    $rc->plugins = new class {
        public $hooks = [];
        public function register_hook($name, $callback) { $this->hooks[$name][] = $callback; }
        public function exec_hook($name, $args) { return $args; }
    };
    $rc->output = new class {
        public $messages = [];
        public function redirect($params) { throw new login_redirect($params['_action'] ?? 'login'); }
        public function show_message($message, $type) { $this->messages[] = $message; }
    };
    $rc->session = new class {
        public $rotations = 0;
        public function regenerate_id($destroy) { $this->rotations++; }
        public function remove($key) { unset($_SESSION[$key]); }
    };
    $rc->user = (object) ['ID' => 0];
    $plugin = new class {
        public function add_hook($name, $callback) {}
        public function gettext($key) { return $key; }
    };
    $login = new rcube_stalwart_login($plugin);
    $api = new login_api();
    $api->mfa = $mfa;
    $property = new ReflectionProperty($login, 'client');
    $property->setAccessible(true);
    $property->setValue($login, $api);
    $rc->oauth = new rcube_stalwart_oauth($api);
    $_SESSION = ['temp' => true];
    $_POST = ['_user' => 'alias@example.test', '_pass' => 'dummy-password', '_url' => '_task=mail&_mbox=Sent'];
    $_SERVER['REQUEST_METHOD'] = 'POST';
    return [$login, $api, $rc];
}
function login_start($login)
{
    try { return $login->startup(['task' => 'login', 'action' => 'login']); }
    catch (login_redirect $e) { return $e->getMessage(); }
}
function login_challenge($login)
{
    login_check(login_start($login) === 'plugin.stalwart-login', 'Credentials produce a native second-factor page');
    return $_SESSION['stalwart_login']['flow'];
}
function login_auth($login)
{
    return $login->authenticate(['valid' => true, 'user' => 'submitted', 'pass' => 'submitted']);
}

list($login, $api, $rc) = login_fixture();
$flow = login_challenge($login);
login_check(!isset($_SESSION['oauth_token'], $_SESSION['user_id']), 'No mailbox authorization before OTP');
login_check($_SESSION['stalwart_login']['password'] !== 'dummy-password' && $rc->decrypt($_SESSION['stalwart_login']['password']) === 'dummy-password', 'Pending password is encrypted');
login_check($rc->session->rotations === 1 && !isset($_POST['_pass']), 'Rotate challenge session and remove posted password');
$form = $login->form(['inputs' => [], 'hidden' => [], 'buttons' => []]);
$rendered = json_encode($form);
login_check(strpos($rendered, 'dummy-password') === false && strpos($rendered, 'encrypted:') === false, 'Form never exposes saved credentials');
login_check(array_keys($form['inputs']) === ['code'], 'Second step shows only the authenticator code');
login_check(strpos($rendered, 'one-time-code') !== false && strpos($rendered, 'csrf-test') !== false, 'OTP autofill and protected cancellation');
login_check(strpos($form['hidden']['url'], 'Sent') !== false, 'Preserve post-login destination');
$_POST = ['_stalwart_flow' => $flow, '_stalwart_code' => '654321'];
login_check(login_start($login) === 'plugin.stalwart-login', 'Wrong code returns to second step');
login_check($_SESSION['stalwart_login']['attempts'] === 4 && !isset($_SESSION['oauth_token']), 'Wrong code consumes an attempt, grants no access');
// Each HTTP request constructs a fresh controller; keep only the pending server session.
$pending = $_SESSION;
list($login, $api, $rc) = login_fixture();
$_SESSION = $pending;
$_POST = ['_stalwart_flow' => $flow, '_stalwart_code' => '123456'];
login_start($login);
$rc->kill_session();
$auth = login_auth($login);
login_check(empty($auth['abort']) && $auth['user'] === 'canonical@example.test' && $auth['pass'] === 'Bearer test-token', 'Completed OTP survives the native pre-login session reset');
login_check($rc->config->get('imap_auth_type') === 'XOAUTH2', 'Initial IMAP login uses OAuth');
$login->login_after([]);
login_check(!isset($_SESSION['stalwart_login']) && $_SESSION['oauth_token']['refresh_token'] !== 'test-refresh', 'Success discards challenge and encrypts tokens');
login_check($rc->oauth->is_token_valid(), 'Unexpired token is usable');
$storage = $rc->oauth->storage_init(['driver' => 'imap']);
login_check($storage['auth_type'] === 'XOAUTH2' && $storage['password'] === 'Bearer test-token', 'Authenticated requests retain XOAUTH2');
login_check($rc->oauth->smtp_connect([])['smtp_auth_type'] === 'XOAUTH2', 'SMTP uses the same verified authorization');
$_SESSION['oauth_token']['expires'] = time() - 1;
login_check($rc->oauth->is_token_valid() && $rc->decrypt($_SESSION['oauth_token']['access_token']) === 'new-token', 'Refresh replaces encrypted access token');
$_SESSION['oauth_token']['expires'] = time() - 1;
$api->refresh_error = true;
try { $rc->oauth->storage_init(['driver' => 'imap']); throw new RuntimeException('Expired session reached transport'); }
catch (login_redirect $e) { login_check(!isset($_SESSION['oauth_token']), 'Rejected refresh destroys session before mail transport'); }

foreach (['csrf', 'nonce', 'expired', 'binding', 'attempts', 'method'] as $invalid) {
    list($login, $api, $rc) = login_fixture();
    $flow = login_challenge($login);
    $_POST = ['_stalwart_flow' => $flow, '_stalwart_code' => '123456'];
    if ($invalid === 'csrf') { $rc->valid = false; }
    if ($invalid === 'nonce') { $_POST['_stalwart_flow'] = str_repeat('0', 64); }
    if ($invalid === 'expired') { $_SESSION['stalwart_login']['expires'] = time() - 1; }
    if ($invalid === 'binding') { $_SESSION['stalwart_login']['binding'] = 'other-client'; }
    if ($invalid === 'attempts') { $_SESSION['stalwart_login']['attempts'] = 0; }
    if ($invalid === 'method') { $_SERVER['REQUEST_METHOD'] = 'GET'; }
    login_start($login);
    login_check(!empty(login_auth($login)['abort']) && !isset($_SESSION['stalwart_login']), 'Reject and clear invalid challenge: ' . $invalid);
    login_check($api->calls === 1, 'Invalid challenge causes no second API call: ' . $invalid);
}
list($login, $api, $rc) = login_fixture();
$flow = login_challenge($login);
$_POST = ['_stalwart_flow' => $flow, '_stalwart_code' => 'bad'];
$_SESSION['stalwart_login']['attempts'] = 1;
login_start($login);
login_check(!isset($_SESSION['stalwart_login']) && !empty(login_auth($login)['abort']), 'Last malformed attempt ends the challenge');
list($login, $api, $rc) = login_fixture();
login_challenge($login);
try { $login->startup(['task' => 'login', 'action' => 'plugin.stalwart-login-cancel']); }
catch (login_redirect $e) { login_check(!isset($_SESSION['stalwart_login']), 'Cancel deletes pending credentials'); }
list($login, $api, $rc) = login_fixture(false);
login_start($login);
login_check(empty(login_auth($login)['abort']) && !isset($_SESSION['stalwart_login']), 'Accounts without MFA complete in one step');
$login->login_failed([]);
login_check(!empty(login_auth($login)['abort']), 'Mailbox failure discards request authorization');
list($login, $api, $rc) = login_fixture();
$_POST['_pass'] = 'wrong-password';
login_start($login);
login_check(!empty(login_auth($login)['abort']) && !isset($_SESSION['stalwart_login']), 'Wrong password grants neither a challenge nor mailbox access');
list($login, $api, $rc) = login_fixture(false);
login_start($login);
login_auth($login);
$login->login_after([]);
$api->server = 'another-server';
try { $rc->oauth->storage_init(['driver' => 'imap']); throw new RuntimeException('Mismatched token reached transport'); }
catch (login_redirect $e) { login_check(!isset($_SESSION['oauth_token']), 'Server change destroys token session before transport'); }

list($login, $api, $rc) = login_fixture();
$flow = login_challenge($login);
$api->server = 'another-server';
$_POST = ['_stalwart_flow' => $flow, '_stalwart_code' => '123456'];
login_start($login);
login_check($api->calls === 1 && !empty(login_auth($login)['abort']), 'Changing server during OTP cannot forward pending credentials');

echo $checks . " native Stalwart login checks passed.\n";
