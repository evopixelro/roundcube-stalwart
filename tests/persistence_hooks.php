<?php

// Exercise unmodified Roundcube plugin hooks with no live mailbox or credentials.
if (PHP_SAPI !== 'cli') {
    exit;
}
$roundcube_root = getenv('ROUNDCUBE_ROOT') ?: dirname(__DIR__, 3);
$persistent_root = getenv('PERSISTENT_LOGIN_ROOT') ?: $roundcube_root . '/plugins/persistent_login';
if (!is_file($persistent_root . '/persistent_login.php')) {
    throw new RuntimeException('Set PERSISTENT_LOGIN_ROOT to an unchanged Persistent Login plugin.');
}
ob_start();
define('RCUBE_INSTALL_PATH', $roundcube_root . '/');
define('RCUBE_PLUGINS_DIR', dirname($persistent_root) . '/');
define('RCUBE_CHARSET', 'UTF-8');
require $roundcube_root . '/vendor/autoload.php';
require $roundcube_root . '/program/lib/Roundcube/rcube_plugin.php';
require $roundcube_root . '/program/lib/Roundcube/rcube_plugin_api.php';
require $roundcube_root . '/program/lib/Roundcube/html.php';
require $roundcube_root . '/program/include/rcmail_oauth.php';
require $persistent_root . '/persistent_login.php';
require dirname(__DIR__) . '/stalwart_auth.php';
require dirname(__DIR__) . '/stalwart_oauth.php';
require dirname(__DIR__) . '/stalwart_login.php';
set_error_handler(function ($level, $message, $file, $line) {
    if (error_reporting() & $level) {
        throw new ErrorException($message, 0, $level, $file, $line);
    }
});
function slashify($value) { return rtrim($value, '/\\') . '/'; }
function unslashify($value) { return rtrim($value, '/\\'); }
class rcube_utils
{
    const INPUT_GET = 1;
    const INPUT_POST = 2;
    static function https_check() { return true; }
    static function get_input_string($key, $source, ...$rest) { return ($source === 1 ? $_GET : $_POST)[$key] ?? null; }
    static function rep_specialchars_output($value, ...$rest) { return htmlspecialchars((string) $value, ENT_QUOTES); }
}
class rcube
{
    static $instance;
    static function get_instance() { return self::$instance; }
    static function Q($value) { return htmlspecialchars($value, ENT_QUOTES); }
}
class rcmail extends rcube
{
    public $config;
    public $plugins;
    public $oauth;
    public $task;
    public $output;
    public $user;
    public $session;
    function read_localization($path) { return ['ifpl_rememberme' => 'Remember me']; }
    function load_language($language, $texts) {}
    function gettext($key, ...$rest) { return $key; }
    function get_request_token() { return 'csrf-hook-test'; }
    function check_request($mode = null) { return true; }
    function oauth_config() { return []; }
    function get_cache_shared($name) { return null; }
    function get_http_client($options) { return new GuzzleHttp\Client($options); }
}
class persistence_hook_api extends rcube_plugin_api
{
    public function __construct() { parent::__construct(); }
    public function attach($plugin) { $this->plugins[$plugin->ID] = $plugin; }
}
class persistence_login_bridge extends rcube_plugin
{
    public $login;
    public function init() { $this->login = new rcube_stalwart_login($this); }
}
function hook_fixture($first = true, $task = 'login', $allowed = true, $enabled = true, $valid = true)
{
    $_GET = $_POST = $_COOKIE = [];
    $_SESSION = ['language' => 'en_US'];
    $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    unset($_SERVER['HTTP_X_FORWARDED_FOR']);
    $rc = new rcmail();
    $rc->task = $task;
    $rc->config = new class {
        public $values = [
            'plugins' => ['persistent_login', 'stalwart'], 'ifpl_cookie_name' => '_custom',
            'stalwart_api_url' => 'https://mail.example.test/jmap', 'stalwart_login_client_id' => 'test',
            'stalwart_login_redirect_uri' => 'https://webmail.example.test/index.php/login/oauth',
            'imap_host' => 'ssl://mail.example.test:993',
        ];
        public $loads = 0;
        function get($key, $default = null) { return $this->values[$key] ?? $default; }
        function set($key, $value) { $this->values[$key] = $value; }
        function load_from_file($file) { $this->loads++; return true; }
    };
    if (!$allowed) {
        $rc->config->values['ifpl_netmask_whitelist'] = ['10.0.0.0/8'];
    }
    if (!$valid) {
        $rc->config->values['stalwart_api_url'] = 'invalid';
    }
    $rc->user = (object) ['ID' => $task === 'mail' ? 7 : 0];
    $rc->output = new class {
        public $ajax_call = false;
        function get_env($key) { return false; }
        function set_env($key, $value) {}
        function add_script($script, $position) {}
    };
    $rc->session = new class {
        function remove($key) { unset($_SESSION[$key]); }
    };
    rcube::$instance = $rc;
    $rc->plugins = new persistence_hook_api();
    $plugin = new persistent_login($rc->plugins);
    $bridge = new persistence_login_bridge($rc->plugins);
    if ($first && $enabled) {
        $rc->plugins->attach($plugin);
    }
    $rc->plugins->attach($bridge);
    if (!$first && $enabled) {
        $rc->plugins->attach($plugin);
    }
    $rc->plugins->init($rc, $task);
    return [$rc, $plugin, $bridge];
}
$checks = 0;
function check_hook($condition, $message)
{
    global $checks;
    if (!$condition) { throw new RuntimeException($message); }
    $checks++;
}
function has_hook($rc, $plugin, $name, $method = null)
{
    return in_array([$plugin, $method ?: $name], $rc->plugins->handlers[$name] ?? [], true);
}
function helpers($rc)
{
    return array_values(array_filter($rc->plugins->handlers['startup'] ?? [], function ($hook) {
        return $hook[0] instanceof rcube_stalwart_persistent_login;
    }));
}
foreach ([true, false] as $first) {
    foreach (['login', 'mail', 'logout'] as $task) {
        [$rc, $plugin, $bridge] = hook_fixture($first, $task);
        foreach (['startup', 'authenticate', 'login_after'] as $name) {
            check_hook(!has_hook($rc, $plugin, $name), 'Stalwart does not run password persistence: ' . $name);
        }
        check_hook(count(helpers($rc)) === 1, 'Exactly one Stalwart persistence handler in either plugin order');
        check_hook(has_hook($rc, $plugin, 'logout_after'), 'Legacy cookie cleanup remains available');
        check_hook($rc->config->loads === 1, 'Plugin settings load once on each task');
        check_hook(count($rc->plugins->handlers['oauth_refresh_token']) === 1, 'Refresh updates are handled on authenticated requests');
        $after = $rc->plugins->handlers['login_after'];
        check_hook($after[0][0] === $bridge->login && $after[1][0] instanceof rcube_stalwart_persistent_login,
            'Persistence runs after verified Stalwart tokens are stored');
        check_hook(!empty($rc->oauth->persistent_login_context()['managed']), 'Adapter declares its independent persistence');
        check_hook(has_hook($rc, $plugin, 'template_object_loginform', 'persistent_login_loginform'), 'Initial login reuses the original checkbox renderer');
        $rc->plugins->exec_hook('loginform_content', ['inputs' => [], 'hidden' => ['stalwart' => 'challenge'], 'buttons' => []]);
        check_hook(!has_hook($rc, $plugin, 'template_object_loginform', 'persistent_login_loginform'), 'Second step never adds a conflicting remember checkbox');
    }
}
[$rc] = hook_fixture(true, 'login', true, false);
check_hook(!helpers($rc), 'Stalwart login remains usable without Persistent Login');
[$rc, $plugin] = hook_fixture(true, 'login', false);
check_hook(!helpers($rc) && !has_hook($rc, $plugin, 'startup'), 'The configured network whitelist is respected');
[$rc, $plugin] = hook_fixture(false, 'login', true, true, false);
check_hook(!helpers($rc), 'Invalid Stalwart settings cannot create remembered sessions');
foreach (['startup', 'authenticate', 'login_after'] as $name) {
    check_hook(!has_hook($rc, $plugin, $name), 'Invalid settings cannot fall back to saved passwords: ' . $name);
}
check_hook(!has_hook($rc, $plugin, 'template_object_loginform', 'persistent_login_loginform'), 'Invalid settings do not advertise persistent login');
ob_end_clean();
echo "Stalwart persistence hooks: {$checks} checks passed.\n";
