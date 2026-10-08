<?php

// Exercise the real Roundcube plugin base class without bootstrapping a live application.
$roundcube_root = getenv('ROUNDCUBE_ROOT') ?: dirname(__DIR__, 3);
$base = $roundcube_root . '/program/lib/Roundcube/rcube_plugin.php';
if (!is_file($base)) {
    throw new RuntimeException('Set ROUNDCUBE_ROOT to a development Roundcube installation.');
}
require $base;
require dirname(__DIR__) . '/stalwart.php';

set_error_handler(function ($level, $message, $file, $line) {
    throw new ErrorException($message, 0, $level, $file, $line);
});

$checks = 0;
function lifecycle_check($condition, $message)
{
    global $checks;
    if (!$condition) {
        throw new RuntimeException($message);
    }
    $checks++;
}

function slashify($path)
{
    return rtrim($path, '/\\') . '/';
}

// Only the application environment is simulated; rcube_plugin methods are upstream code.
class rcube
{
    public static $instance;
    public static function get_instance() { return self::$instance; }
}

class rcmail extends rcube
{
    public $config;
    public $output;
    public $session;
    public $user;
    public function get_user_name() { return 'user@example.test'; }
    public function read_localization($path) { return []; }
}

class stalwart_lifecycle_api
{
    public $dir;
    public $url = 'plugins/';
    public $hooks = [];
    public $actions = [];
    public $assets = [];
    public $loads = [];
    public $password_config = [];

    public function register_hook($name, $callback) { $this->hooks[$name][] = $callback; }
    public function register_action($name, $id, $callback, $task) { $this->actions[$name] = $callback; }
    public function include_script($file, $attributes = []) { $this->assets[] = $file; }
    public function include_stylesheet($file) { $this->assets[] = $file; }
    public function load_plugin($name, $force = false)
    {
        $this->loads[] = $name;
        if ($name === 'password') {
            rcube::$instance->config->values = array_replace(rcube::$instance->config->values, $this->password_config);
        }
        return true;
    }
}

function lifecycle(array $values = [], array $password_config = [])
{
    $rc = new rcmail();
    $rc->config = new class($values) {
        public $values;
        public function __construct($values) { $this->values = $values; }
        public function get($key, $default = null) { return $this->values[$key] ?? $default; }
        public function load_from_file($file) { return true; }
    };
    $rc->output = new class {
        public function add_label(...$labels) {}
    };
    $rc->session = new class {
        public function remove($key) { unset($_SESSION[$key]); }
    };
    $rc->user = (object) ['ID' => 1];
    rcube::$instance = $rc;
    $api = new stalwart_lifecycle_api();
    $api->dir = dirname(__DIR__, 2) . '/';
    $api->password_config = $password_config;
    $plugin = new stalwart($api);
    $plugin->init();
    lifecycle_check(isset($api->hooks['startup']), 'Startup hook is registered through the native plugin API');
    $args = $plugin->startup(['action' => 'plugin.password']);
    return [$plugin, $api, $args];
}

$_SESSION = ['storage_host' => 'mail.example.test'];
list($plugin, $api) = lifecycle();
lifecycle_check($plugin->ID === 'stalwart', 'Entry class matches the Composer installation directory');
lifecycle_check($plugin->task === 'settings' && $plugin->noajax && $plugin->noframe, 'Plugin only runs in native settings requests');
lifecycle_check(!$api->actions && !$api->assets && !$api->loads, 'Disabled defaults do not register actions, assets or a password provider');

$enabled = ['stalwart_enabled' => true, 'stalwart_api_url' => 'https://mail.example.test/jmap'];
$features = ['twofactor' => 'plugin.stalwart', 'app_passwords' => 'plugin.stalwart-app-passwords',
    'aliases' => 'plugin.stalwart-aliases', 'public_keys' => 'plugin.stalwart-public-keys',
    'masked_email' => 'plugin.stalwart-masked-email'];
foreach ($features as $feature => $action) {
    list($plugin, $api) = lifecycle($enabled + ['stalwart_' . $feature . '_enabled' => true]);
    lifecycle_check(array_keys($api->actions) === [$action, $action . '-save'], 'Only the selected feature exposes actions: ' . $feature);
    lifecycle_check($api->assets === ['stalwart/stalwart.css', 'stalwart/stalwart.js'], 'Assets use the native plugin resource namespace');
    $menu = $plugin->settings_actions(['actions' => []]);
    lifecycle_check(count($menu['actions']) === 1 && $menu['actions'][0]['domain'] === 'stalwart', 'Menu translations use the plugin domain');
}

$native_menu = [['action' => 'preferences'], ['action' => 'plugin.password'], ['action' => 'identities']];
list($plugin) = lifecycle($enabled + ['stalwart_twofactor_enabled' => true, 'password_driver' => 'mailcow']);
$menu = $plugin->settings_actions(['actions' => $native_menu]);
lifecycle_check(array_column($menu['actions'], 'action') === ['preferences', 'plugin.password', 'plugin.stalwart', 'identities'], '2FA follows the existing password provider');

list($plugin, $api, $args) = lifecycle($enabled + ['password_driver' => 'stalwart', 'stalwart_twofactor_enabled' => true]);
lifecycle_check($api->loads === ['password'], 'Standard Password plugin loads through require_plugin');
lifecycle_check($args['action'] === 'plugin.password-stalwart', 'Legacy password links resolve to the selected page');
$menu = $plugin->settings_actions(['actions' => $native_menu]);
$actions = array_column($menu['actions'], 'action');
lifecycle_check(!in_array('plugin.password', $actions, true), 'The original password menu entry is replaced only for our driver');
lifecycle_check(array_search('plugin.stalwart', $actions, true) === array_search('plugin.password-stalwart', $actions, true) + 1, '2FA follows the plugin password page');

list($plugin, $api, $args) = lifecycle($enabled + ['password_driver' => 'stalwart'], ['password_driver' => 'mailcow']);
lifecycle_check(!isset($api->actions['plugin.password-stalwart']), 'Password local configuration can select another provider');
lifecycle_check($args['action'] === 'plugin.password', 'Another provider retains its native action');
lifecycle_check($plugin->settings_actions(['actions' => $native_menu])['actions'] === $native_menu, 'Another provider retains its menu unchanged');

foreach ($features as $feature => $action) {
    list($plugin, $api) = lifecycle(['stalwart_enabled' => false, 'stalwart_api_url' => 'https://mail.example.test/jmap',
        'stalwart_' . $feature . '_enabled' => true]);
    lifecycle_check(!$api->actions, 'Master switch prevents actions despite a feature flag: ' . $feature);
}

echo $checks . " native Roundcube lifecycle checks passed.\n";
