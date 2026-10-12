<?php

// Exercise server resolution with upstream utilities, without external connections.
$roundcube_root = getenv('ROUNDCUBE_ROOT') ?: dirname(__DIR__, 3);
require $roundcube_root . '/vendor/autoload.php';
require $roundcube_root . '/program/lib/Roundcube/rcube_utils.php';
require dirname(__DIR__) . '/stalwart_client.php';
require dirname(__DIR__) . '/stalwart_auth.php';

set_error_handler(function ($level, $message, $file, $line) {
    if (error_reporting() & $level) {
        throw new ErrorException($message, 0, $level, $file, $line);
    }
});
$checks = 0;
class rcube
{
    public static function get_instance() { return (object) ['output' => null]; }
}
function config_check($value, $message)
{
    global $checks;
    if (!$value) {
        throw new RuntimeException($message);
    }
    $checks++;
}
function config_rejected($callback, $message)
{
    try {
        $callback();
    }
    catch (RuntimeException $e) {
        config_check($e->getMessage() === $message, 'Expected ' . $message);
        return;
    }
    throw new RuntimeException('Expected rejection: ' . $message);
}
class server_config
{
    public $values;
    public function __construct($values) { $this->values = $values; }
    public function get($key, $default = null) { return $this->values[$key] ?? $default; }
    public function set($key, $value) { $this->values[$key] = $value; }
}
class server_app
{
    public $config;
    public $user;
    public function __construct($values, $id) { $this->config = new server_config($values); $this->user = (object) ['ID' => $id]; }
    public function autoselect_host() { return rcube_stalwart_config::hosts($this->config)[0] ?? ''; }
    public function get_user_name() { return 'same@example.test'; }
    public function decrypt($value) { return $value; }
}
$hosts = ['ssl://first.example.test:993' => 'First', 'ssl://second.example.test:993' => 'Second', 'ssl://classic.example.test:993' => 'Classic'];
$profiles = [];
foreach (['first', 'second'] as $server) {
    $profiles['ssl://' . $server . '.example.test:993'] = [
        'api_url' => 'https://' . $server . '.example.test/jmap',
        'login_enabled' => true, 'login_client_id' => $server, 'login_client_secret' => 'secret-' . $server,
        'login_redirect_uri' => 'https://webmail.example.test/index.php/login/oauth',
        'twofactor_enabled' => true, 'password_driver' => 'stalwart',
    ];
}
$values = ['imap_host' => $hosts, 'stalwart_hosts' => $profiles, 'stalwart_enabled' => true,
    'stalwart_api_url' => 'https://unrelated.example.test/jmap', 'stalwart_login_client_secret' => 'unrelated-secret'];

foreach (['first', 'second', 'classic'] as $server) {
    $_POST = [];
    $_GET = ['_host' => 'ssl://' . $server . '.example.test:993'];
    $_SESSION = [];
    $rc = new server_app($values, 0);
    rcube_stalwart_config::apply($rc);
    config_check($rc->config->get('stalwart_enabled') === ($server !== 'classic'), 'Plugin active only on explicitly mapped server');
    if ($server !== 'classic') {
        $auth = new rcube_stalwart_auth($rc->config);
        config_check($auth->host() === $_GET['_host'], 'Embedded login keeps selected IMAP host');
        config_check($auth->options()['client_secret'] === 'secret-' . $server, 'Embedded login uses only its own client');
    }
    else {
        config_check($rc->config->get('stalwart_api_url') === '' && $rc->config->get('stalwart_login_client_secret') === '', 'Unmapped server cannot inherit credentials');
    }
}

// Once authenticated, a query string cannot switch the API destination.
foreach (['first', 'second'] as $server) {
    $_SESSION = ['storage_host' => $server . '.example.test', 'storage_port' => 993, 'storage_ssl' => 'ssl', 'password' => 'dummy'];
    $_GET = ['_host' => 'ssl://classic.example.test:993'];
    $_POST = [];
    $_SERVER['REQUEST_METHOD'] = 'GET';
    $rc = new server_app($values, 17);
    rcube_stalwart_config::apply($rc);
    $client = rcube_stalwart_client::from_session($rc);
    $url = new ReflectionProperty($client, 'url');
    $url->setAccessible(true);
    config_check($url->getValue($client) === 'https://' . $server . '.example.test/jmap', 'Settings API comes from authenticated session');
    $binding = rcube_stalwart_config::binding($rc);
    $_SERVER['REQUEST_METHOD'] = 'POST';
    config_rejected(function () use ($rc) { rcube_stalwart_client::from_session($rc); }, 'statechanged');
    $_POST['_stalwart_server'] = $binding;
    config_check(rcube_stalwart_client::from_session($rc) instanceof rcube_stalwart_client, 'Current server form accepted');
    $rc->user->ID = 18;
    config_rejected(function () use ($rc) { rcube_stalwart_client::from_session($rc); }, 'authenticationerror');
    $rc->user->ID = 17;
    $rc->config->set('stalwart_api_url', 'https://changed.example.test/jmap');
    config_rejected(function () use ($rc) { rcube_stalwart_client::from_session($rc); }, 'authenticationerror');
}

$_SESSION = [];
$_POST = [];
$_GET = ['_host' => 'ssl://attacker.example.test:993'];
$rc = new server_app($values, 0);
rcube_stalwart_config::apply($rc);
config_check(!$rc->config->get('stalwart_enabled'), 'Unknown host rejected');

$_GET = ['_host' => 'ssl://first.example.test:993'];
$legacy = $values;
unset($legacy['stalwart_hosts']);
$rc = new server_app($legacy, 0);
rcube_stalwart_config::apply($rc);
config_check(!$rc->config->get('stalwart_enabled'), 'Multiple hosts cannot implicitly share global API credentials');
$legacy['imap_host'] = 'ssl://first.example.test:993';
$rc = new server_app($legacy, 0);
rcube_stalwart_config::apply($rc);
config_check($rc->config->get('stalwart_enabled'), 'Legacy single-host settings remain available');

$incomplete = $values;
$incomplete['stalwart_hosts']['ssl://first.example.test:993'] = ['api_url' => 'https://first.example.test/jmap', 'login_enabled' => true];
$rc = new server_app($incomplete, 0);
rcube_stalwart_config::apply($rc);
config_check($rc->config->get('stalwart_login_client_secret') === '', 'Incomplete mapped client never inherits global secret');
config_rejected(function () use ($rc) { new rcube_stalwart_auth($rc->config); }, 'loginconfigurationerror');

$_SESSION = ['storage_host' => 'first.example.test', 'storage_port' => 993, 'storage_ssl' => 'ssl'];
$_GET = [];
$ambiguous = $values;
$ambiguous['imap_host']['ssl://first.example.test'] = 'Duplicate';
$rc = new server_app($ambiguous, 17);
rcube_stalwart_config::apply($rc);
config_check(!$rc->config->get('stalwart_enabled'), 'Ambiguous aliases fail closed');
$_SESSION['storage_port'] = 1993;
$rc = new server_app($values, 17);
rcube_stalwart_config::apply($rc);
config_check(!$rc->config->get('stalwart_enabled'), 'Session port must match configured server');

echo $checks . " per-server configuration checks passed.\n";
