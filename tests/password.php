<?php

// Run from client.php. Exercise local password policy without changing any account.
require_once $roundcube_root . '/program/lib/Roundcube/rcube_charset.php';
require dirname(__DIR__) . '/stalwart_page.php';
require dirname(__DIR__) . '/stalwart_password.php';

class stalwart_password_policy_test extends rcube_stalwart_password_page
{
    public function __construct($settings)
    {
        $this->rc = new class($settings) {
            public $config;
            public $output;
            public $plugins;
            public function __construct($settings)
            {
                $this->config = new class($settings) {
                    private $settings;
                    public function __construct($settings) { $this->settings = $settings; }
                    public function get($key, $default = null) { return $this->settings[$key] ?? $default; }
                };
                $this->output = new class {
                    public function get_charset() { return 'UTF-8'; }
                };
                $this->plugins = (object) ['dir' => $GLOBALS['roundcube_root'] . '/plugins/'];
            }
            public function get_user_name() { return 'test@example.test'; }
        };
    }

    public function validate_password($current, $new, $confirm)
    {
        return $this->validate($current, $new, $confirm, 'UTF-8');
    }
}

$policy = new stalwart_password_policy_test([]);
check($policy->validate_password('current', 'NewPassword1!', 'NewPassword1!') === 'NewPassword1!', 'Valid password preserved');
foreach ([
    ['', 'NewPassword1!', 'NewPassword1!', 'currentpasswordrequired'],
    ['current', 'NewPassword1!', 'Different!', 'passwordmismatch'],
    ['current', 'short', 'short', 'passwordshort'],
    ['current', "NewPass\nword1!", "NewPass\nword1!", 'passwordforbidden'],
    ['SamePassword1!', 'SamePassword1!', 'SamePassword1!', 'passwordsame'],
] as $data) {
    fails(function () use ($policy, $data) { $policy->validate_password($data[0], $data[1], $data[2]); }, $data[3]);
}
$policy = new stalwart_password_policy_test(['password_minimum_length' => 20]);
fails(function () use ($policy) { $policy->validate_password('current', 'NewPassword1!', 'NewPassword1!'); }, 'passwordshort');
$policy = new stalwart_password_policy_test(['password_force_save' => true]);
check($policy->validate_password('SamePassword1!', 'SamePassword1!', 'SamePassword1!') === 'SamePassword1!', 'Force-save policy retained');
$policy = new stalwart_password_policy_test(['password_minimum_score' => 5]);
fails(function () use ($policy) { $policy->validate_password('current', 'onlyletters', 'onlyletters'); }, 'passwordweak');
check($policy->validate_password('current', 'NewPassword1!', 'NewPassword1!') === 'NewPassword1!', 'Default strength policy retained');
$policy = new stalwart_password_policy_test(['password_minimum_score' => 5, 'password_strength_driver' => 'missing_driver']);
fails(function () use ($policy) { $policy->validate_password('current', 'NewPassword1!', 'NewPassword1!'); }, 'configurationerror');
$policy = new stalwart_password_policy_test(['password_minimum_score' => 5, 'password_strength_driver' => '../invalid']);
fails(function () use ($policy) { $policy->validate_password('current', 'NewPassword1!', 'NewPassword1!'); }, 'configurationerror');

$settings = ['stalwart_enabled' => true, 'stalwart_api_url' => 'https://mail.example.test/jmap'];
$_SESSION['storage_host'] = 'mail.example.test';
check((new stalwart_password_policy_test($settings))->available(), 'Password page enabled');
check(!(new stalwart_password_policy_test($settings + ['password_hosts' => ['other.example.test']]))->available(), 'Host restrictions retained');
check(!(new stalwart_password_policy_test($settings + ['password_login_exceptions' => [' test@example.test ']]))->available(), 'Login exceptions retained');
check(!(new stalwart_password_policy_test([]))->available(), 'Password page disabled by default');
