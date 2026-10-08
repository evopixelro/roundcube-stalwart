<?php

// Standalone, offline checks. No Roundcube bootstrap, database or real credentials.
$roundcube_root = getenv('ROUNDCUBE_ROOT') ?: dirname(__DIR__, 3);
if (!is_file($roundcube_root . '/vendor/autoload.php')
    || !is_file($roundcube_root . '/program/lib/Roundcube/rcube_charset.php')
) {
    throw new RuntimeException('Set ROUNDCUBE_ROOT to a development Roundcube installation with Composer dependencies.');
}
require $roundcube_root . '/vendor/autoload.php';
require dirname(__DIR__) . '/stalwart_client.php';
require dirname(__DIR__) . '/stalwart_totp.php';

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

$checks = 0;
function check($condition, $message)
{
    global $checks;
    if (!$condition) {
        throw new RuntimeException($message);
    }
    $checks++;
}
function response($method, array $result)
{
    return new Response(200, [], json_encode(['methodResponses' => [[$method, $result, 'stalwart']]]));
}
function client(array $responses, &$history, $authorization = null)
{
    $history = [];
    $stack = HandlerStack::create(new MockHandler($responses));
    $stack->push(Middleware::history($history));
    return new rcube_stalwart_client('https://mail.example.test/jmap', $authorization ?: ['token' => 'dummy-user-token'], new Client(['handler' => $stack]));
}
function fails($callback, $expected)
{
    try {
        $callback();
    }
    catch (RuntimeException $e) {
        check($e->getMessage() === $expected, 'Unexpected error: ' . $e->getMessage());
        return;
    }
    throw new RuntimeException('Expected failure: ' . $expected);
}

$get = 'x:AccountPassword/get';
$set = 'x:AccountPassword/set';
foreach ([null => false, '********' => true] as $masked => $enabled) {
    $api = client([response($get, ['list' => [['id' => 'singleton', 'otpAuth' => ['otpUrl' => $enabled ? $masked : null]]]])], $history);
    check($api->status() === $enabled, 'Incorrect 2FA state');
    $request = $history[0]['request'];
    check($request->getHeaderLine('Authorization') === 'Bearer dummy-user-token', 'Bearer authentication');
    check(json_decode((string) $request->getBody(), true)['methodCalls'][0][1] === ['ids' => ['singleton']], 'Only own singleton requested');
    check($history[0]['options']['verify'] === true && $history[0]['options']['allow_redirects'] === false, 'TLS and redirect policy');
}

$api = client([response($set, ['updated' => ['singleton' => null]])], $history, ['username' => 'user@example.test', 'password' => 'dummy-app-password']);
$api->update('dummy-primary-password', '123456', ['secret' => 'dummy-new-password']);
$patch = json_decode((string) $history[0]['request']->getBody(), true)['methodCalls'][0][1]['update']['singleton'];
check($patch === ['secret' => 'dummy-new-password', 'currentSecret' => 'dummy-primary-password', 'otpAuth/otpCode' => '123456'], 'Password change must preserve OTP URL');
check($history[0]['request']->getHeaderLine('Authorization') === 'Basic ' . base64_encode('user@example.test:dummy-app-password'), 'App credential authentication');
check(!$api->uses_account_password('dummy-primary-password') && $api->uses_account_password('dummy-app-password'), 'Credential distinction');

foreach (['otpauth://totp/Example:user?secret=TEST', null] as $uri) {
    $api = client([response($set, ['updated' => ['singleton' => null]])], $history);
    $api->update('dummy-current', $uri === null ? '123456' : '', ['otpAuth/otpUrl' => $uri]);
    $patch = json_decode((string) $history[0]['request']->getBody(), true)['methodCalls'][0][1]['update']['singleton'];
    check(array_key_exists('otpAuth/otpUrl', $patch) && $patch['otpAuth/otpUrl'] === $uri, 'Enable/disable patch');
    check(!array_key_exists('secret', $patch), '2FA changes must not change the password');
}
foreach ([401 => 'authenticationerror', 403 => 'permissionerror', 429 => 'ratelimited', 500 => 'connectionerror', 302 => 'connectionerror'] as $status => $error) {
    $api = client([new Response($status)], $history);
    fails(function () use ($api) { $api->status(); }, $error);
}
foreach (['not json', '{}', '{"methodResponses":false}', str_repeat('x', 65537)] as $body) {
    $api = client([new Response(200, [], $body)], $history);
    fails(function () use ($api) { $api->status(); }, 'responseerror');
}
foreach ([[], ['updated' => []], ['updated' => 'invalid'], ['notUpdated' => ['singleton' => 'invalid']]] as $result) {
    $api = client([response($set, $result)], $history);
    fails(function () use ($api) { $api->update('dummy', '', ['secret' => 'new']); }, 'responseerror');
}
foreach ([
    ['forbidden', 'Current secret is incorrect.', 'credentialserror'],
    ['forbidden', 'Current OTP code is required to change the password or OTP auth.', 'coderequired'],
    ['forbidden', 'Operation not allowed.', 'permissionerror'],
    ['invalidProperties', 'Sensitive arbitrary server text', 'policyerror'],
] as $error) {
    $api = client([response($set, ['notUpdated' => ['singleton' => ['type' => $error[0], 'description' => $error[1]]]])], $history);
    fails(function () use ($api) { $api->update('dummy', '', ['secret' => 'new']); }, $error[2]);
}
$api = client([response('error', ['type' => 'unknownMethod'])], $history);
fails(function () use ($api) { $api->status(); }, 'unsupportedserver');
$api = client([response($get, ['list' => [], 'notFound' => ['singleton']])], $history);
fails(function () use ($api) { $api->status(); }, 'unsupportedaccount');
$api = client([], $history);
fails(function () use ($api) { $api->update('', '', []); }, 'currentpasswordrequired');
fails(function () use ($api) { $api->update('dummy', '12345x', []); }, 'invalidcode');
check(!$history, 'Invalid input must not send API requests');
foreach (['http://mail.example.test/jmap', 'https://user:password@mail.example.test/jmap', 'https://mail.example.test/jmap?token=secret', "https://mail.example.test/jmap\n"] as $url) {
    fails(function () use ($url) { new rcube_stalwart_client($url, ['token' => 'dummy']); }, 'configurationerror');
}

// RFC 6238 SHA-1 vectors, truncated to six digits.
$secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
foreach ([59 => '287082', 1111111109 => '081804', 1111111111 => '050471', 1234567890 => '005924', 2000000000 => '279037', 20000000000 => '353130'] as $time => $code) {
    check(rcube_stalwart_totp::verify($secret, $code, $time), 'RFC TOTP vector ' . $time);
}
check(!rcube_stalwart_totp::verify($secret, '287082', 180), 'Expired code rejected');
check(!rcube_stalwart_totp::verify($secret, '28708x', 59), 'Non-numeric code rejected');
$generated = rcube_stalwart_totp::secret();
check((bool) preg_match('/^[A-Z2-7]{32}$/D', $generated), '160-bit base32 secret');
check($generated !== rcube_stalwart_totp::secret(), 'Fresh enrolment secret');
$uri = rcube_stalwart_totp::uri($generated, 'Mail Example', 'Mixed.Case@example.test');
check(strpos($uri, rawurlencode('Mail Example:Mixed.Case@example.test')) !== false, 'Issuer/account label');

// Roundcube 1.6's is_token_valid() returns false for a token that needs no refresh.
class rcmail_oauth
{
    public static $calls = 0;
    public static $refresh = false;
    public static function get_instance() { return new self(); }
    public function is_token_valid()
    {
        self::$calls++;
        if (self::$refresh) {
            $_SESSION['oauth_token']['access_token'] = 'refreshed-dummy-token';
            $_SESSION['oauth_token']['expires'] = time() + 60;
        }
        return self::$refresh;
    }
}
$rc = new class {
    public $config;
    public function __construct() {
        $this->config = new class {
            public function get($key, $default = null) {
                return ['stalwart_enabled' => true, 'stalwart_api_url' => 'https://mail.example.test/jmap'][$key] ?? $default;
            }
        };
    }
    public function decrypt($value) { return $value; }
    public function get_user_name() { return 'user@example.test'; }
};
$_SESSION = ['oauth_token' => ['access_token' => 'dummy', 'expires' => time() + 60]];
check(rcube_stalwart_client::from_session($rc) instanceof rcube_stalwart_client, 'Fresh OAuth token accepted');
check(rcmail_oauth::$calls === 0, 'Unexpired OAuth token must not depend on refresh return value');
$_SESSION['oauth_token']['expires'] = time() - 60;
fails(function () use ($rc) { rcube_stalwart_client::from_session($rc); }, 'authenticationerror');
rcmail_oauth::$refresh = true;
check(rcube_stalwart_client::from_session($rc) instanceof rcube_stalwart_client, 'Expired OAuth token refreshed');
check($_SESSION['oauth_token']['access_token'] === 'refreshed-dummy-token', 'Uses updated session token');
require __DIR__ . '/features.php';
require __DIR__ . '/password.php';
require __DIR__ . '/resources.php';

echo $checks . " offline Stalwart checks passed.\n";
