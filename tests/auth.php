<?php

// Verify the Stalwart login wire contract without a live server or credentials.
$roundcube_root = getenv('ROUNDCUBE_ROOT') ?: dirname(__DIR__, 3);
require $roundcube_root . '/vendor/autoload.php';
require dirname(__DIR__) . '/stalwart_auth.php';

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

$checks = 0;
function auth_check($condition, $message)
{
    global $checks;
    if (!$condition) {
        throw new RuntimeException($message);
    }
    $checks++;
}
function auth_config(array $values = [])
{
    return new class($values) {
        private $values;
        public function __construct($values) { $this->values = $values; }
        public function get($key, $default = null) {
            return ($this->values + [
                'stalwart_api_url' => 'https://mail.example.test/jmap',
                'stalwart_login_client_id' => 'roundcube-test',
                'stalwart_login_redirect_uri' => 'https://webmail.example.test/index.php/login/oauth',
                'imap_host' => 'ssl://mail.example.test:993',
            ])[$key] ?? $default;
        }
    };
}
function auth_client(array $responses, &$history)
{
    $history = [];
    $stack = HandlerStack::create(new MockHandler($responses));
    $stack->push(Middleware::history($history));
    return new rcube_stalwart_auth(auth_config(), new Client(['handler' => $stack]));
}
function auth_response(array $data)
{
    return new Response(200, ['Content-Type' => 'application/json'], json_encode($data));
}
function auth_fails($callback, $expected)
{
    try {
        $callback();
    }
    catch (RuntimeException $e) {
        auth_check($e->getMessage() === $expected, 'Expected ' . $expected . ', got ' . $e->getMessage());
        return;
    }
    throw new RuntimeException('Expected rejection: ' . $expected);
}

$verifier = str_repeat('A', 43);
$grant = ['type' => 'authenticated', 'client_code' => 'one-use-code', 'iss' => 'https://mail.example.test'];
$token = ['access_token' => 'access-test', 'refresh_token' => 'refresh-test', 'token_type' => 'Bearer', 'expires_in' => 3600];
$identity = ['sub' => '42', 'preferred_username' => 'canonical@example.test'];
$api = auth_client([auth_response(['type' => 'mfaRequired'])], $history);
auth_check($api->authorize('alias@example.test', 'dummy', $verifier) === null, 'MFA challenge is not an authenticated session');
auth_check(count($history) === 1, 'No token or identity request before second factor');
$request = json_decode((string) $history[0]['request']->getBody(), true);
auth_check(!isset($request['mfaToken']), 'First step has no OTP');
auth_check($request['codeChallengeMethod'] === 'S256' && $request['codeChallenge'] === rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='), 'PKCE S256');

foreach (['', '123456'] as $code) {
    $api = auth_client([auth_response($grant), auth_response($token + ['id_token' => 'untrusted.jwt']), auth_response($identity)], $history);
    $result = $api->authorize('alias@example.test', 'dummy', $verifier, $code);
    auth_check($result === ['username' => 'canonical@example.test', 'token' => $token], 'Canonical identity and whitelisted token fields');
    auth_check(count($history) === 3, 'Authorization, token exchange and identity are required');
    $request = json_decode((string) $history[0]['request']->getBody(), true);
    auth_check(($request['mfaToken'] ?? '') === $code, 'OTP sent only to Stalwart');
    parse_str((string) $history[1]['request']->getBody(), $exchange);
    auth_check($exchange['code_verifier'] === $verifier && $exchange['client_id'] === 'roundcube-test', 'Token exchange bound to verifier and client');
    auth_check($history[2]['request']->getHeaderLine('Authorization') === 'Bearer access-test', 'Identity requires the granted token');
    foreach ($history as $entry) {
        auth_check($entry['options']['verify'] === true && $entry['options']['allow_redirects'] === false, 'Credentials use verified TLS without redirects');
        auth_check($entry['options']['timeout'] === 15 && $entry['options']['connect_timeout'] === 5, 'Bounded network calls');
    }
}
foreach ([['type' => 'failure'], $grant + ['unused' => true]] as $response) {
    if ($response['type'] !== 'failure') {
        $response['iss'] = 'https://wrong.example.test';
    }
    $api = auth_client([auth_response($response)], $history);
    auth_fails(function () use ($api, $verifier) { $api->authorize('user', 'dummy', $verifier); }, $response['type'] === 'failure' ? 'credentialserror' : 'loginresponseerror');
    auth_check(count($history) === 1, 'Rejected grant cannot be exchanged');
}
foreach ([302 => 'connectionerror', 400 => 'credentialserror', 401 => 'credentialserror', 403 => 'credentialserror', 429 => 'ratelimited', 500 => 'connectionerror'] as $status => $error) {
    $api = auth_client([new Response($status, [], 'private server details')], $history);
    auth_fails(function () use ($api, $verifier) { $api->authorize('user', 'dummy', $verifier); }, $error);
}
foreach (['not json', '{}', str_repeat('x', 65537)] as $body) {
    $api = auth_client([new Response(200, [], $body)], $history);
    auth_fails(function () use ($api, $verifier) { $api->authorize('user', 'dummy', $verifier); }, 'loginresponseerror');
}
foreach ([['access_token' => "bad\r\nheader"], ['refresh_token' => ''], ['token_type' => 'Basic'], ['expires_in' => 0], ['expires_in' => '3600']] as $bad) {
    $api = auth_client([auth_response($grant), auth_response(array_replace($token, $bad))], $history);
    auth_fails(function () use ($api, $verifier) { $api->authorize('user', 'dummy', $verifier); }, 'loginresponseerror');
    auth_check(count($history) === 2, 'Invalid token cannot be used for userinfo');
}
foreach ([[], ['sub' => '42'], ['sub' => '42', 'preferred_username' => "injected\nuser"]] as $bad) {
    $api = auth_client([auth_response($grant), auth_response($token), auth_response($bad)], $history);
    auth_fails(function () use ($api, $verifier) { $api->authorize('user', 'dummy', $verifier); }, 'loginresponseerror');
}
$api = auth_client([], $history);
foreach ([['', 'dummy', $verifier, ''], ['user', '', $verifier, ''], ['user', 'dummy', 'short', ''], ['user', 'dummy', $verifier, '12345x']] as $input) {
    auth_fails(function () use ($api, $input) { $api->authorize(...$input); }, 'credentialserror');
}
auth_check(!$history, 'Invalid form input causes no network requests');
foreach ([['stalwart_api_url' => 'http://mail.example.test/jmap'], ['stalwart_api_url' => 'https://user:secret@mail.example.test/jmap'], ['stalwart_login_redirect_uri' => 'https://webmail.example.test/?secret=1'], ['imap_host' => ''], ['imap_host' => ['first', 'second']]] as $config) {
    auth_fails(function () use ($config) { new rcube_stalwart_auth(auth_config($config)); }, 'loginconfigurationerror');
}
$api = auth_client([auth_response($token)], $history);
auth_check($api->refresh('old-refresh') === $token, 'Refresh uses validated token response');
parse_str((string) $history[0]['request']->getBody(), $exchange);
auth_check($exchange['grant_type'] === 'refresh_token' && $exchange['refresh_token'] === 'old-refresh', 'Refresh exchange');
echo $checks . " Stalwart authentication API checks passed.\n";
