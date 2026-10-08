<?php

// Run through client.php using its isolated mock transport, never a live server.
require_once __DIR__ . '/../stalwart_public_key.php';

function own_settings($key = null)
{
    return response('x:AccountSettings/get', ['accountId' => 'own', 'list' => [
        ['id' => 'singleton', 'encryptionAtRest' => $key === null ? ['@type' => 'Disabled'] : ['@type' => 'Aes256', 'publicKey' => $key]],
    ]]);
}

function request_args(array $history, $index)
{
    return json_decode((string) $history[$index]['request']->getBody(), true)['methodCalls'][0][1];
}

$pgp = file_get_contents(__DIR__ . '/fixtures/public.asc');
$pem = file_get_contents(__DIR__ . '/fixtures/public.pem');
foreach ([$pgp, $pem, str_replace("\n", "\r\n", $pgp)] as $public) {
    check(substr(rcube_stalwart_public_key::validate($public), -1) === "\n", 'Valid public key normalized');
}
foreach (['-----BEGIN PRIVATE KEY-----', '-----BEGIN PGP PRIVATE KEY BLOCK-----'] as $private) {
    fails(function () use ($private) { rcube_stalwart_public_key::validate($private); }, 'privatekeyrejected');
}
$disguised = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" . base64_encode(chr(0xc5) . chr(1) . 'x') . "\n-----END PGP PUBLIC KEY BLOCK-----";
fails(function () use ($disguised) { rcube_stalwart_public_key::validate($disguised); }, 'privatekeyrejected');
foreach (['', str_repeat('x', 16385), $pem . $pem, str_replace('BEGIN CERTIFICATE', 'BEGIN PUBLIC KEY', $pem),
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\nZm9v\n-----END PGP PUBLIC KEY BLOCK-----",
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" . base64_encode(chr(0xc6) . chr(255) . 'x') . "\n-----END PGP PUBLIC KEY BLOCK-----"] as $invalid) {
    fails(function () use ($invalid) { rcube_stalwart_public_key::validate($invalid); }, 'invalidpublickey');
}
$api = client([own_settings(), response('x:PublicKey/set', ['created' => ['new' => ['id' => 'key1']]])], $history);
$api->create_public_key(' Personal ', $pgp, '');
$args = request_args($history, 1);
check($args['accountId'] === 'own' && $args['create']['new']['description'] === 'Personal', 'Public key created for signed-in account');
check($args['create']['new']['expiresAt'] === null && $args['create']['new']['key'] === rcube_stalwart_public_key::validate($pgp), 'Public key exact material/expiry');
check(strpos((string) $history[1]['request']->getBody(), '"emailAddresses":{}') !== false, 'Public key address restriction is an empty map');

$key = ['id' => 'key1', 'accountId' => 'own', 'description' => 'Personal', 'createdAt' => '2026-01-01T00:00:00Z', 'expiresAt' => null];
$masked = ['id' => 'mask1', 'accountId' => 'own', 'description' => 'Shop', 'email' => 'shop.random@example.test', 'enabled' => true, 'forDomain' => 'shop.example.test', 'expiresAt' => null];
foreach (['PublicKey' => $key, 'MaskedEmail' => $masked] as $type => $item) {
    $api = client([own_settings(), response('x:' . $type . '/query', ['ids' => [$item['id']]]), response('x:' . $type . '/get', ['list' => [$item]])], $history);
    $result = $type === 'PublicKey' ? $api->public_keys() : $api->masked_email();
    check($result['items'] === [$item] && !$result['more'], 'Owned resource listing ' . $type);
    check(request_args($history, 1) === ['accountId' => 'own', 'filter' => ['accountId' => 'own'], 'position' => 0, 'limit' => 21], 'Explicit account filter, including privileged users');
    check(!in_array('key', request_args($history, 2)['properties'], true), 'List does not request key material');
    $foreign = $item;
    $foreign['accountId'] = 'someone-else';
    $api = client([own_settings(), response('x:' . $type . '/query', ['ids' => [$item['id']]]), response('x:' . $type . '/get', ['list' => [$foreign]])], $history);
    fails(function () use ($api, $type) { $type === 'PublicKey' ? $api->public_keys() : $api->masked_email(); }, 'responseerror');
    $api = client([own_settings(), response('x:' . $type . '/get', ['list' => [$foreign]])], $history);
    fails(function () use ($api, $type, $item) { $type === 'PublicKey' ? $api->update_public_key('delete', $item['id'], '') : $api->update_masked_email('delete', $item['id']); }, 'itemnotfound');
    check(count($history) === 2, 'Cross-account resource cannot be changed');
    $api = client([own_settings(), response('x:' . $type . '/get', ['list' => [], 'notFound' => [$item['id']]])], $history);
    fails(function () use ($api, $type, $item) { $type === 'PublicKey' ? $api->update_public_key('delete', $item['id'], '') : $api->update_masked_email('delete', $item['id']); }, 'itemnotfound');
}
$ids = array_map(function ($n) { return 'key' . $n; }, range(1, 21));
$api = client([own_settings('key1'), response('x:PublicKey/query', ['ids' => $ids]), response('x:PublicKey/get', ['list' => [$key]])], $history);
$result = $api->public_keys(1);
check($result['more'] && $result['page'] === 1 && $result['active_key'] === 'key1', 'Pagination and active key metadata');
check(count(request_args($history, 2)['ids']) === 20 && request_args($history, 1)['position'] === 20, 'Bounded requests with lookahead');
$api = client([own_settings('key1'), response('x:PublicKey/get', ['list' => [$key]])], $history);
fails(function () use ($api) { $api->update_public_key('delete', 'key1', ''); }, 'keyinuse');
check(count($history) === 2, 'Active encryption key never deleted');
$api = client([own_settings('key1'), response('x:PublicKey/get', ['list' => [$key]]), response('x:PublicKey/set', ['updated' => ['key1' => null]])], $history);
$api->update_public_key('rename', 'key1', ' New name ');
check(request_args($history, 2) === ['accountId' => 'own', 'update' => ['key1' => ['description' => 'New name']]], 'Rename leaves key and encryption settings intact');
$api = client([own_settings(), response('x:PublicKey/get', ['list' => [$key]]), response('x:PublicKey/set', ['destroyed' => ['key1']])], $history);
$api->update_public_key('delete', 'key1', '');
check(request_args($history, 2) === ['accountId' => 'own', 'destroy' => ['key1']], 'Only selected public key deleted');

$api = client([own_settings(), response('x:MaskedEmail/set', ['created' => ['new' => ['id' => 'mask1']]])], $history);
$api->create_masked_email(' Newsletter ', 'News', ' SHOP.Example.test ', '2099-01-01');
check(request_args($history, 1) === ['accountId' => 'own', 'create' => ['new' => ['enabled' => true, 'description' => 'Newsletter', 'expiresAt' => '2099-01-01T00:00:00Z', 'emailPrefix' => 'news', 'forDomain' => 'shop.example.test']]], 'Masked address created by server, with optional prefix/site/expiry');
$api = client([own_settings(), response('x:MaskedEmail/set', ['created' => ['new' => ['id' => 'mask1']]])], $history);
$api->create_masked_email('Newsletter', '', '', '');
check(request_args($history, 1)['create']['new'] === ['enabled' => true, 'description' => 'Newsletter', 'expiresAt' => null], 'No optional values sent when empty');
$api = client([], $history);
foreach (['bad@foreign.test', 'bad-prefix', '<script>', str_repeat('x', 65)] as $prefix) {
    fails(function () use ($api, $prefix) { $api->create_masked_email('Test', $prefix, '', ''); }, 'invalidprefix');
}
foreach (['https://shop.test', 'a/b', '-bad.test', str_repeat('x', 254)] as $domain) {
    fails(function () use ($api, $domain) { $api->create_masked_email('Test', '', $domain, ''); }, 'invalidsitedomain');
}
foreach (['2020-01-01', '2099-02-30', 'tomorrow', '9999-01-01'] as $expires) {
    fails(function () use ($api, $expires) { $api->create_masked_email('Test', '', '', $expires); }, 'invalidexpiry');
}
fails(function () use ($api, $disguised) { $api->create_public_key('Test', $disguised, ''); }, 'privatekeyrejected');
check(!$history, 'Invalid input and private material never leave the browser-facing server');
foreach (['disable', 'enable', 'delete'] as $op) {
    $api = client([own_settings(), response('x:MaskedEmail/get', ['list' => [$masked]]), response('x:MaskedEmail/set', $op === 'delete' ? ['destroyed' => ['mask1']] : ['updated' => ['mask1' => null]])], $history);
    $api->update_masked_email($op, 'mask1');
    check(request_args($history, 2) === ($op === 'delete' ? ['accountId' => 'own', 'destroy' => ['mask1']] : ['accountId' => 'own', 'update' => ['mask1' => ['enabled' => $op === 'enable']]]), 'Individual masked address ' . $op);
}
$masked['expiresAt'] = '2020-01-01T00:00:00Z';
$api = client([own_settings(), response('x:MaskedEmail/get', ['list' => [$masked]])], $history);
fails(function () use ($api) { $api->update_masked_email('enable', 'mask1'); }, 'maskedexpired');
check(count($history) === 2, 'Expired addresses cannot be re-enabled');
$api = client([own_settings(), response('error', ['type' => 'forbidden', 'description' => 'This feature is only available in the Enterprise edition.'])], $history);
fails(function () use ($api) { $api->masked_email(); }, 'enterpriserequired');
$api = client([own_settings(), response('x:PublicKey/set', ['notCreated' => ['new' => ['type' => 'invalidProperties']]])], $history);
fails(function () use ($api, $pgp) { $api->create_public_key('Test', $pgp, ''); }, 'policyerror');
$api = client([own_settings(), response('x:PublicKey/get', ['list' => [$key]]), response('x:PublicKey/set', ['notDestroyed' => ['key1' => ['type' => 'forbidden']]])], $history);
fails(function () use ($api) { $api->update_public_key('delete', 'key1', ''); }, 'permissionerror');
