<?php

use GuzzleHttp\Psr7\Response;

// Run client.php first; these checks use the same isolated mock transport.
$cfg = new class {
    public $values = ['stalwart_enabled' => true, 'stalwart_api_url' => 'https://mail.example.test/jmap'];
    public function get($key, $default = null) { return $this->values[$key] ?? $default; }
};
foreach (['twofactor', 'app_passwords', 'aliases', 'public_keys', 'masked_email'] as $feature) {
    check(!rcube_stalwart_client::feature_enabled($cfg, $feature), 'Feature defaults to disabled');
    $cfg->values['stalwart_' . $feature . '_enabled'] = true;
    check(rcube_stalwart_client::feature_enabled($cfg, $feature), 'Independent feature flag');
    $cfg->values['stalwart_' . $feature . '_enabled'] = false;
}
$cfg->values['stalwart_app_passwords_enabled'] = true;
$cfg->values['stalwart_enabled'] = false;
check(!rcube_stalwart_client::feature_enabled($cfg, 'app_passwords'), 'Master disables features');
$cfg->values['stalwart_enabled'] = true;
$cfg->values['stalwart_api_url'] = '';
check(!rcube_stalwart_client::feature_enabled($cfg, 'app_passwords'), 'API URL required');

$apps = [['id' => 'app1', 'description' => 'Phone', 'createdAt' => '2026-01-01T00:00:00Z', 'expiresAt' => null]];
$api = client([response('x:AppPassword/get', ['list' => $apps])], $history);
check($api->app_passwords() === $apps, 'Application password listing');
$args = json_decode((string) $history[0]['request']->getBody(), true)['methodCalls'][0][1];
check(!isset($args['accountId']) && !in_array('secret', $args['properties'], true), 'No caller account ID or stored hashes');
$api = client([response('x:AppPassword/set', ['created' => ['new' => ['id' => 'app2', 'secret' => 'app_dummy-secret']]])], $history);
check($api->create_app_password(' Phone ', '2099-02-01')['secret'] === 'app_dummy-secret', 'Secret returned on create');
$args = json_decode((string) $history[0]['request']->getBody(), true)['methodCalls'][0][1];
check($args['create']['new'] === ['description' => 'Phone', 'permissions' => ['@type' => 'Inherit'], 'expiresAt' => '2099-02-01T00:00:00Z'], 'Exact create schema');
$api = client([], $history);
foreach (['', "Name\n", str_repeat('a', 201)] as $name) {
    fails(function () use ($api, $name) { $api->create_app_password($name, ''); }, 'invaliddescription');
}
foreach (['2020-01-01', '2099-02-30', 'tomorrow'] as $date) {
    fails(function () use ($api, $date) { $api->create_app_password('Phone', $date); }, 'invalidexpiry');
}
check(!$history, 'Invalid app input sends no requests');
$api = client([response('x:AppPassword/get', ['list' => $apps])], $history);
fails(function () use ($api) { $api->revoke_app_password('api-key-or-primary'); }, 'itemnotfound');
check(count($history) === 1, 'Cannot revoke a different credential kind');
$api = client([response('x:AppPassword/get', ['list' => $apps]), response('x:AppPassword/set', ['destroyed' => ['app1']])], $history);
$api->revoke_app_password('app1');
check(json_decode((string) $history[1]['request']->getBody(), true)['methodCalls'][0][1] === ['destroy' => ['app1']], 'Only selected app password revoked');
foreach (['forbidden' => 'permissionerror', 'overQuota' => 'overquota'] as $error => $message) {
    $api = client([response('x:AppPassword/set', ['notCreated' => ['new' => ['type' => $error]]])], $history);
    fails(function () use ($api) { $api->create_app_password('Phone', ''); }, $message);
}

$account = ['id' => 'my-account', 'name' => 'user', 'domainId' => 'domain1', 'aliases' => [
    ['name' => 'contact', 'domainId' => 'domain1', 'description' => 'Contact', 'enabled' => true],
    ['name' => 'archive', 'domainId' => 'domain2', 'description' => null, 'enabled' => false],
]];
function alias_responses($account)
{
    return [
        response('x:AccountSettings/get', ['accountId' => 'my-account', 'list' => [['id' => 'singleton']]]),
        response('x:Account/get', ['list' => [$account]]),
        response('x:Domain/get', ['list' => [['id' => 'domain1', 'name' => 'example.test'], ['id' => 'domain2', 'name' => 'other.test']]]),
    ];
}
$version = hash('sha256', json_encode([$account['id'], $account['aliases']]));
$api = client(alias_responses($account), $history);
check($api->aliases()['version'] === $version, 'Alias snapshot');
$args = json_decode((string) $history[1]['request']->getBody(), true)['methodCalls'][0][1];
check($args['ids'] === ['my-account'], 'Account ID resolved from own singleton');
$api = client(array_merge(alias_responses($account), [response('x:Account/set', ['updated' => ['my-account' => null]])]), $history);
$api->save_alias('create', '', 'news', 'News', $version);
$patch = json_decode((string) $history[3]['request']->getBody(), true)['methodCalls'][0][1]['update'];
check(array_keys($patch) === ['my-account'] && array_keys($patch['my-account']) === ['aliases'], 'Only own aliases updated');
check(array_slice($patch['my-account']['aliases'], 0, 2) === $account['aliases'], 'Preserves existing metadata and other domains');
check($patch['my-account']['aliases'][2] === ['name' => 'news', 'domainId' => 'domain1', 'description' => 'News', 'enabled' => true], 'New alias fixed to primary domain');
foreach (['disable', 'enable', 'delete'] as $op) {
    $api = client(array_merge(alias_responses($account), [response('x:Account/set', ['updated' => ['my-account' => null]])]), $history);
    $api->save_alias($op, rcube_stalwart_client::alias_key($account['aliases'][0]), '', '', $version);
    $aliases = json_decode((string) $history[3]['request']->getBody(), true)['methodCalls'][0][1]['update']['my-account']['aliases'];
    check($op === 'delete' ? $aliases === [$account['aliases'][1]] : $aliases[0]['enabled'] === ($op === 'enable'), 'Alias ' . $op);
}
foreach (['USER' => 'aliasexists', 'CONTACT' => 'aliasexists', 'bad@outside.test' => 'invalidalias', '<script>' => 'invalidalias'] as $name => $error) {
    $api = client(alias_responses($account), $history);
    fails(function () use ($api, $name, $version) { $api->save_alias('create', '', $name, '', $version); }, $error);
    check(count($history) === 3, 'Rejected alias does not write');
}
$api = client(alias_responses($account), $history);
fails(function () use ($api, $version) { $api->save_alias('delete', 'foreign-alias', '', '', $version); }, 'itemnotfound');
$api = client(alias_responses($account), $history);
fails(function () use ($api) { $api->save_alias('create', '', 'news', '', 'stale-version'); }, 'aliaseschanged');
check(count($history) === 3, 'Stale form does not write');
$foreign = $account;
$foreign['id'] = 'another-account';
$api = client(alias_responses($foreign), $history);
fails(function () use ($api) { $api->aliases(); }, 'responseerror');
$api = client([response('x:AccountSettings/get', ['accountId' => 'my-account']), new Response(403)], $history);
fails(function () use ($api) { $api->aliases(); }, 'permissionerror');
