<?php

/**
 * User-scoped Stalwart 0.16 account API client.
 * No administrator credentials or account IDs are accepted from the browser.
 */
class rcube_stalwart_client
{
    private $url;
    private $authorization;
    private $password;
    private $http;

    public function __construct($url, array $authorization, $http = null)
    {
        $parts = is_string($url) ? parse_url($url) : false;
        if (!$parts || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment']) || preg_match('/[\x00-\x20\\\\]/', $url)
        ) {
            throw new RuntimeException('configurationerror');
        }

        $this->url = $url;
        if (isset($authorization['token']) && is_string($authorization['token']) && $authorization['token'] !== '') {
            $this->authorization = 'Bearer ' . $authorization['token'];
        }
        else if (!empty($authorization['username']) && isset($authorization['password']) && is_string($authorization['password'])) {
            if (strpos($authorization['username'], ':') !== false) {
                throw new RuntimeException('configurationerror');
            }
            $this->password = $authorization['password'];
            $this->authorization = 'Basic ' . base64_encode($authorization['username'] . ':' . $this->password);
        }
        else {
            throw new RuntimeException('authenticationerror');
        }

        if (preg_match('/[\r\n]/', $this->authorization)) {
            throw new RuntimeException('authenticationerror');
        }

        $this->http = $http ?: new \GuzzleHttp\Client();
    }

    public static function enabled($config)
    {
        return $config->get('stalwart_enabled', false) && $config->get('stalwart_api_url', '') !== '';
    }

    public static function feature_enabled($config, $feature)
    {
        return in_array($feature, ['twofactor', 'app_passwords', 'aliases', 'public_keys', 'masked_email'], true)
            && self::enabled($config) && $config->get('stalwart_' . $feature . '_enabled', false);
    }

    public static function from_session($rc)
    {
        if (!self::enabled($rc->config)) {
            throw new RuntimeException('configurationerror');
        }

        if (!empty($_SESSION['oauth_token'])) {
            // In Roundcube 1.6 this method reports a successful refresh, not an unexpired token.
            if (isset($_SESSION['oauth_token']['expires']) && $_SESSION['oauth_token']['expires'] < time()
                && !rcmail_oauth::get_instance()->is_token_valid()
            ) {
                throw new RuntimeException('authenticationerror');
            }
            $authorization = ['token' => $_SESSION['oauth_token']['access_token'] ?? ''];
        }
        else {
            $authorization = [
                'username' => $rc->get_user_name(),
                'password' => $rc->decrypt($_SESSION['password'] ?? ''),
            ];
        }

        return new self($rc->config->get('stalwart_api_url'), $authorization);
    }

    public function uses_account_password($current)
    {
        return $this->password !== null && hash_equals($this->password, $current);
    }

    public function status()
    {
        $result = $this->request('x:AccountPassword/get', ['ids' => ['singleton']]);
        $account = $result['list'][0] ?? null;
        if (!is_array($account) || ($account['id'] ?? '') !== 'singleton'
            || !isset($account['otpAuth']) || !is_array($account['otpAuth']) || !array_key_exists('otpUrl', $account['otpAuth'])
        ) {
            throw new RuntimeException('unsupportedaccount');
        }

        $url = $account['otpAuth']['otpUrl'];
        if ($url !== null && (!is_string($url) || $url === '')) {
            throw new RuntimeException('responseerror');
        }

        // Stalwart returns a masked value when OTP is enabled, never the secret.
        return $url !== null;
    }

    public function update($current, $code, array $changes)
    {
        if (!is_string($current) || $current === '') {
            throw new RuntimeException('currentpasswordrequired');
        }
        if (!is_string($code) || ($code !== '' && !preg_match('/^[0-9]{6}$/D', $code))) {
            throw new RuntimeException('invalidcode');
        }

        // Patch the OTP code independently so a password change preserves existing 2FA.
        $changes['currentSecret'] = $current;
        if ($code !== '') {
            $changes['otpAuth/otpCode'] = $code;
        }

        $result = $this->request('x:AccountPassword/set', ['update' => ['singleton' => $changes]]);
        $this->check_updated($result, 'singleton');
    }

    public function app_passwords()
    {
        // The server selects the authenticated account. Do not request stored secret hashes.
        $result = $this->request('x:AppPassword/get', [
            'ids' => null,
            'properties' => ['id', 'description', 'createdAt', 'expiresAt'],
        ]);
        $items = $this->items($result);
        foreach ($items as $item) {
            if (!is_string($item['description'] ?? null)) {
                throw new RuntimeException('responseerror');
            }
        }
        return $items;
    }

    public function create_app_password($description, $expires)
    {
        $description = $this->description($description);
        $credential = ['description' => $description, 'permissions' => ['@type' => 'Inherit']];
        if ($expires !== '') {
            $date = is_string($expires) ? DateTimeImmutable::createFromFormat('!Y-m-d', $expires, new DateTimeZone('UTC')) : false;
            if (!$date || $date->format('Y-m-d') !== $expires || $date->getTimestamp() <= time()) {
                throw new RuntimeException('invalidexpiry');
            }
            $credential['expiresAt'] = $date->format('Y-m-d\TH:i:s\Z');
        }

        $result = $this->request('x:AppPassword/set', ['create' => ['new' => $credential]]);
        if (isset($result['notCreated']['new'])) {
            $this->fail(is_array($result['notCreated']['new']) ? $result['notCreated']['new'] : []);
        }
        $created = $result['created']['new'] ?? null;
        if (!is_array($created) || !is_string($created['secret'] ?? null) || $created['secret'] === ''
            || !is_string($created['id'] ?? null)
        ) {
            throw new RuntimeException('responseerror');
        }
        return ['id' => $created['id'], 'secret' => $created['secret']];
    }

    public function revoke_app_password($id)
    {
        // Stalwart stores multiple credential kinds on an account. Accept only a listed app password.
        if (!is_string($id) || !in_array($id, array_column($this->app_passwords(), 'id'), true)) {
            throw new RuntimeException('itemnotfound');
        }
        $result = $this->request('x:AppPassword/set', ['destroy' => [$id]]);
        if (isset($result['notDestroyed'][$id])) {
            $this->fail(is_array($result['notDestroyed'][$id]) ? $result['notDestroyed'][$id] : []);
        }
        if (!is_array($result['destroyed'] ?? null) || !in_array($id, $result['destroyed'], true)) {
            throw new RuntimeException('responseerror');
        }
    }

    public function aliases()
    {
        // Resolve our account ID from a user-scoped singleton, never from a submitted ID or username.
        $settings = $this->request('x:AccountSettings/get', ['ids' => ['singleton'], 'properties' => ['id']]);
        $id = $settings['accountId'] ?? null;
        if (!is_string($id) || $id === '') {
            throw new RuntimeException('responseerror');
        }
        $result = $this->request('x:Account/get', [
            'ids' => [$id], 'properties' => ['id', 'name', 'domainId', 'emailAddress', 'aliases'],
        ]);
        $account = $this->items($result)[0] ?? null;
        if (!$account || $account['id'] !== $id || !is_string($account['domainId'] ?? null)
            || !is_string($account['name'] ?? null) || !is_array($account['aliases'] ?? null)
        ) {
            throw new RuntimeException('responseerror');
        }
        $domain_ids = [$account['domainId']];
        foreach ($account['aliases'] as $alias) {
            if (!is_array($alias) || !is_string($alias['domainId'] ?? null)
                || !is_string($alias['name'] ?? null) || !is_bool($alias['enabled'] ?? null)
                || (isset($alias['description']) && !is_string($alias['description']))
            ) {
                throw new RuntimeException('responseerror');
            }
            $domain_ids[] = $alias['domainId'];
        }
        $domains = $this->request('x:Domain/get', [
            'ids' => array_values(array_unique($domain_ids)), 'properties' => ['id', 'name'],
        ]);
        $account['domains'] = [];
        foreach ($this->items($domains) as $domain) {
            if (!is_string($domain['name'] ?? null)) {
                throw new RuntimeException('responseerror');
            }
            $account['domains'][$domain['id']] = $domain['name'];
        }
        foreach ($domain_ids as $domain_id) {
            if (!isset($account['domains'][$domain_id])) {
                throw new RuntimeException('responseerror');
            }
        }
        $account['version'] = hash('sha256', json_encode([$id, $account['aliases']]));
        return $account;
    }

    public function save_alias($operation, $key, $name, $description, $version)
    {
        if (!in_array($operation, ['create', 'enable', 'disable', 'delete'], true)) {
            throw new RuntimeException('invalidoperation');
        }
        $account = $this->aliases();
        if (!is_string($version) || !hash_equals($account['version'], $version)) {
            throw new RuntimeException('aliaseschanged');
        }
        $aliases = $account['aliases'];
        if ($operation === 'create') {
            // Restrict new aliases to the mailbox's own domain. The server enforces availability and policy.
            if (!is_string($name) || strlen($name) > 64 || !preg_match('/^[a-zA-Z0-9][a-zA-Z0-9._+-]*$/D', $name)
                || !filter_var($name . '@example.com', FILTER_VALIDATE_EMAIL)
            ) {
                throw new RuntimeException('invalidalias');
            }
            $description = $description === '' ? null : $this->description($description);
            if (strcasecmp($name, $account['name']) === 0) {
                throw new RuntimeException('aliasexists');
            }
            foreach ($aliases as $alias) {
                if ($alias['domainId'] === $account['domainId'] && strcasecmp($alias['name'], $name) === 0) {
                    throw new RuntimeException('aliasexists');
                }
            }
            $aliases[] = ['name' => $name, 'domainId' => $account['domainId'], 'description' => $description, 'enabled' => true];
        }
        else {
            $found = false;
            foreach ($aliases as $index => $alias) {
                if (is_string($key) && hash_equals(self::alias_key($alias), $key)) {
                    if ($operation === 'delete') {
                        unset($aliases[$index]);
                    }
                    else {
                        $aliases[$index]['enabled'] = $operation === 'enable';
                    }
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                throw new RuntimeException('itemnotfound');
            }
        }
        // Preserve other aliases and every unrelated account property.
        $result = $this->request('x:Account/set', ['update' => [
            $account['id'] => ['aliases' => array_values($aliases)],
        ]]);
        $this->check_updated($result, $account['id']);
    }

    public static function alias_key(array $alias)
    {
        return hash('sha256', json_encode([$alias['domainId'], $alias['name']]));
    }

    public function public_keys($page = 0)
    {
        return $this->owned_resources('PublicKey', ['description', 'createdAt', 'expiresAt'], $page);
    }

    public function masked_email($page = 0)
    {
        return $this->owned_resources('MaskedEmail', ['description', 'email', 'enabled', 'forDomain', 'createdAt', 'expiresAt'], $page);
    }

    public function create_public_key($description, $key, $expires)
    {
        require_once __DIR__ . '/stalwart_public_key.php';
        $object = [
            'description' => $this->description($description),
            'key' => rcube_stalwart_public_key::validate($key),
            'expiresAt' => $this->expiry($expires),
            'emailAddresses' => new stdClass(),
        ];
        $this->create_resource('PublicKey', $object);
    }

    public function update_public_key($operation, $id, $description)
    {
        if (!in_array($operation, ['rename', 'delete'], true)) {
            throw new RuntimeException('invalidoperation');
        }
        $settings = $this->account_settings();
        $this->owned_resource('PublicKey', $id, $settings['accountId']);
        if ($operation === 'delete') {
            // Never remove the key currently selected for encryption of incoming mail.
            if (($settings['encryptionAtRest']['publicKey'] ?? null) === $id) {
                throw new RuntimeException('keyinuse');
            }
            $this->destroy_resource('PublicKey', $id, $settings['accountId']);
        }
        else {
            $result = $this->request('x:PublicKey/set', ['accountId' => $settings['accountId'], 'update' => [
                $id => ['description' => $this->description($description)],
            ]]);
            $this->check_updated($result, $id);
        }
    }

    public function create_masked_email($description, $prefix, $domain, $expires)
    {
        if (!is_string($prefix) || ($prefix !== '' && !preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_]{0,63}$/D', $prefix))) {
            throw new RuntimeException('invalidprefix');
        }
        if (!is_string($domain)) {
            throw new RuntimeException('invalidsitedomain');
        }
        $domain = strtolower(trim($domain));
        if ($domain !== '' && (!filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) || strlen($domain) > 253)) {
            throw new RuntimeException('invalidsitedomain');
        }
        $object = ['enabled' => true, 'description' => $this->description($description), 'expiresAt' => $this->expiry($expires)];
        if ($prefix !== '') {
            $object['emailPrefix'] = strtolower($prefix);
        }
        if ($domain !== '') {
            $object['forDomain'] = $domain;
        }
        // The server chooses the address and the authenticated account's domain.
        // Its expiry is encoded in the generated address and cannot be edited later.
        $this->create_resource('MaskedEmail', $object);
    }

    public function update_masked_email($operation, $id)
    {
        if (!in_array($operation, ['enable', 'disable', 'delete'], true)) {
            throw new RuntimeException('invalidoperation');
        }
        $settings = $this->account_settings();
        $item = $this->owned_resource('MaskedEmail', $id, $settings['accountId']);
        if ($operation === 'delete') {
            $this->destroy_resource('MaskedEmail', $id, $settings['accountId']);
        }
        else {
            if ($operation === 'enable' && !empty($item['expiresAt']) && strtotime($item['expiresAt']) <= time()) {
                throw new RuntimeException('maskedexpired');
            }
            $result = $this->request('x:MaskedEmail/set', ['accountId' => $settings['accountId'], 'update' => [
                $id => ['enabled' => $operation === 'enable'],
            ]]);
            $this->check_updated($result, $id);
        }
    }

    private function account_settings()
    {
        $result = $this->request('x:AccountSettings/get', [
            'ids' => ['singleton'], 'properties' => ['id', 'encryptionAtRest'],
        ]);
        $settings = $this->items($result)[0] ?? null;
        if (!is_string($result['accountId'] ?? null) || $result['accountId'] === ''
            || !$settings || $settings['id'] !== 'singleton'
            || !is_array($settings['encryptionAtRest'] ?? null)
            || !is_string($settings['encryptionAtRest']['@type'] ?? null)
        ) {
            throw new RuntimeException('responseerror');
        }
        $settings['accountId'] = $result['accountId'];
        return $settings;
    }

    /**
     * Query only our account, including when an administrator has impersonation rights.
     * Return 20 entries per page; never fetch public key material in a listing.
     */
    private function owned_resources($type, array $properties, $page)
    {
        $settings = $this->account_settings();
        $page = max(0, min(10000, (int) $page));
        $result = $this->request('x:' . $type . '/query', [
            'accountId' => $settings['accountId'], 'filter' => ['accountId' => $settings['accountId']],
            'position' => $page * 20, 'limit' => 21,
        ]);
        if (!is_array($result['ids'] ?? null) || count($result['ids']) > 21) {
            throw new RuntimeException('responseerror');
        }
        foreach ($result['ids'] as $id) {
            if (!is_string($id) || $id === '') {
                throw new RuntimeException('responseerror');
            }
        }
        $ids = array_slice($result['ids'], 0, 20);
        $items = [];
        if ($ids) {
            $items = $this->items($this->request('x:' . $type . '/get', [
                'accountId' => $settings['accountId'], 'ids' => $ids,
                'properties' => array_merge(['id', 'accountId'], $properties),
            ]));
            foreach ($items as $item) {
                if (($item['accountId'] ?? null) !== $settings['accountId'] || !in_array($item['id'], $ids, true)) {
                    throw new RuntimeException('responseerror');
                }
                $this->validate_resource($type, $item);
            }
        }
        return ['items' => $items, 'page' => $page, 'more' => count($result['ids']) > 20,
            'active_key' => $settings['encryptionAtRest']['publicKey'] ?? null];
    }

    private function owned_resource($type, $id, $account_id)
    {
        if (!is_string($id) || !preg_match('/^[A-Za-z0-9_-]{1,128}$/D', $id)) {
            throw new RuntimeException('itemnotfound');
        }
        $result = $this->request('x:' . $type . '/get', [
            'accountId' => $account_id, 'ids' => [$id],
            'properties' => ['id', 'accountId', 'description', 'expiresAt'],
        ]);
        if (!empty($result['notFound'])) {
            throw new RuntimeException('itemnotfound');
        }
        $item = $this->items($result)[0] ?? null;
        if (!$item || $item['id'] !== $id || ($item['accountId'] ?? null) !== $account_id) {
            throw new RuntimeException('itemnotfound');
        }
        if (isset($item['expiresAt']) && (!is_string($item['expiresAt']) || strtotime($item['expiresAt']) === false)) {
            throw new RuntimeException('responseerror');
        }
        return $item;
    }

    private function validate_resource($type, array $item)
    {
        if (isset($item['description']) && !is_string($item['description'])) {
            throw new RuntimeException('responseerror');
        }
        foreach (['createdAt', 'expiresAt'] as $field) {
            if (isset($item[$field]) && (!is_string($item[$field]) || strtotime($item[$field]) === false)) {
                throw new RuntimeException('responseerror');
            }
        }
        if ($type === 'MaskedEmail' && (!is_string($item['email'] ?? null) || !is_bool($item['enabled'] ?? null)
            || (isset($item['forDomain']) && !is_string($item['forDomain']))
        )) {
            throw new RuntimeException('responseerror');
        }
    }

    private function create_resource($type, array $object)
    {
        $settings = $this->account_settings();
        $result = $this->request('x:' . $type . '/set', ['accountId' => $settings['accountId'], 'create' => ['new' => $object]]);
        if (isset($result['notCreated']['new'])) {
            $this->fail(is_array($result['notCreated']['new']) ? $result['notCreated']['new'] : []);
        }
        if (!is_string($result['created']['new']['id'] ?? null) || $result['created']['new']['id'] === '') {
            throw new RuntimeException('responseerror');
        }
    }

    private function destroy_resource($type, $id, $account_id)
    {
        $result = $this->request('x:' . $type . '/set', ['accountId' => $account_id, 'destroy' => [$id]]);
        if (isset($result['notDestroyed'][$id])) {
            $this->fail(is_array($result['notDestroyed'][$id]) ? $result['notDestroyed'][$id] : []);
        }
        if (!is_array($result['destroyed'] ?? null) || !in_array($id, $result['destroyed'], true)) {
            throw new RuntimeException('responseerror');
        }
    }

    private function expiry($expires)
    {
        if ($expires === '') {
            return null;
        }
        $date = is_string($expires) ? DateTimeImmutable::createFromFormat('!Y-m-d', $expires, new DateTimeZone('UTC')) : false;
        if (!$date || $date->format('Y-m-d') !== $expires || $date->getTimestamp() <= time()
            || $date->getTimestamp() - time() > 4294967295
        ) {
            throw new RuntimeException('invalidexpiry');
        }
        return $date->format('Y-m-d\TH:i:s\Z');
    }

    private function description($description)
    {
        if (!is_string($description) || trim($description) === '' || strlen($description) > 200
            || preg_match('/[\x00-\x1f\x7f]/', $description)
        ) {
            throw new RuntimeException('invaliddescription');
        }
        return trim($description);
    }

    private function items(array $result)
    {
        if (!is_array($result['list'] ?? null) || !empty($result['notFound'])) {
            throw new RuntimeException('responseerror');
        }
        foreach ($result['list'] as $item) {
            if (!is_array($item) || !is_string($item['id'] ?? null) || $item['id'] === '') {
                throw new RuntimeException('responseerror');
            }
        }
        return $result['list'];
    }

    private function check_updated(array $result, $id)
    {
        if (isset($result['notUpdated'][$id])) {
            $this->fail(is_array($result['notUpdated'][$id]) ? $result['notUpdated'][$id] : []);
        }
        if (!isset($result['updated']) || !is_array($result['updated']) || !array_key_exists($id, $result['updated'])) {
            throw new RuntimeException('responseerror');
        }
    }

    private function request($method, array $arguments)
    {
        try {
            $response = $this->http->post($this->url, [
                'headers' => ['Authorization' => $this->authorization, 'Accept' => 'application/json'],
                'json' => [
                    'using' => ['urn:ietf:params:jmap:core', 'urn:stalwart:jmap'],
                    'methodCalls' => [[$method, $arguments, 'stalwart']],
                ],
                'connect_timeout' => 5,
                'timeout' => 15,
                'verify' => true,
                'allow_redirects' => false,
                'http_errors' => false,
                'stream' => true,
            ]);

            $status = $response->getStatusCode();
            if ($status === 401) {
                throw new RuntimeException('authenticationerror');
            }
            if ($status === 403) {
                throw new RuntimeException('permissionerror');
            }
            if ($status === 429) {
                throw new RuntimeException('ratelimited');
            }
            if ($status !== 200) {
                throw new RuntimeException('connectionerror');
            }

            $stream = $response->getBody();
            $body = '';
            while (!$stream->eof() && strlen($body) <= 65536) {
                try {
                    $part = $stream->read(min(8192, 65537 - strlen($body)));
                }
                catch (RuntimeException $e) {
                    throw new RuntimeException('connectionerror');
                }
                if ($part === '') {
                    break;
                }
                $body .= $part;
            }
            $stream->close();
            if (strlen($body) > 65536) {
                throw new RuntimeException('responseerror');
            }
            $data = json_decode($body, true);
        }
        catch (\GuzzleHttp\Exception\GuzzleException $e) {
            // Request exceptions may contain credentials or response bodies. Never expose or log them.
            throw new RuntimeException('connectionerror');
        }

        if (!is_array($data) || !isset($data['methodResponses']) || !is_array($data['methodResponses'])) {
            throw new RuntimeException('responseerror');
        }
        foreach ($data['methodResponses'] as $result) {
            if (!is_array($result)) {
                throw new RuntimeException('responseerror');
            }
            if (($result[2] ?? '') === 'stalwart') {
                if (($result[0] ?? '') === 'error') {
                    $this->fail(is_array($result[1] ?? null) ? $result[1] : []);
                }
                if (($result[0] ?? '') === $method && isset($result[1]) && is_array($result[1])) {
                    return $result[1];
                }
            }
        }

        throw new RuntimeException('responseerror');
    }

    private function fail(array $error)
    {
        $type = $error['type'] ?? '';
        $description = is_string($error['description'] ?? null) ? $error['description'] : '';
        if ($type === 'forbidden') {
            if (strpos($description, 'only available in the Enterprise edition') !== false) {
                throw new RuntimeException('enterpriserequired');
            }
            if (strpos($description, 'Current OTP code is required') !== false) {
                throw new RuntimeException('coderequired');
            }
            if (strpos($description, 'Current secret is incorrect') !== false) {
                throw new RuntimeException('credentialserror');
            }
            throw new RuntimeException('permissionerror');
        }
        if ($type === 'invalidProperties') {
            throw new RuntimeException('policyerror');
        }
        if ($type === 'overQuota') {
            throw new RuntimeException('overquota');
        }
        if ($type === 'notFound') {
            throw new RuntimeException('itemnotfound');
        }
        if ($type === 'stateMismatch') {
            throw new RuntimeException('aliaseschanged');
        }
        if ($type === 'unknownMethod' || $type === 'unknownCapability') {
            throw new RuntimeException('unsupportedserver');
        }
        throw new RuntimeException('responseerror');
    }
}
