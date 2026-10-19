<?php

/**
 * Remember Stalwart mailboxes using encrypted, server-bound refresh credentials.
 */
class rcube_stalwart_persistent_login
{
    private $rc;
    private $client;
    private $cookie_name;
    private $lifetime;
    private $requested = false;
    private $restoring = false;

    public function __construct($rc, $client, $cookie_name, $lifetime)
    {
        $this->rc = $rc;
        $this->client = $client;
        $this->cookie_name = $cookie_name . '_stalwart';
        $this->lifetime = max(0, min(2592000, (int) $lifetime));
    }

    /**
     * Replace credential persistence only for the embedded Stalwart login.
     */
    public static function init($rc, $client)
    {
        if (!$rc->plugins->get_plugin('persistent_login')) {
            return;
        }

        // Initialize the existing plugin first, regardless of configured order.
        $rc->plugins->load_plugin('persistent_login', true);
        $plugin = $rc->plugins->get_plugin('persistent_login');
        if (!in_array([$plugin, 'startup'], $rc->plugins->handlers['startup'] ?? [], true)) {
            return;
        }

        foreach (['startup', 'authenticate', 'login_after'] as $hook) {
            $rc->plugins->unregister_hook($hook, [$plugin, $hook]);
        }
        // Even invalid Stalwart settings must not fall back to saved passwords.
        if (!$client) {
            $rc->plugins->unregister_hook('template_object_loginform', [$plugin, 'persistent_login_loginform']);
            return;
        }

        $handler = new self($rc, $client, $rc->config->get('ifpl_cookie_name', '_pt'),
            $rc->config->get('ifpl_login_expire', 259200));
        $rc->plugins->register_hook('startup', [$handler, 'startup']);
        $rc->plugins->register_hook('login_after', [$handler, 'login_after']);
        $rc->plugins->register_hook('oauth_refresh_token', [$handler, 'refresh']);
        $rc->plugins->register_hook('logout_after', [$handler, 'logout_after']);
        $rc->plugins->register_hook('loginform_content', [$handler, 'form']);
    }

    /**
     * Keep the original checkbox only on the first step of authentication.
     */
    public function form($args)
    {
        if (!empty($args['hidden']['stalwart']) || $this->lifetime <= 0) {
            $plugin = $this->rc->plugins->get_plugin('persistent_login');
            $this->rc->plugins->unregister_hook('template_object_loginform', [$plugin, 'persistent_login_loginform']);
        }

        return $args;
    }

    private function context()
    {
        return ['host' => $this->client->host(), 'binding' => $this->client->binding()];
    }

    public function startup($args)
    {
        if ($args['task'] !== 'login' || !empty($this->rc->user->ID)) {
            return $args;
        }

        $context = $this->context();
        if (!$context) {
            return $args;
        }

        if ($this->lifetime <= 0) {
            $this->revoke();
            return $args;
        }

        $method = $_SERVER['REQUEST_METHOD'] ?? '';
        if ($args['action'] === 'login' && $method === 'POST') {
            // Keep this in the request: normal login replaces the temporary session.
            $this->requested = $this->rc->check_request()
                && rcube_utils::get_input_string('_ifpl', rcube_utils::INPUT_POST) === '1';
        }
        elseif ($args['action'] === '' && $method === 'GET' && empty($_SESSION['stalwart_login'])
            && empty($_GET['_remote']) && empty($_GET['_framed'])
        ) {
            $this->restore($context);
        }

        return $args;
    }

    public function login_after($args)
    {
        if (!$this->restoring && !empty($_SESSION['oauth_token'])) {
            $this->remember($_SESSION['oauth_token']);
        }

        return $args;
    }

    private function remember($token)
    {
        $context = $this->context();
        $requested = $this->requested;
        $this->requested = false;

        // A new explicit login replaces any previous remembered mailbox.
        $this->revoke();
        $plugin = $this->rc->plugins->get_plugin('persistent_login');
        if ($plugin) {
            $plugin->unset_persistent_cookie();
        }
        if ($requested && $context && $this->lifetime > 0 && !empty($token['refresh_token'])) {
            $this->issue($token, $context, time() + $this->lifetime);
        }
    }

    public function refresh($args)
    {
        $marker = $_SESSION['stalwart_persistent_login'] ?? null;
        if ($this->restoring || !$marker || empty($this->rc->user->ID)) {
            return $args;
        }

        $context = $this->context();
        if (!$context || ($marker['expires'] ?? 0) <= time()
            || ($marker['binding'] ?? null) !== $context['binding']
        ) {
            $this->revoke();
            return $args;
        }

        $record = $this->record($marker['cookie']);
        $payload = $this->payload($_SESSION['oauth_token'] ?? [], $context, $marker['expires']);
        if (!$record || !$payload || (int) $record['user_id'] !== (int) $this->rc->user->ID) {
            $this->revoke();
            return $args;
        }

        $db = $this->rc->get_dbh();
        $data = $this->seal($payload, $record['key']);
        if ($data === false) {
            $this->revoke();
            return $args;
        }

        // Update rotated refresh credentials, without extending the chosen lifetime.
        $result = $db->query('UPDATE ' . $db->table_name('cache')
            . ' SET data = ? WHERE user_id = ? AND cache_key = ? AND expires > ' . $db->now(),
            $data, $record['user_id'], $record['key']);
        if ($db->affected_rows($result) !== 1) {
            unset($_SESSION['stalwart_persistent_login']);
        }

        return $args;
    }

    public function logout_after($args)
    {
        $this->revoke();
        return $args;
    }

    private function restore($context)
    {
        $cookie = $_COOKIE[$this->cookie_name] ?? '';
        $record = $this->record($cookie);
        if (!$record) {
            if ($cookie !== '') {
                $this->cookie('', time() - 3600);
            }
            return;
        }

        $db = $this->rc->get_dbh();
        $result = $db->query('SELECT data FROM ' . $db->table_name('cache')
            . ' WHERE user_id = ? AND cache_key = ? AND expires > ' . $db->now(),
            $record['user_id'], $record['key']);
        $row = $db->fetch_assoc($result);
        $payload = $row ? $this->open($row['data'], $record['key']) : null;
        if (!$payload || ($payload['expires'] ?? 0) <= time()
            || (int) ($payload['user_id'] ?? 0) !== $record['user_id']
        ) {
            $this->revoke();
            return;
        }
        // Never send a refresh credential to a different Stalwart server.
        if (($payload['binding'] ?? null) !== $context['binding'] || ($payload['host'] ?? null) !== $context['host']) {
            return;
        }

        // Claim once before contacting the server, including concurrent requests.
        $result = $db->query('DELETE FROM ' . $db->table_name('cache')
            . ' WHERE user_id = ? AND cache_key = ? AND data = ?',
            $record['user_id'], $record['key'], $row['data']);
        if ($db->affected_rows($result) !== 1) {
            return;
        }

        $this->cookie('', time() - 3600);
        $this->restoring = true;
        $success = false;
        try {
            $token = $payload['token'] ?? [];
            if (empty($token['refresh_token']) || empty($payload['username'])
                || empty($token['identity']) || empty($token['stalwart_login'])
                || ($token['stalwart_server'] ?? null) !== $context['binding']
            ) {
                throw new RuntimeException('Invalid remembered OAuth identity');
            }
            // Refresh through the selected Stalwart adapter before opening IMAP.
            $auth = $this->rc->oauth->refresh_access_token($token);
            $updated = $_SESSION['oauth_token'] ?? [];
            if (!$auth || empty($auth['authorization']) || ($updated['identity'] ?? null) !== $token['identity']) {
                throw new RuntimeException('Remembered OAuth authorization expired');
            }
            if (!empty($updated['auth_type'])) {
                $this->rc->config->set('imap_auth_type', $updated['auth_type']);
            }
            $this->rc->config->set('login_password_maxlen', strlen($auth['authorization']));
            if (!$this->rc->login($payload['username'], $auth['authorization'], $context['host'], false)
                || (int) $this->rc->user->ID !== $record['user_id']
            ) {
                throw new RuntimeException('Remembered mailbox is unavailable');
            }

            $_SESSION['oauth_token'] = $updated;
            $this->rc->session->remove('temp');
            $this->rc->session->regenerate_id(false);
            $this->rc->session->set_auth_cookie();
            $this->rc->log_login();
            $this->issue($updated, $context, $payload['expires']);
            $success = true;
        }
        catch (Throwable $e) {
            // Server errors may contain credentials. Fall back to an ordinary login.
            $this->rc->kill_session();
        }

        if ($success) {
            $redirect = $this->rc->plugins->exec_hook('login_after', ['_task' => 'mail']);
            unset($redirect['abort'], $redirect['_err']);
            $this->rc->output->redirect($redirect, 0, true);
        }
        $this->restoring = false;
    }

    private function payload($token, $context, $expires)
    {
        $username = $this->rc->user->data['username'] ?? '';
        if (!$this->rc->user->ID || !$username || !is_array($token) || empty($token['refresh_token'])
            || empty($token['identity']) || !is_string($token['identity']) || empty($token['stalwart_login'])
            || ($token['stalwart_server'] ?? null) !== $context['binding']
        ) {
            return null;
        }

        return [
            'user_id' => (int) $this->rc->user->ID, 'username' => $username,
            'host' => $context['host'], 'binding' => $context['binding'], 'expires' => $expires,
            'token' => $token,
        ];
    }

    private function issue($token, $context, $expires)
    {
        $payload = $this->payload($token, $context, $expires);
        if (!$payload || $expires <= time() || headers_sent()) {
            return;
        }

        $cookie = 'v1.' . $payload['user_id'] . '.' . bin2hex(random_bytes(32));
        $record = $this->record($cookie);
        $data = $this->seal($payload, $record['key']);
        if ($data === false) {
            return;
        }
        $db = $this->rc->get_dbh();
        $result = $db->query('INSERT INTO ' . $db->table_name('cache') . ' (user_id, cache_key, expires, data) VALUES (?, ?, ?, ?)',
            $record['user_id'], $record['key'], date('Y-m-d H:i:s', $expires), $data);
        if ($db->affected_rows($result) === 1 && $this->cookie($cookie, $expires)) {
            $_SESSION['stalwart_persistent_login'] = ['cookie' => $cookie, 'expires' => $expires, 'binding' => $context['binding']];
        }
    }

    private function revoke()
    {
        $cookies = [$_COOKIE[$this->cookie_name] ?? '', $_SESSION['stalwart_persistent_login']['cookie'] ?? ''];
        $db = $this->rc->get_dbh();
        foreach (array_unique($cookies) as $cookie) {
            if ($record = $this->record($cookie)) {
                $db->query('DELETE FROM ' . $db->table_name('cache') . ' WHERE user_id = ? AND cache_key = ?',
                    $record['user_id'], $record['key']);
            }
        }
        unset($_SESSION['stalwart_persistent_login']);
        $this->cookie('', time() - 3600);
    }

    private function record($cookie)
    {
        if (!is_string($cookie) || !preg_match('/^v1\.([1-9][0-9]{0,9})\.([a-f0-9]{64})$/D', $cookie, $match)) {
            return null;
        }
        return ['user_id' => (int) $match[1], 'key' => 'stalwart.login.' . hash('sha256', $cookie)];
    }

    private function seal($payload, $context)
    {
        $secret = $this->rc->config->get('des_key');
        if (!is_string($secret) || strlen($secret) < 24) {
            return false;
        }
        $iv = random_bytes(12);
        $key = hash('sha256', 'stalwart.login:' . $secret, true);
        $json = json_encode($payload);
        if ($json === false) {
            return false;
        }
        $data = openssl_encrypt($json, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $context);
        return $data === false ? false : base64_encode($iv . $tag . $data);
    }

    private function open($data, $context)
    {
        $secret = $this->rc->config->get('des_key');
        $data = is_string($data) ? base64_decode($data, true) : false;
        if (!is_string($secret) || strlen($secret) < 24 || $data === false || strlen($data) < 29) {
            return null;
        }
        $key = hash('sha256', 'stalwart.login:' . $secret, true);
        $json = openssl_decrypt(substr($data, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA,
            substr($data, 0, 12), substr($data, 12, 16), $context);
        $result = $json === false ? null : json_decode($json, true);
        return is_array($result) ? $result : null;
    }

    private function cookie($value, $expires)
    {
        if (headers_sent()) {
            return false;
        }
        $options = session_get_cookie_params();
        $options['expires'] = $expires;
        $options['secure'] = $options['secure'] || rcube_utils::https_check();
        $options['httponly'] = true;
        $options['samesite'] = 'Lax';
        unset($options['lifetime']);
        $result = setcookie($this->cookie_name, $value, $options);
        if ($result) {
            if ($value === '') {
                unset($_COOKIE[$this->cookie_name]);
            }
            else {
                $_COOKIE[$this->cookie_name] = $value;
            }
        }
        return $result;
    }
}
