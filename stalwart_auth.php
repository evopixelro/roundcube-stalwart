<?php

require_once __DIR__ . '/stalwart_config.php';

/**
 * Stalwart authorization-code client for the native Webmail login form.
 */
class rcube_stalwart_auth
{
    private $issuer;
    private $client_id;
    private $client_secret;
    private $redirect_uri;
    private $http;
    private $host;

    public function __construct($config, $http = null)
    {
        $api = $config->get('stalwart_api_url', '');
        if (!is_string($api) || !preg_match('~/jmap/?$~', $api)) {
            throw new RuntimeException('loginconfigurationerror');
        }
        $this->issuer = preg_replace('~/jmap/?$~', '', $api);
        $this->redirect_uri = $config->get('stalwart_login_redirect_uri', '');
        foreach ([$this->issuer, $this->redirect_uri] as $url) {
            $parts = is_string($url) ? parse_url($url) : false;
            if (!$parts || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])
                || isset($parts['user']) || isset($parts['pass']) || isset($parts['query'])
                || isset($parts['fragment']) || preg_match('/[\x00-\x20\\\\]/', $url)
            ) {
                throw new RuntimeException('loginconfigurationerror');
            }
        }
        $this->client_id = $config->get('stalwart_login_client_id', '');
        $this->client_secret = $config->get('stalwart_login_client_secret', '');
        $hosts = rcube_stalwart_config::hosts($config);
        $this->host = $config->get('stalwart_selected_host', count($hosts) === 1 ? $hosts[0] : null);
        if (!is_string($this->client_id) || $this->client_id === '' || strlen($this->client_id) > 2048
            || !is_string($this->client_secret)
            || !is_string($this->host) || !in_array($this->host, $hosts, true)
        ) {
            throw new RuntimeException('loginconfigurationerror');
        }
        $this->http = $http ?: new \GuzzleHttp\Client();
    }

    public function host()
    {
        return $this->host;
    }

    public function binding()
    {
        return hash('sha256', json_encode([$this->issuer, $this->client_id, $this->client_secret, $this->redirect_uri, $this->host]));
    }

    public function options()
    {
        return [
            'provider' => null, 'auth_uri' => null, 'config_uri' => null,
            'token_uri' => $this->issuer . '/auth/token',
            'client_id' => $this->client_id, 'client_secret' => $this->client_secret,
            'login_redirect' => false, 'debug' => false,
        ];
    }

    /**
     * Let Stalwart verify both factors. The plugin never obtains the TOTP seed.
     */
    public function authorize($username, $password, $verifier, $code = '')
    {
        if (!is_string($username) || $username === '' || strlen($username) > 320
            || !is_string($password) || $password === '' || strlen($password) > 4096
            || !is_string($code) || ($code !== '' && !preg_match('/^[0-9]{6}$/D', $code))
            || !is_string($verifier) || !preg_match('/^[A-Za-z0-9_-]{43,128}$/D', $verifier)
        ) {
            throw new RuntimeException('credentialserror');
        }
        $request = [
            'type' => 'authCode', 'accountName' => $username, 'accountSecret' => $password,
            'clientId' => $this->client_id, 'redirectUri' => $this->redirect_uri,
            'scope' => 'openid offline_access urn:ietf:params:oauth:scope:mail',
            'codeChallenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'codeChallengeMethod' => 'S256',
        ];
        if ($code !== '') {
            $request['mfaToken'] = $code;
        }
        $result = $this->request('/api/auth', ['json' => $request]);
        if (($result['type'] ?? '') === 'mfaRequired') {
            return null;
        }
        if (($result['type'] ?? '') === 'failure') {
            throw new RuntimeException('credentialserror');
        }
        if (($result['type'] ?? '') !== 'authenticated'
            || !is_string($result['client_code'] ?? null) || $result['client_code'] === ''
            || ($result['iss'] ?? null) !== $this->issuer
        ) {
            throw new RuntimeException('loginresponseerror');
        }

        $token = $this->token([
            'grant_type' => 'authorization_code', 'code' => $result['client_code'],
            'redirect_uri' => $this->redirect_uri, 'code_verifier' => $verifier,
        ]);
        $identity = $this->request('/auth/userinfo', [
            'headers' => ['Authorization' => 'Bearer ' . $token['access_token']],
        ], 'GET');
        // Obtain the canonical mailbox identity from the token's server, not submitted input.
        $user = $identity['preferred_username'] ?? $identity['email'] ?? null;
        if (!is_string($identity['sub'] ?? null) || $identity['sub'] === ''
            || !is_string($user) || $user === '' || strlen($user) > 320 || preg_match('/[\x00-\x1f\x7f]/', $user)
        ) {
            throw new RuntimeException('loginresponseerror');
        }
        return ['username' => $user, 'token' => $token];
    }

    public function refresh($refresh_token)
    {
        if (!is_string($refresh_token) || $refresh_token === '') {
            throw new RuntimeException('loginexpired');
        }
        return $this->token(['grant_type' => 'refresh_token', 'refresh_token' => $refresh_token]);
    }

    private function token(array $params)
    {
        $params['client_id'] = $this->client_id;
        if ($this->client_secret !== '') {
            $params['client_secret'] = $this->client_secret;
        }
        $token = $this->request('/auth/token', ['form_params' => $params]);
        if (($token['token_type'] ?? '') !== 'Bearer' && ($token['token_type'] ?? '') !== 'bearer') {
            throw new RuntimeException('loginresponseerror');
        }
        foreach (['access_token', 'refresh_token'] as $key) {
            if (($key === 'access_token' || isset($token[$key]))
                && (!is_string($token[$key] ?? null) || $token[$key] === ''
                    || strlen($token[$key]) > 16384 || preg_match('/[\x00-\x20\x7f]/', $token[$key]))
            ) {
                throw new RuntimeException('loginresponseerror');
            }
        }
        if (!is_int($token['expires_in'] ?? null) || $token['expires_in'] < 30 || $token['expires_in'] > 31536000) {
            throw new RuntimeException('loginresponseerror');
        }
        // Identity is read from userinfo over verified TLS; do not trust an unverified JWT.
        return array_intersect_key($token, array_flip(['access_token', 'refresh_token', 'expires_in', 'token_type']));
    }

    private function request($path, array $options, $method = 'POST')
    {
        $options['headers']['Accept'] = 'application/json';
        $options += [
            'connect_timeout' => 5, 'timeout' => 15, 'read_timeout' => 15, 'verify' => true,
            'allow_redirects' => false, 'http_errors' => false, 'stream' => true,
        ];
        try {
            $response = $this->http->request($method, $this->issuer . $path, $options);
            $status = $response->getStatusCode();
            $stream = $response->getBody();
            try {
                if ($status === 429) {
                    throw new RuntimeException('ratelimited');
                }
                if ($status === 401 || $status === 403 || $status === 400) {
                    throw new RuntimeException('credentialserror');
                }
                if ($status !== 200) {
                    throw new RuntimeException('connectionerror');
                }
                $body = '';
                while (!$stream->eof() && strlen($body) <= 65536) {
                    $part = $stream->read(min(8192, 65537 - strlen($body)));
                    if ($part === '') {
                        break;
                    }
                    $body .= $part;
                }
            }
            finally {
                $stream->close();
            }
        }
        catch (\GuzzleHttp\Exception\GuzzleException $e) {
            // Exceptions can include passwords, OTPs and tokens. Never log their contents.
            throw new RuntimeException('connectionerror');
        }
        if (strlen($body) > 65536 || !is_array($data = json_decode($body, true))) {
            throw new RuntimeException('loginresponseerror');
        }
        return $data;
    }
}
