<?php

/**
 * Attach verified Stalwart tokens to Roundcube's normal mail transport hooks.
 */
class rcube_stalwart_oauth extends rcmail_oauth
{
    private $client;

    public function __construct($client)
    {
        $this->client = $client;
        parent::__construct($client->options());
        self::$instance = $this;
        // Register only transport hooks; native redirect login is a separate mode.
        foreach (['storage_init', 'smtp_connect', 'managesieve_connect', 'refresh', 'keep-alive'] as $hook) {
            $this->rcmail->plugins->register_hook($hook, [$this, $hook === 'keep-alive' ? 'refresh' : $hook]);
        }
    }

    public function prepare(array $token, $username)
    {
        $token['expires'] = time() + $token['expires_in'] - min(60, (int) ($token['expires_in'] / 2));
        $token['stalwart_login'] = true;
        $token['stalwart_server'] = $this->client->binding();
        // Both transport and refresh credentials use Roundcube's session encryption.
        $token['access_token'] = $this->rcmail->encrypt($token['access_token']);
        if (isset($token['refresh_token'])) {
            $token['refresh_token'] = $this->rcmail->encrypt($token['refresh_token']);
        }
        $token['identity'] = $username;
        $token['auth_type'] = 'XOAUTH2';
        return $token;
    }

    public function refresh_access_token(array $token)
    {
        try {
            if (($token['stalwart_server'] ?? '') !== $this->client->binding()) {
                throw new RuntimeException('loginexpired');
            }
            $updated = $this->client->refresh($this->rcmail->decrypt($token['refresh_token'] ?? ''));
            $authorization = 'Bearer ' . $updated['access_token'];
            $updated = $this->prepare($updated, $token['identity']);
            $_SESSION['oauth_token'] = array_merge($token, $updated);
            $_SESSION['password'] = $this->rcmail->encrypt($authorization);
            $this->rcmail->plugins->exec_hook('oauth_refresh_token', $updated);
            return ['token' => $_SESSION['oauth_token'], 'authorization' => $authorization];
        }
        catch (RuntimeException $e) {
            // Expired credentials must not leave an authenticated Webmail session behind.
            $this->rcmail->kill_session();
            return false;
        }
    }

    protected function check_token_validity($token)
    {
        if (($token['stalwart_server'] ?? '') !== $this->client->binding()) {
            $this->rcmail->kill_session();
            $this->rcmail->output->redirect(['_task' => 'login']);
            return false;
        }
        if (isset($token['expires']) && $token['expires'] <= time()) {
            if ($this->refresh_access_token($token) === false) {
                $this->rcmail->output->redirect(['_task' => 'login']);
                return false;
            }
            return true;
        }
        return false;
    }

    public function is_token_valid()
    {
        if (empty($_SESSION['oauth_token']['stalwart_login'])) {
            return false;
        }
        $this->check_token_validity($_SESSION['oauth_token']);
        return !empty($_SESSION['oauth_token']) && $_SESSION['oauth_token']['expires'] > time();
    }

    public function storage_init($options)
    {
        if ($options['driver'] === 'imap' && $this->is_token_valid()) {
            $options['auth_type'] = 'XOAUTH2';
            $options['password'] = 'Bearer ' . $this->rcmail->decrypt($_SESSION['oauth_token']['access_token']);
        }
        return $options;
    }

    public function smtp_connect($options)
    {
        if ($this->is_token_valid()) {
            $options['smtp_auth_type'] = 'XOAUTH2';
            $options['smtp_user'] = '%u';
            $options['smtp_pass'] = '%p';
        }
        return $options;
    }

    public function managesieve_connect($options)
    {
        if ($this->is_token_valid()) {
            $options['auth_type'] = 'XOAUTH2';
            $options['password'] = 'Bearer ' . $this->rcmail->decrypt($_SESSION['oauth_token']['access_token']);
        }
        return $options;
    }

    public function refresh($options)
    {
        $this->is_token_valid();
        return $options;
    }
}
