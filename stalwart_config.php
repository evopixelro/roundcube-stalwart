<?php

/**
 * Resolve Stalwart settings against Roundcube's configured mail servers.
 */
class rcube_stalwart_config
{
    public static function hosts($config)
    {
        $hosts = $config->get('imap_host', 'localhost:143');
        $result = [];
        foreach ((array) $hosts as $key => $value) {
            $host = is_int($key) ? $value : $key;
            if (is_string($host) && $host !== '') {
                $result[] = $host;
            }
        }
        return $result;
    }

    /**
     * Authenticated requests use the mailbox session, never a submitted host.
     */
    public static function host($rc)
    {
        $hosts = self::hosts($rc->config);
        if (!empty($rc->user->ID)) {
            $matches = [];
            foreach ($hosts as $host) {
                $address = strpos($host, '%') === false ? $host : rcube_utils::parse_host($host);
                if (!is_string($address) || $address === '') {
                    continue;
                }
                list($name, $scheme, $port) = rcube_utils::parse_host_uri($address, 143, 993);
                $ssl = in_array($scheme, ['ssl', 'imaps', 'tls'], true) ? $scheme : false;
                if ($name === ($_SESSION['storage_host'] ?? null)
                    && $port === (int) ($_SESSION['storage_port'] ?? 143)
                    && $ssl === ($_SESSION['storage_ssl'] ?? false)
                ) {
                    $matches[] = $host;
                }
            }
            return count($matches) === 1 ? $matches[0] : null;
        }

        $host = rcube_utils::get_input_string('_host', rcube_utils::INPUT_POST);
        if ($host === null || $host === '') {
            $host = rcube_utils::get_input_string('_host', rcube_utils::INPUT_GET);
        }
        if ($host !== null && $host !== '') {
            return in_array($host, $hosts, true) ? $host : null;
        }
        $host = $rc->autoselect_host();
        return in_array($host, $hosts, true) ? $host : (count($hosts) === 1 ? $hosts[0] : null);
    }

    public static function apply($rc)
    {
        $config = $rc->config;
        $host = self::host($rc);
        $profiles = $config->get('stalwart_hosts');
        $enabled = $config->get('stalwart_enabled', false) && $host !== null;
        $config->set('stalwart_selected_host', $host);

        if ($profiles !== null) {
            $profile = is_array($profiles) ? ($profiles[$host ?? ''] ?? null) : null;
            $enabled = $enabled && is_array($profile) && !empty($profile['api_url']);
            // Never inherit another server's endpoint or OAuth client credentials.
            foreach (['api_url', 'login_client_id', 'login_client_secret', 'login_redirect_uri'] as $key) {
                $config->set('stalwart_' . $key, is_array($profile) ? ($profile[$key] ?? '') : '');
            }
            foreach (['login', 'twofactor', 'app_passwords', 'aliases', 'public_keys', 'masked_email'] as $feature) {
                $key = $feature . '_enabled';
                $config->set('stalwart_' . $key, $enabled && ($profile[$key] ?? $config->get('stalwart_' . $key, false)));
            }
            self::password_driver($rc);
        }
        else if (count(self::hosts($config)) !== 1) {
            // Multiple servers need an explicit allowlist, including password-only hosts.
            $enabled = false;
        }
        $config->set('stalwart_enabled', $enabled);

        if (!empty($rc->user->ID) && $enabled) {
            $binding = self::binding($rc);
            if (isset($_SESSION['stalwart_server']) && $_SESSION['stalwart_server'] !== $binding) {
                $config->set('stalwart_enabled', false);
            }
            else {
                $_SESSION['stalwart_server'] = $binding;
            }
        }
    }

    public static function password_driver($rc)
    {
        $profiles = $rc->config->get('stalwart_hosts');
        $host = $rc->config->get('stalwart_selected_host');
        $profile = is_array($profiles) ? ($profiles[$host ?? ''] ?? null) : null;
        if (is_array($profile) && isset($profile['password_driver'])) {
            $rc->config->set('password_driver', $profile['password_driver']);
        }
    }

    public static function binding($rc)
    {
        return hash('sha256', json_encode([
            $rc->config->get('stalwart_selected_host'), $rc->config->get('stalwart_api_url'),
            $rc->config->get('stalwart_login_client_id'), $rc->config->get('stalwart_login_client_secret'),
            $rc->config->get('stalwart_login_redirect_uri'), $rc->user->ID ?? null,
        ]));
    }

    public static function check_session($rc)
    {
        if (empty($rc->user->ID) || self::host($rc) !== $rc->config->get('stalwart_selected_host')
            || ($_SESSION['stalwart_server'] ?? '') !== self::binding($rc)
        ) {
            throw new RuntimeException('authenticationerror');
        }
        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST'
            && rcube_utils::get_input_string('_stalwart_server', rcube_utils::INPUT_POST) !== self::binding($rc)
        ) {
            throw new RuntimeException('statechanged');
        }
    }
}
