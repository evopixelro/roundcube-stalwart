<?php

/**
 * Native Stalwart account security settings for Roundcube.
 */
class stalwart extends rcube_plugin
{
    public $task = 'settings';
    public $noajax = true;
    public $noframe = true;

    private $rc;
    private $enabled;
    private $error;
    private $pages = [];

    /**
     * Register enabled settings actions and their native Roundcube UI resources.
     */
    public function init()
    {
        require_once __DIR__ . '/stalwart_client.php';
        require_once __DIR__ . '/stalwart_totp.php';
        require_once __DIR__ . '/stalwart_page.php';

        $this->rc = rcmail::get_instance();
        $this->load_config();
        $this->add_texts('localization/');

        // Wait for other plugins to load their configuration, regardless of plugin order.
        $this->add_hook('startup', [$this, 'startup']);
    }

    public function startup($args)
    {
        if ($this->rc->config->get('password_driver') === 'stalwart') {
            // Reuse the bundled plugin's settings, translations and first-login policy.
            // Its source, drivers and templates remain unchanged.
            $this->require_plugin('password');
        }
        // Loading Password can override the driver through its local configuration.
        if ($this->rc->config->get('password_driver') === 'stalwart') {
            require_once __DIR__ . '/stalwart_password.php';
            $this->pages['password'] = $page = new rcube_stalwart_password_page($this);
            $this->register_action($page->action, [$page, 'show']);
            $this->register_action($page->action . '-save', [$page, 'save']);
            if ($args['action'] === 'plugin.password' || $args['action'] === 'plugin.password-save') {
                $args['action'] = $page->action . ($args['action'] === 'plugin.password-save' ? '-save' : '');
            }
        }

        $this->add_hook('settings_actions', [$this, 'settings_actions']);
        if ($this->pages || rcube_stalwart_client::enabled($this->rc->config)) {
            $this->include_stylesheet('stalwart.css');
            $this->include_script('stalwart.js');
            $this->rc->output->add_label('stalwart.confirmrevoke', 'stalwart.confirmdeletealias', 'stalwart.confirmdisablealias',
                'stalwart.confirmdeletekey', 'stalwart.confirmdeletemasked', 'stalwart.confirmdisablemasked');
        }
        if (!rcube_stalwart_client::enabled($this->rc->config)) {
            return $args;
        }

        if (rcube_stalwart_client::feature_enabled($this->rc->config, 'twofactor')) {
            $this->register_action('plugin.stalwart', [$this, 'settings']);
            $this->register_action('plugin.stalwart-save', [$this, 'save']);
        }
        else {
            $this->rc->session->remove('stalwart_setup');
        }
        foreach (['app_passwords', 'aliases', 'public_keys', 'masked_email'] as $feature) {
            if (rcube_stalwart_client::feature_enabled($this->rc->config, $feature)) {
                require_once __DIR__ . '/stalwart_' . $feature . '.php';
                $class = 'rcube_stalwart_' . $feature;
                $this->pages[$feature] = $page = new $class($this);
                $this->register_action($page->action, [$page, 'show']);
                $this->register_action($page->action . '-save', [$page, 'save']);
            }
        }
        if (!rcube_stalwart_client::feature_enabled($this->rc->config, 'app_passwords')) {
            $this->rc->session->remove('stalwart_app_secret');
        }
        return $args;
    }

    /**
     * Add enabled features to the Settings menu.
     */
    public function settings_actions($args)
    {
        if (isset($this->pages['password'])) {
            $args['actions'] = array_values(array_filter($args['actions'], function ($action) {
                return $action['action'] !== 'plugin.password';
            }));
        }
        $position = count($args['actions']);
        foreach ($this->pages as $page) {
            if ($page instanceof rcube_stalwart_password_page && !$page->available()) {
                continue;
            }
            $args['actions'][] = [
                'action' => $page->action,
                'class' => $page->menu_class,
                'label' => $page->title,
                'domain' => 'stalwart',
            ];
        }
        if (rcube_stalwart_client::feature_enabled($this->rc->config, 'twofactor')) {
            // Keep 2FA immediately below either the native or our password page.
            foreach ($args['actions'] as $index => $action) {
                if (in_array($action['action'], ['plugin.password', 'plugin.password-stalwart'], true)) {
                    $position = $index + 1;
                    break;
                }
            }
            array_splice($args['actions'], $position, 0, [[
                'action' => 'plugin.stalwart',
                'class' => 'twofactor-management',
                'label' => 'twofactor',
                'title' => 'manage',
                'domain' => 'stalwart',
            ]]);
        }
        return $args;
    }

    /**
     * Display the current server state and consume the previous action's notice.
     */
    public function settings()
    {
        // The QR code and enrolment secret must never be cached by a shared proxy.
        header('Cache-Control: private, no-store');
        try {
            $this->enabled = rcube_stalwart_client::from_session($this->rc)->status();
        }
        catch (RuntimeException $e) {
            $this->error = $e->getMessage();
        }

        if (isset($_SESSION['stalwart_notice'])) {
            $notice = $_SESSION['stalwart_notice'];
            $this->rc->session->remove('stalwart_notice');
            if (($notice['expires'] ?? 0) >= time()) {
                $this->rc->output->show_message('stalwart.' . $notice['message'], $notice['type']);
            }
        }

        $this->rc->overwrite_action('plugin.stalwart');
        $this->register_handler('plugin.body', [$this, 'settings_form']);
        $this->rc->output->set_pagetitle($this->gettext('twofactor'));
        $this->rc->output->send('plugin');
    }

    /**
     * Verify the current account credentials before changing TOTP settings.
     */
    public function save()
    {
        $this->rc->request_security_check();
        $message = 'updated';
        $type = 'confirmation';

        try {
            $operation = rcube_utils::get_input_string('_operation', rcube_utils::INPUT_POST);
            $password = rcube_utils::get_input_string('_current', rcube_utils::INPUT_POST, true);
            $code = trim(rcube_utils::get_input_string('_code', rcube_utils::INPUT_POST));
            if ($password === '') {
                throw new RuntimeException('currentpasswordrequired');
            }
            if (!preg_match('/^[0-9]{6}$/D', $code)) {
                throw new RuntimeException('invalidcode');
            }

            $client = rcube_stalwart_client::from_session($this->rc);
            $enabled = $client->status();
            if ($operation === 'enable' && !$enabled) {
                // A primary password stops working for IMAP after enabling 2FA.
                // Require a separate app password or OAuth before making that change.
                if ($client->uses_account_password($password)) {
                    throw new RuntimeException('persistentloginrequired');
                }

                $pending = $_SESSION['stalwart_setup'] ?? [];
                $token = rcube_utils::get_input_string('_setup', rcube_utils::INPUT_POST);
                if (!$this->valid_setup($pending) || !hash_equals($pending['token'], $token)) {
                    $this->rc->session->remove('stalwart_setup');
                    throw new RuntimeException('setupexpired');
                }

                $secret = $this->rc->decrypt($pending['secret']);
                $_SESSION['stalwart_setup']['attempts']++;
                if (!rcube_stalwart_totp::verify($secret, $code)) {
                    throw new RuntimeException('invalidcode');
                }

                $client->update($password, '', ['otpAuth/otpUrl' => $this->otp_uri($secret)]);
            }
            else if ($operation === 'disable' && $enabled) {
                $client->update($password, $code, ['otpAuth/otpUrl' => null]);
            }
            else {
                throw new RuntimeException('statechanged');
            }

            $this->rc->session->remove('stalwart_setup');
        }
        catch (RuntimeException $e) {
            $message = $e->getMessage();
            $type = 'error';
        }

        $_SESSION['stalwart_notice'] = ['message' => $message, 'type' => $type, 'expires' => time() + 60];
        $this->rc->output->redirect(['_task' => 'settings', '_action' => 'plugin.stalwart']);
    }

    /**
     * Render the plugin body through Roundcube's form helpers and active skin.
     */
    public function settings_form()
    {
        if ($this->error) {
            $content = html::div('boxwarning', rcube::Q($this->gettext($this->error)));
        }
        else {
            $content = html::p('hint', rcube::Q($this->gettext($this->enabled ? 'enabled' : 'disabled')));
            $hidden = new html_hiddenfield();
            $hidden->add(['name' => '_operation', 'value' => $this->enabled ? 'disable' : 'enable']);

            if (!$this->enabled) {
                if (!$this->valid_setup($_SESSION['stalwart_setup'] ?? [])) {
                    $_SESSION['stalwart_setup'] = [
                        'secret' => $this->rc->encrypt(rcube_stalwart_totp::secret()),
                        'token' => bin2hex(random_bytes(16)),
                        'user' => $this->rc->user->ID,
                        'expires' => time() + 600,
                        'attempts' => 0,
                    ];
                }
                $pending = $_SESSION['stalwart_setup'];
                $secret = $this->rc->decrypt($pending['secret']);
                $hidden->add(['name' => '_setup', 'value' => $pending['token']]);

                $renderer = new \BaconQrCode\Renderer\ImageRenderer(
                    new \BaconQrCode\Renderer\RendererStyle\RendererStyle(240),
                    new \BaconQrCode\Renderer\Image\SvgImageBackEnd()
                );
                $qr = (new \BaconQrCode\Writer($renderer))->writeString($this->otp_uri($secret));
                $content .= html::p('hint', rcube::Q($this->gettext('setuphelp')))
                    . html::div('stalwart-enrollment',
                        html::img(['src' => 'data:image/svg+xml;base64,' . base64_encode($qr), 'alt' => $this->gettext('qrcode'), 'width' => 240, 'height' => 240])
                        . html::p(null, rcube::Q($this->gettext('manualkey')))
                        . html::tag('code', ['class' => 'stalwart-secret'], rcube::Q($secret))
                    )
                    . html::p('hint', rcube::Q($this->gettext('loginhelp')));
            }
            else {
                $this->rc->session->remove('stalwart_setup');
            }

            $table = new html_table(['cols' => 2, 'class' => 'propform']);
            $password = new html_passwordfield(['name' => '_current', 'id' => 'stalwart-current', 'autocomplete' => 'current-password', 'required' => true]);
            $table->add('title', html::label('stalwart-current', rcube::Q($this->gettext('currentpassword'))));
            $table->add(null, $password->show());
            $otp = new html_inputfield(['name' => '_code', 'id' => 'stalwart-code', 'inputmode' => 'numeric', 'pattern' => '[0-9]{6}', 'maxlength' => 6, 'autocomplete' => 'one-time-code', 'required' => true]);
            $table->add('title', html::label('stalwart-code', rcube::Q($this->gettext('otpcode'))));
            $table->add(null, $otp->show());

            $button = $this->rc->output->button([
                'command' => 'plugin.stalwart-save',
                'class'   => 'button mainaction submit',
                'label'   => 'stalwart.' . ($this->enabled ? 'disable' : 'enable'),
            ]);
            $content .= $this->rc->output->form_tag([
                'id' => 'stalwart-form',
                'method' => 'post',
                'action' => $this->rc->url(['_task' => 'settings', '_action' => 'plugin.stalwart-save']),
            ], $hidden->show() . $table->show() . html::p('formbuttons', $button));
        }

        return html::div(['id' => 'prefs-title', 'class' => 'boxtitle'], rcube::Q($this->gettext('twofactor')))
            . html::div('box formcontainer scroller', html::div('boxcontent formcontent', $content));
    }

    private function valid_setup(array $pending)
    {
        return isset($pending['secret'], $pending['token'], $pending['user'], $pending['expires'], $pending['attempts'])
            && $pending['user'] === $this->rc->user->ID && $pending['expires'] > time() && $pending['attempts'] < 5;
    }

    private function otp_uri($secret)
    {
        return rcube_stalwart_totp::uri($secret, $this->rc->config->get('product_name', 'Webmail'), $this->rc->get_user_name());
    }
}
