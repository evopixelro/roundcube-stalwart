<?php

/**
 * Native two-step login, completed before Roundcube creates a mailbox session.
 */
class rcube_stalwart_login
{
    private $rc;
    private $plugin;
    private $client;
    private $authorization;
    private $error;

    public function __construct($plugin)
    {
        $this->plugin = $plugin;
        $this->rc = rcmail::get_instance();
        $plugin->add_hook('startup', [$this, 'startup']);
        $plugin->add_hook('authenticate', [$this, 'authenticate']);
        $plugin->add_hook('login_after', [$this, 'login_after']);
        $plugin->add_hook('login_failed', [$this, 'login_failed']);
        $plugin->add_hook('loginform_content', [$this, 'form']);
        try {
            // External redirect login and the embedded flow are alternative modes.
            if ($this->rc->config->get('oauth_provider')) {
                throw new RuntimeException('loginconfigurationerror');
            }
            $this->client = new rcube_stalwart_auth($this->rc->config);
            $this->rc->oauth = new rcube_stalwart_oauth($this->client);
        }
        catch (RuntimeException $e) {
            $this->error = 'loginconfigurationerror';
        }
    }

    public function startup($args)
    {
        if (!empty($this->rc->user->ID)) {
            $this->clear();
            return $args;
        }
        if ($args['task'] !== 'login') {
            return $args;
        }
        if ($args['action'] === 'plugin.stalwart-login-cancel') {
            $this->rc->request_security_check(rcube_utils::INPUT_GET);
            $this->clear();
            $this->rc->output->redirect(['_task' => 'login']);
        }
        if ($args['action'] !== 'login') {
            return $args;
        }
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || empty($_SESSION['temp']) || !$this->rc->check_request()) {
            $this->clear();
            $this->error = 'loginexpired';
            return $args;
        }

        $flow = rcube_utils::get_input_string('_stalwart_flow', rcube_utils::INPUT_POST);
        try {
            if ($this->error) {
                throw new RuntimeException($this->error);
            }
            if ($flow !== null && $flow !== '') {
                $pending = $this->pending();
                if (!$pending || !hash_equals($pending['flow'], $flow)) {
                    throw new RuntimeException('loginexpired');
                }
                // Consume an attempt before contacting the server, including malformed codes.
                $pending['attempts']--;
                $_SESSION['stalwart_login']['attempts'] = $pending['attempts'];
                $code = trim((string) rcube_utils::get_input_string('_stalwart_code', rcube_utils::INPUT_POST));
                if (!preg_match('/^[0-9]{6}$/D', $code)) {
                    throw new RuntimeException('invalidcode');
                }
                $password = $this->rc->decrypt($pending['password']);
                $this->authorization = $this->client->authorize($pending['username'], $password, $pending['verifier'], $code);
                unset($password);
                if (!$this->authorization) {
                    throw new RuntimeException('credentialserror');
                }
            }
            else {
                $this->clear();
                $username = trim((string) rcube_utils::get_input_string('_user', rcube_utils::INPUT_POST));
                $password = rcube_utils::get_input_string('_pass', rcube_utils::INPUT_POST, true,
                    $this->rc->config->get('password_charset', 'UTF-8'));
                $verifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
                $this->authorization = $this->client->authorize($username, $password, $verifier);
                if (!$this->authorization) {
                    $encrypted = $this->rc->encrypt($password);
                    if (!is_string($encrypted) || $encrypted === '') {
                        throw new RuntimeException('loginconfigurationerror');
                    }
                    $this->rc->session->regenerate_id(false);
                    $_SESSION['stalwart_login'] = [
                        'username' => $username, 'password' => $encrypted, 'verifier' => $verifier,
                        'flow' => bin2hex(random_bytes(32)), 'binding' => $this->client->binding(),
                        'expires' => time() + 300, 'attempts' => 5,
                        'url' => rcube_utils::get_input_string('_url', rcube_utils::INPUT_POST),
                    ];
                    unset($password, $_POST['_pass']);
                    $this->rc->output->redirect(['_task' => 'login', '_action' => 'plugin.stalwart-login']);
                }
                unset($password);
            }
            $this->clear();
        }
        catch (RuntimeException $e) {
            $message = $e->getMessage();
            $allowed = ['loginconfigurationerror', 'loginexpired', 'credentialserror', 'invalidcode',
                'ratelimited', 'connectionerror', 'loginresponseerror'];
            $this->error = in_array($message, $allowed, true) ? $message : 'connectionerror';
            if ($flow && $this->pending() && in_array($this->error, ['credentialserror', 'invalidcode', 'connectionerror'], true)) {
                $_SESSION['stalwart_login_notice'] = $this->error;
                $this->rc->output->redirect(['_task' => 'login', '_action' => 'plugin.stalwart-login']);
            }
            $this->clear();
        }
        return $args;
    }

    /**
     * Preserve Roundcube's checks, session rotation and normal login hooks.
     */
    public function authenticate($args)
    {
        if (empty($args['valid']) || !empty($args['abort'])) {
            $this->authorization = null;
            return $args;
        }
        if ($this->error || !$this->authorization) {
            $args['abort'] = true;
            $args['error'] = 'stalwart.' . ($this->error ?: 'loginexpired');
            return $args;
        }
        $args['user'] = $this->authorization['username'];
        $args['pass'] = 'Bearer ' . $this->authorization['token']['access_token'];
        $this->rc->config->set('imap_auth_type', 'XOAUTH2');
        $this->rc->config->set('login_password_maxlen', strlen($args['pass']));
        return $args;
    }

    public function login_after($args)
    {
        if ($this->authorization) {
            $_SESSION['oauth_token'] = $this->rc->oauth->prepare(
                $this->authorization['token'], $this->authorization['username']);
            $this->rc->plugins->exec_hook('oauth_login', $_SESSION['oauth_token'] + [
                'username' => $this->authorization['username'],
            ]);
            $this->authorization = null;
        }
        $this->clear();
        return $args;
    }

    public function login_failed($args)
    {
        $this->authorization = null;
        $this->clear();
        return $args;
    }

    /**
     * Reuse the active skin's login template for the second factor.
     */
    public function form($args)
    {
        if (!empty($_SESSION['stalwart_login_notice'])) {
            $this->rc->output->show_message('stalwart.' . $_SESSION['stalwart_login_notice'], 'warning');
            $this->rc->session->remove('stalwart_login_notice');
        }
        if (!$pending = $this->pending()) {
            return $args;
        }
        header('Cache-Control: private, no-store');
        $code = new html_inputfield([
            'name' => '_stalwart_code', 'id' => 'rcmstalwartcode', 'class' => 'form-control',
            'inputmode' => 'numeric', 'autocomplete' => 'one-time-code', 'pattern' => '[0-9]{6}',
            'maxlength' => 6, 'required' => 'required', 'autofocus' => 'autofocus',
            'data-icon' => 'pass',
        ]);
        $args['inputs'] = [
            'code' => ['title' => html::label('rcmstalwartcode', rcube::Q($this->plugin->gettext('otpcode'))),
                'content' => $code->show()],
        ];
        $args['hidden']['stalwart'] = (new html_hiddenfield(['name' => '_stalwart_flow', 'value' => $pending['flow']]))->show();
        $args['hidden']['url'] = (new html_hiddenfield(['name' => '_url', 'value' => $pending['url']]))->show();
        $args['hidden']['help'] = html::p(['class' => 'stalwart-login-help'], rcube::Q($this->plugin->gettext('loginotphelp')));
        $args['buttons'] = [
            'submit' => ['outterclass' => 'formbuttons', 'content' => html::tag('button', [
                'type' => 'submit', 'id' => 'rcmloginsubmit', 'class' => 'button mainaction submit',
            ], rcube::Q($this->plugin->gettext('loginverify')))],
            'cancel' => ['outterclass' => 'stalwart-login-cancel', 'content' => html::a([
                'class' => 'button', 'href' => $this->rc->url(['_task' => 'login',
                    '_action' => 'plugin.stalwart-login-cancel', '_token' => $this->rc->get_request_token()]),
            ], rcube::Q($this->rc->gettext('back')))],
        ];
        return $args;
    }

    private function pending()
    {
        $pending = $_SESSION['stalwart_login'] ?? null;
        if (!is_array($pending) || ($pending['expires'] ?? 0) <= time() || ($pending['attempts'] ?? 0) <= 0
            || !$this->client || ($pending['binding'] ?? '') !== $this->client->binding()
        ) {
            $this->clear();
            return null;
        }
        return $pending;
    }

    private function clear()
    {
        $this->rc->session->remove('stalwart_login');
        $this->rc->session->remove('stalwart_login_notice');
    }
}
