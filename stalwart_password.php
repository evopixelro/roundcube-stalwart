<?php

/**
 * Self-contained account-password page using the bundled Password plugin's policy.
 * No files are installed into the Password plugin and no core patches are needed.
 *
 * Password policy and session handling adapted from Roundcube's Password plugin.
 * Original author: Aleksander Machniak <alec@alec.pl>
 * Copyright (C) The Roundcube Dev Team
 * Modifications Copyright (C) 2026 EvoPixel
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 * This program is distributed WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See LICENSE.
 */
class rcube_stalwart_password_page extends rcube_stalwart_page
{
    // Keep this prefix compatible with Password's first-login redirect policy.
    public $action = 'plugin.password-stalwart';
    public $title = 'password';
    public $menu_class = 'password';

    public function available()
    {
        $hosts = $this->rc->config->get('password_hosts');
        $exceptions = array_filter(array_map('trim', (array) $this->rc->config->get('password_login_exceptions')));

        return rcube_stalwart_client::enabled($this->rc->config)
            && (!$hosts || in_array($_SESSION['storage_host'] ?? '', (array) $hosts, true))
            && !in_array($this->rc->get_user_name(), $exceptions, true);
    }

    public function show()
    {
        if (rcube_utils::get_input_string('_first', rcube_utils::INPUT_GET)) {
            $this->rc->output->show_message('password.firstloginchange', 'notice');
        }
        else if (!empty($_SESSION['password_expires'])) {
            $this->rc->output->show_message(
                $_SESSION['password_expires'] == 1 ? 'password.passwdexpired' : 'password.passwdexpirewarning',
                $_SESSION['password_expires'] == 1 ? 'error' : 'warning',
                ['expirationdatetime' => $_SESSION['password_expires']]
            );
        }
        parent::show();
    }

    public function save()
    {
        $this->rc->request_security_check();
        try {
            if (!$this->available() || $this->rc->config->get('password_disabled')) {
                throw new RuntimeException('passwordunavailable');
            }

            $charset = strtoupper($this->rc->config->get('password_charset', 'UTF-8'));
            $current = rcube_utils::get_input_string('_curpasswd', rcube_utils::INPUT_POST, true, $charset);
            $new = rcube_utils::get_input_string('_newpasswd', rcube_utils::INPUT_POST, true);
            $confirm = rcube_utils::get_input_string('_confpasswd', rcube_utils::INPUT_POST, true);
            $code = trim(rcube_utils::get_input_string('_stalwart_code', rcube_utils::INPUT_POST));
            $new = $this->validate($current, $new, $confirm, $charset);

            // Recheck the mail login, just as the bundled Password plugin does.
            if (!$this->rc->get_storage()->check_connection()) {
                throw new RuntimeException('authenticationerror');
            }
            $client = rcube_stalwart_client::from_session($this->rc);
            $primary_login = $client->uses_account_password($current);
            $client->update($current, $code, ['secret' => $new]);

            // Notify integrations of the real password change. Never replace an app
            // credential or OAuth session with the primary account password.
            $result = $this->rc->plugins->exec_hook('password_change', ['old_pass' => $current, 'new_pass' => $new]);
            if ($primary_login) {
                $_SESSION['password'] = $this->rc->encrypt($result['new_pass']);
            }
            if ($this->rc->config->get('newuserpassword')) {
                $this->rc->user->save_prefs(['newuserpassword' => false]);
            }
            if ($this->rc->config->get('password_log')) {
                rcube::write_log('password', sprintf('Password changed for user %s (ID: %d) from %s',
                    $this->rc->get_user_name(), $this->rc->user->ID, rcube_utils::remote_ip()));
            }
            $this->rc->session->remove('password_expires');
        }
        catch (RuntimeException $e) {
            $this->redirect($e->getMessage(), 'error');
            return;
        }
        $this->redirect('passwordsaved');
    }

    /**
     * Enforce configured local policy before sending a password to the server.
     */
    protected function validate($current, $new, $confirm, $charset)
    {
        if ($current === '' || $new === '') {
            throw new RuntimeException('currentpasswordrequired');
        }
        $source = strtoupper($this->rc->output->get_charset());
        $converted = rcube_charset::convert($new, $source, $charset);
        if (rcube_charset::convert($converted, $charset, $source) !== $new
            || preg_match('/[\x00-\x1F\x7F]/', $converted)
        ) {
            throw new RuntimeException('passwordforbidden');
        }
        if ($new !== $confirm) {
            throw new RuntimeException('passwordmismatch');
        }
        $minimum = (int) $this->rc->config->get('password_minimum_length', 8);
        if ($minimum && strlen($converted) < $minimum) {
            throw new RuntimeException('passwordshort');
        }
        if (!$this->rc->config->get('password_force_save') && hash_equals($current, $converted)) {
            throw new RuntimeException('passwordsame');
        }

        $minimum_score = $this->rc->config->get('password_minimum_score');
        if ($minimum_score) {
            $score = (!preg_match('/[0-9]/', $converted) || !preg_match('/[^A-Za-z0-9]/', $converted)) ? 1 : 5;
            if ($driver = $this->rc->config->get('password_strength_driver')) {
                // Reuse a configured standard strength driver; a missing driver fails closed.
                $file = $this->rc->plugins->dir . 'password/drivers/' . $driver . '.php';
                if (!preg_match('/^[a-zA-Z0-9_]+$/D', $driver) || !is_file($file)) {
                    throw new RuntimeException('configurationerror');
                }
                require_once $file;
                $class = 'rcube_' . $driver . '_password';
                if (!class_exists($class) || !method_exists($class, 'check_strength')) {
                    throw new RuntimeException('configurationerror');
                }
                list($score) = (new $class())->check_strength($converted);
            }
            if ($score < $minimum_score) {
                throw new RuntimeException('passwordweak');
            }
        }
        return $converted;
    }

    protected function build()
    {
        if (!$this->available()) {
            throw new RuntimeException('passwordunavailable');
        }
        if ($disabled = $this->rc->config->get('password_disabled')) {
            return html::div('boxwarning', is_string($disabled) ? rcube::Q($disabled) : $this->text('passwordunavailable'));
        }

        $table = new html_table(['cols' => 2, 'class' => 'propform']);
        foreach (['curpasswd' => 'currentpassword', 'newpasswd' => 'newpassword', 'confpasswd' => 'confirmpassword'] as $id => $label) {
            $input = new html_passwordfield([
                'name' => '_' . $id,
                'id' => $id,
                'autocomplete' => $id === 'curpasswd' ? 'current-password' : 'new-password',
                'required' => true,
            ]);
            $table->add('title', html::label($id, $this->text($label)));
            $table->add(null, $input->show());
        }
        $otp = new html_inputfield([
            'name' => '_stalwart_code', 'id' => 'stalwart-code', 'inputmode' => 'numeric',
            'pattern' => '[0-9]{6}', 'maxlength' => 6, 'autocomplete' => 'one-time-code',
        ]);
        $table->add('title', html::label('stalwart-code', $this->text('otpcode')));
        $table->add(null, $otp->show() . html::p('hint', $this->text('codehelp')));

        $minimum = (int) $this->rc->config->get('password_minimum_length', 8);
        $hint = $minimum ? html::p('hint', rcube::Q($this->plugin->gettext([
            'name' => 'passwordminimum', 'vars' => ['length' => $minimum],
        ]))) : '';
        return $this->form([], $table->show() . $hint . html::p('formbuttons', $this->button('savepassword', null, true)), 'stalwart-password-form');
    }
}
