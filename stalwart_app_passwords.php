<?php

/**
 * Create and revoke the signed-in user's Stalwart application passwords.
 */
class rcube_stalwart_app_passwords extends rcube_stalwart_page
{
    public $action = 'plugin.stalwart-app-passwords';
    public $title = 'apppasswords';
    public $menu_class = 'stalwart-app-passwords';

    protected function build()
    {
        $items = rcube_stalwart_client::from_session($this->rc)->app_passwords();
        $content = html::p('hint', $this->text('apphelp'));
        if (isset($_SESSION['stalwart_app_secret'])) {
            $pending = $_SESSION['stalwart_app_secret'];
            $this->rc->session->remove('stalwart_app_secret');
            if (($pending['user'] ?? null) === $this->rc->user->ID && ($pending['expires'] ?? 0) > time()) {
                $content .= html::div('boxwarning stalwart-generated', $this->text('secretshownonce')
                    . html::tag('code', ['class' => 'stalwart-secret'], rcube::Q($this->rc->decrypt($pending['secret']))));
            }
        }

        $table = new html_table(['cols' => 2, 'class' => 'propform']);
        $description = new html_inputfield(['name' => '_description', 'id' => 'stalwart-description', 'maxlength' => 200, 'required' => true, 'autocomplete' => 'off']);
        $table->add('title', html::label('stalwart-description', $this->text('appname')));
        $table->add(null, $description->show());
        $expires = new html_inputfield(['type' => 'date', 'name' => '_expires', 'id' => 'stalwart-expires', 'min' => gmdate('Y-m-d', time() + 86400)]);
        $table->add('title', html::label('stalwart-expires', $this->text('expires')));
        $table->add(null, $expires->show() . html::p('hint', $this->text('expiryhelp')));
        $content .= $this->form(['_operation' => 'create'], $table->show()
            . html::p('formbuttons', $this->button('generate', null, true)), 'stalwart-app-create');

        $content .= html::tag('h2', null, $this->text('existingapps'));
        if (!$items) {
            return $content . html::p('hint', $this->text('noapps'));
        }
        foreach ($items as $item) {
            $details = html::tag('strong', null, rcube::Q($item['description']))
                . html::p('hint', $this->text('created') . ': ' . $this->date($item['createdAt'] ?? null)
                    . ' · ' . $this->text('expires') . ': ' . $this->date($item['expiresAt'] ?? null));
            $content .= html::div('stalwart-entry', html::div('stalwart-entry-details', $details)
                . $this->form(['_operation' => 'revoke', '_id' => $item['id']], $this->button('revoke', 'stalwart.confirmrevoke')));
        }
        return $content;
    }

    public function save()
    {
        $this->rc->request_security_check();
        $message = 'apprevoked';
        try {
            $client = rcube_stalwart_client::from_session($this->rc);
            $operation = rcube_utils::get_input_string('_operation', rcube_utils::INPUT_POST);
            if ($operation === 'create') {
                $created = $client->create_app_password(
                    rcube_utils::get_input_string('_description', rcube_utils::INPUT_POST),
                    rcube_utils::get_input_string('_expires', rcube_utils::INPUT_POST)
                );
                // Deliver the generated secret once through an encrypted, short-lived session value.
                $_SESSION['stalwart_app_secret'] = [
                    'secret' => $this->rc->encrypt($created['secret']),
                    'user' => $this->rc->user->ID,
                    'expires' => time() + 120,
                ];
                $message = 'appcreated';
            }
            else if ($operation === 'revoke') {
                $client->revoke_app_password(rcube_utils::get_input_string('_id', rcube_utils::INPUT_POST));
            }
            else {
                throw new RuntimeException('invalidoperation');
            }
        }
        catch (RuntimeException $e) {
            $this->redirect($e->getMessage(), 'error');
            return;
        }
        $this->redirect($message);
    }
}
