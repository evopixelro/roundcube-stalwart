<?php

/**
 * Import and manage the signed-in account's public encryption keys.
 */
class rcube_stalwart_public_keys extends rcube_stalwart_page
{
    public $action = 'plugin.stalwart-public-keys';
    public $title = 'publickeys';
    public $menu_class = 'stalwart-public-keys';

    protected function build()
    {
        $result = rcube_stalwart_client::from_session($this->rc)->public_keys(rcube_utils::get_input_string('_page', rcube_utils::INPUT_GET));
        $content = html::p('hint', $this->text('keyhelp'));
        $table = new html_table(['cols' => 2, 'class' => 'propform']);
        $name = new html_inputfield(['name' => '_description', 'id' => 'stalwart-key-name', 'maxlength' => 200, 'required' => true]);
        $table->add('title', html::label('stalwart-key-name', $this->text('keyname')));
        $table->add(null, $name->show());
        $key = new html_textarea(['name' => '_key', 'id' => 'stalwart-key', 'rows' => 8, 'cols' => 60, 'maxlength' => 16384, 'required' => true, 'spellcheck' => 'false', 'autocomplete' => 'off']);
        $table->add('title', html::label('stalwart-key', $this->text('publickey')));
        $table->add(null, $key->show() . html::p('hint', $this->text('keyformat')));
        $expires = new html_inputfield(['type' => 'date', 'name' => '_expires', 'id' => 'stalwart-key-expires', 'min' => gmdate('Y-m-d', time() + 86400)]);
        $table->add('title', html::label('stalwart-key-expires', $this->text('expires')));
        $table->add(null, $expires->show() . html::p('hint', $this->text('expiryhelp')));
        $content .= $this->form(['_operation' => 'create'], $table->show()
            . html::p('formbuttons', $this->button('importkey', null, true)), 'stalwart-key-create');
        $content .= html::tag('h2', null, $this->text('existingkeys'));
        if (!$result['items']) {
            $content .= html::p('hint', $this->text('nokeys'));
        }
        foreach ($result['items'] as $item) {
            $active = $result['active_key'] === $item['id'];
            $details = html::tag('strong', null, rcube::Q($item['description'] ?? ''))
                . ($active ? html::p('hint', $this->text('activekey')) : '')
                . html::p('hint', $this->text('created') . ': ' . $this->date($item['createdAt'] ?? null)
                    . ' · ' . $this->text('expires') . ': ' . $this->date($item['expiresAt'] ?? null));
            $name = new html_inputfield(['name' => '_description', 'class' => 'form-control', 'maxlength' => 200, 'required' => true, 'aria-label' => $this->plugin->gettext('keyname')]);
            $actions = $this->form(['_operation' => 'rename', '_id' => $item['id']],
                $name->show($item['description'] ?? '') . $this->button('renamekey'));
            if (!$active) {
                $actions .= $this->form(['_operation' => 'delete', '_id' => $item['id']], $this->button('delete', 'stalwart.confirmdeletekey'));
            }
            $content .= html::div('stalwart-entry', html::div('stalwart-entry-details', $details) . html::div('stalwart-entry-actions', $actions));
        }
        return $content . $this->pagination($result);
    }

    public function save()
    {
        $this->rc->request_security_check();
        try {
            $client = rcube_stalwart_client::from_session($this->rc);
            $operation = rcube_utils::get_input_string('_operation', rcube_utils::INPUT_POST);
            $description = rcube_utils::get_input_string('_description', rcube_utils::INPUT_POST);
            if ($operation === 'create') {
                $client->create_public_key($description, rcube_utils::get_input_string('_key', rcube_utils::INPUT_POST, true),
                    rcube_utils::get_input_string('_expires', rcube_utils::INPUT_POST));
            }
            else {
                $client->update_public_key($operation, rcube_utils::get_input_string('_id', rcube_utils::INPUT_POST), $description);
            }
        }
        catch (RuntimeException $e) {
            $this->redirect($e->getMessage(), 'error');
            return;
        }
        $this->redirect('keyupdated');
    }
}
