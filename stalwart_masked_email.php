<?php

/**
 * Create and individually disable the signed-in account's masked addresses.
 */
class rcube_stalwart_masked_email extends rcube_stalwart_page
{
    public $action = 'plugin.stalwart-masked-email';
    public $title = 'maskedemail';
    public $menu_class = 'stalwart-masked-email';

    protected function build()
    {
        $result = rcube_stalwart_client::from_session($this->rc)->masked_email(rcube_utils::get_input_string('_page', rcube_utils::INPUT_GET));
        $content = html::p('hint', $this->text('maskedhelp'));
        $table = new html_table(['cols' => 2, 'class' => 'propform']);
        foreach (['description' => 'maskedname', 'prefix' => 'maskedprefix', 'domain' => 'maskedsitedomain'] as $field => $label) {
            $input = new html_inputfield(['name' => '_' . $field, 'id' => 'stalwart-masked-' . $field,
                'maxlength' => $field === 'prefix' ? 64 : ($field === 'domain' ? 253 : 200), 'required' => $field === 'description']);
            $table->add('title', html::label('stalwart-masked-' . $field, $this->text($label)));
            $table->add(null, $input->show() . ($field === 'prefix' ? html::p('hint', $this->text('maskedprefixhelp')) : ''));
        }
        $expires = new html_inputfield(['type' => 'date', 'name' => '_expires', 'id' => 'stalwart-masked-expires', 'min' => gmdate('Y-m-d', time() + 86400)]);
        $table->add('title', html::label('stalwart-masked-expires', $this->text('expires')));
        $table->add(null, $expires->show() . html::p('hint', $this->text('maskedexpiryhelp')));
        $content .= $this->form(['_operation' => 'create'], $table->show()
            . html::p('formbuttons', $this->button('generatemasked', null, true)), 'stalwart-masked-create');
        $content .= html::tag('h2', null, $this->text('existingmasked'));
        if (!$result['items']) {
            $content .= html::p('hint', $this->text('nomasked'));
        }
        foreach ($result['items'] as $item) {
            $expired = !empty($item['expiresAt']) && strtotime($item['expiresAt']) <= time();
            $details = html::tag('strong', ['class' => 'stalwart-address'], rcube::Q($item['email']))
                . html::p(null, rcube::Q($item['description'] ?? '') . (!empty($item['forDomain']) ? ' · ' . rcube::Q($item['forDomain']) : ''))
                . html::p('hint', $this->text($expired ? 'expired' : ($item['enabled'] ? 'addressenabled' : 'addressdisabled'))
                    . ' · ' . $this->text('expires') . ': ' . $this->date($item['expiresAt'] ?? null));
            $actions = '';
            if (!$expired) {
                $operation = $item['enabled'] ? 'disable' : 'enable';
                $actions = $this->form(['_operation' => $operation, '_id' => $item['id']],
                    $this->button($item['enabled'] ? 'disableaddress' : 'enableaddress', $item['enabled'] ? 'stalwart.confirmdisablemasked' : null));
            }
            $actions .= $this->form(['_operation' => 'delete', '_id' => $item['id']], $this->button('delete', 'stalwart.confirmdeletemasked'));
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
            if ($operation === 'create') {
                $client->create_masked_email(rcube_utils::get_input_string('_description', rcube_utils::INPUT_POST),
                    rcube_utils::get_input_string('_prefix', rcube_utils::INPUT_POST),
                    rcube_utils::get_input_string('_domain', rcube_utils::INPUT_POST),
                    rcube_utils::get_input_string('_expires', rcube_utils::INPUT_POST));
            }
            else {
                $client->update_masked_email($operation, rcube_utils::get_input_string('_id', rcube_utils::INPUT_POST));
            }
        }
        catch (RuntimeException $e) {
            $this->redirect($e->getMessage(), 'error');
            return;
        }
        $this->redirect('maskedupdated');
    }
}
