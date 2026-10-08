<?php

/**
 * Manage aliases of the authenticated Stalwart account without accepting account IDs from forms.
 */
class rcube_stalwart_aliases extends rcube_stalwart_page
{
    public $action = 'plugin.stalwart-aliases';
    public $title = 'aliases';
    public $menu_class = 'stalwart-aliases';

    protected function build()
    {
        $account = rcube_stalwart_client::from_session($this->rc)->aliases();
        $content = html::p('hint', $this->text('aliashelp'));
        $table = new html_table(['cols' => 2, 'class' => 'propform']);
        $name = new html_inputfield(['name' => '_name', 'id' => 'stalwart-alias-name', 'maxlength' => 64, 'required' => true, 'autocomplete' => 'off']);
        $table->add('title', html::label('stalwart-alias-name', $this->text('aliasname')));
        $table->add(null, html::div('stalwart-alias-address', $name->show()
            . html::span(null, '@' . rcube::Q($account['domains'][$account['domainId']]))));
        $description = new html_inputfield(['name' => '_description', 'id' => 'stalwart-alias-description', 'maxlength' => 200]);
        $table->add('title', html::label('stalwart-alias-description', $this->text('description')));
        $table->add(null, $description->show());
        $content .= $this->form(['_operation' => 'create', '_version' => $account['version']], $table->show()
            . html::p('formbuttons', $this->button('addalias', null, true)), 'stalwart-alias-create');
        $content .= html::tag('h2', null, $this->text('existingaliases'));
        if (!$account['aliases']) {
            return $content . html::p('hint', $this->text('noaliases'));
        }
        foreach ($account['aliases'] as $alias) {
            $fields = ['_key' => rcube_stalwart_client::alias_key($alias), '_version' => $account['version']];
            $details = html::tag('strong', null, rcube::Q($alias['name'] . '@' . $account['domains'][$alias['domainId']]))
                . html::p('hint', $this->text($alias['enabled'] ? 'aliasenabled' : 'aliasdisabled')
                    . (!empty($alias['description']) ? ' · ' . rcube::Q($alias['description']) : ''));
            $actions = $this->form($fields + ['_operation' => $alias['enabled'] ? 'disable' : 'enable'],
                $this->button($alias['enabled'] ? 'disablealias' : 'enablealias', $alias['enabled'] ? 'stalwart.confirmdisablealias' : null));
            $actions .= $this->form($fields + ['_operation' => 'delete'], $this->button('deletealias', 'stalwart.confirmdeletealias'));
            $content .= html::div('stalwart-entry', html::div('stalwart-entry-details', $details)
                . html::div('stalwart-entry-actions', $actions));
        }
        return $content;
    }

    public function save()
    {
        $this->rc->request_security_check();
        try {
            rcube_stalwart_client::from_session($this->rc)->save_alias(
                rcube_utils::get_input_string('_operation', rcube_utils::INPUT_POST),
                rcube_utils::get_input_string('_key', rcube_utils::INPUT_POST),
                rcube_utils::get_input_string('_name', rcube_utils::INPUT_POST),
                rcube_utils::get_input_string('_description', rcube_utils::INPUT_POST),
                rcube_utils::get_input_string('_version', rcube_utils::INPUT_POST)
            );
        }
        catch (RuntimeException $e) {
            $this->redirect($e->getMessage() === 'permissionerror' ? 'aliaspermissionerror' : $e->getMessage(), 'error');
            return;
        }
        $this->redirect('aliassaved');
    }
}
