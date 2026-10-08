<?php

/**
 * Shared Roundcube form and flash-message handling for Stalwart settings pages.
 */
abstract class rcube_stalwart_page
{
    public $action;
    public $title;
    public $menu_class;

    protected $rc;
    protected $plugin;
    protected $content;

    public function __construct($plugin)
    {
        $this->plugin = $plugin;
        $this->rc = rcmail::get_instance();
    }

    public function show()
    {
        header('Cache-Control: private, no-store');
        try {
            $this->content = $this->build();
        }
        catch (RuntimeException $e) {
            $message = $e->getMessage();
            if ($message === 'permissionerror' && $this->title === 'aliases') {
                $message = 'aliaspermissionerror';
            }
            $this->content = html::div('boxwarning', $this->text($message));
        }
        $key = $this->action . '-notice';
        if (isset($_SESSION[$key])) {
            $notice = $_SESSION[$key];
            $this->rc->session->remove($key);
            if (($notice['expires'] ?? 0) > time()) {
                $this->rc->output->show_message('stalwart.' . $notice['message'], $notice['type']);
            }
        }
        $this->rc->overwrite_action($this->action);
        $this->plugin->register_handler('plugin.body', [$this, 'body']);
        $this->rc->output->set_pagetitle($this->plugin->gettext($this->title));
        $this->rc->output->send('plugin');
    }

    public function body()
    {
        return html::div(['id' => 'prefs-title', 'class' => 'boxtitle'], $this->text($this->title))
            . html::div('box formcontainer scroller', html::div('boxcontent formcontent stalwart-settings', $this->content));
    }

    protected function text($key)
    {
        return rcube::Q($this->plugin->gettext($key));
    }

    protected function form($fields, $content, $id = null)
    {
        $hidden = new html_hiddenfield();
        foreach ($fields as $name => $value) {
            $hidden->add(['name' => $name, 'value' => $value]);
        }
        return $this->rc->output->form_tag([
            'id' => $id,
            'method' => 'post',
            'action' => $this->rc->url(['_task' => 'settings', '_action' => $this->action . '-save']),
            'class' => 'stalwart-action-form',
        ], $hidden->show() . $content);
    }

    protected function button($label, $confirm = null, $main = false)
    {
        if ($main) {
            return $this->rc->output->button([
                'command' => $this->action . '-save',
                'class'   => 'button mainaction submit',
                'label'   => 'stalwart.' . $label,
            ]);
        }
        return html::tag('button', [
            'type' => 'submit',
            'class' => 'button',
            'data-stalwart-confirm' => $confirm,
        ], $this->text($label));
    }

    protected function redirect($message, $type = 'confirmation')
    {
        $_SESSION[$this->action . '-notice'] = ['message' => $message, 'type' => $type, 'expires' => time() + 60];
        $this->rc->output->redirect(['_task' => 'settings', '_action' => $this->action]);
    }

    protected function date($value)
    {
        if (!$value) {
            return $this->text('neverexpires');
        }
        $time = is_string($value) ? strtotime($value) : false;
        return $time === false ? '—' : rcube::Q($this->rc->format_date($time));
    }

    protected function pagination(array $result)
    {
        $links = '';
        foreach ([-1 => 'previouspage', 1 => 'nextpage'] as $direction => $label) {
            if (($direction < 0 && $result['page'] > 0) || ($direction > 0 && $result['more'])) {
                $links .= html::a(['class' => 'button', 'href' => $this->rc->url([
                    '_task' => 'settings', '_action' => $this->action, '_page' => $result['page'] + $direction,
                ])], $this->text($label));
            }
        }
        return $links ? html::div('stalwart-pagination', $links) : '';
    }

    abstract protected function build();
}
