/* Use Roundcube's confirmation dialog for actions that remove access or delivery. */
window.rcmail && rcmail.addEventListener('init', function() {
    // Native commands also enable the active skin's mobile toolbar buttons.
    $.each({
        'plugin.stalwart-save': 'stalwart-form',
        'plugin.password-stalwart-save': 'stalwart-password-form',
        'plugin.stalwart-public-keys-save': 'stalwart-key-create',
        'plugin.stalwart-masked-email-save': 'stalwart-masked-create',
        'plugin.stalwart-app-passwords-save': 'stalwart-app-create',
        'plugin.stalwart-aliases-save': 'stalwart-alias-create'
    }, function(command, id) {
        var form = document.getElementById(id);
        if (form) {
            rcmail.register_command(command, function() {
                if (form.reportValidity()) {
                    form.submit();
                }
            }, true);
        }
    });

    $(document).on('click', '[data-stalwart-confirm]', function(event) {
        var button = this, form = button.form;
        if (!form || !form.checkValidity()) {
            return;
        }
        event.preventDefault();
        rcmail.confirm_dialog(rcmail.get_label(button.getAttribute('data-stalwart-confirm')), 'continue', function() {
            form.submit();
        });
    });
});
