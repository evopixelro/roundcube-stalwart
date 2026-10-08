# Stalwart for Roundcube

Manage Stalwart account security and email addresses from Roundcube Settings.
An independent community plugin by **EvoPixel**, licensed under **GPL-3.0-or-later**.

The plugin has automated API checks and isolated browser tests. The
Stalwart API contract was checked against server source, but a live Stalwart
deployment has not yet been validated. Test on a staging account before deployment.

## Features

- Account-password changes using the existing Password plugin's policies.
- TOTP two-factor setup and removal, with locally generated QR codes.
- Application passwords: create, display once and revoke.
- Email aliases for accounts with existing administrative permissions.
- Public OpenPGP/S/MIME keys: import, rename and delete.
- Masked email: create, enable/disable and delete on Stalwart Enterprise.

Features are independently configurable and disabled by default. The plugin uses
native settings pages and multilingual catalogs with native English fallback.
No core, skin, built-in
Password plugin or database patches are needed.

The 80 complete language catalogs cover Roundcube 1.6/1.7 through native fallbacks.
New translations are machine-generated; native-speaker corrections are welcome.
Dari uses the Persian fallback. Asturian, Interlingua, Kabyle, Norwegian Nynorsk
and Talossan currently use English.

## Compatibility

Supported Roundcube series: **1.6.x, starting at 1.6.0, and 1.7.x**.
Support targets both series, not just the individual releases listed below. The
plugin uses Roundcube's public plugin API, with no checks that restrict it to
specific patch releases. New 1.6.x and 1.7.x patches are expected to work while
those APIs and the declared dependencies remain compatible; each future release
still needs regression testing.

**Roundcube 1.8 and later:** the plugin may work if the same APIs remain available,
but these versions are not yet tested or included in the supported range. Support
will be reassessed when they are available. Versions before 1.6.0 are unsupported.

### Tested releases

The following are test coverage examples, not an exhaustive compatibility list.

| Roundcube | PHP used | Checks |
| --- | --- | --- |
| 1.6.0 | 7.4 | Offline API/policy suite and native plugin lifecycle |
| 1.6.19 | 8.2 | Offline suites, Composer installation, browser fixtures |
| 1.7.0 | 8.2 | Offline API/policy suite and native plugin lifecycle |
| 1.7.4 | 8.2 | Offline suites, Composer installation, browser fixtures |

Older patches are compatibility fixtures, not deployment recommendations. Use a
current security release from [Roundcube downloads](https://roundcube.net/download/).

### Runtime and integration requirements

The plugin requires PHP 7.4+, JSON, OpenSSL and XMLWriter. Follow any stricter
requirements of Roundcube itself: 1.7 requires PHP 8.1+. Composer resolves Guzzle
and BaconQrCode (versions 2 or 3) in Roundcube's dependency environment.

Browser checks cover stock Elastic and EvoPixel/Xopsys skins on desktop/mobile.
Other skins must implement the native plugin/settings UI and have not all been
tested. Roundcube 1.7 requires its normal `public_html` document root and asset
router. This plugin adds no public PHP endpoint or extra rewrite requirement.

The Stalwart contract was checked against **0.16.25**, using the current `x:*`
JMAP management API, not legacy REST endpoints. Password/TOTP management targets
Stalwart's internal directory, not credentials managed by external directories.

## Install

From the **Roundcube root**, where its `composer.json` is located:

```sh
composer require "evopixel/stalwart:1.0.2"
```

The package and its dependencies are available on Packagist. No extra
`repositories` entry is required. Composer ignores repository declarations inside
dependencies; custom repositories belong to the application root.

To follow development instead, use `evopixel/stalwart:dev-main`.

Allow the trusted `roundcube/plugin-installer` Composer plugin when prompted.
It converts the package name to **`plugins/stalwart`** and normally
creates `config.inc.php` from the distributed example. Check Roundcube's plugin
list and append the following once if the installer has not already enabled it:

```php
// Keep the other entries in your existing plugins array.
$config['plugins'][] = 'stalwart';
```

Configure `plugins/stalwart/config.inc.php`. Copy `config.inc.php.dist`
to that path first if the installer did not create it. Roundcube also supports
`stalwart.inc.php` in its configuration directory when no local plugin
file exists.

**Local plugin configuration overrides the main Roundcube configuration.** A
generated local file with `false` values overrides the same options set to `true`
in the main configuration. Avoid defining an option in multiple locations.

A manual installation must use the same directory name and install the declared
dependencies through Roundcube's root Composer environment. Do not bundle a second
Roundcube installation or a separate plugin `vendor` directory.

### Configuration

| Option | Default | Purpose |
| --- | --- | --- |
| `stalwart_enabled` | `false` | Master switch |
| `stalwart_api_url` | `''` | Trusted HTTPS JMAP URL for the mailbox's server |
| `stalwart_twofactor_enabled` | `false` | TOTP setup/removal |
| `stalwart_app_passwords_enabled` | `false` | Application passwords |
| `stalwart_aliases_enabled` | `false` | Alias administration |
| `stalwart_public_keys_enabled` | `false` | Public-key management |
| `stalwart_masked_email_enabled` | `false` | Enterprise masked email |

For example, in the local plugin configuration:

```php
$config['stalwart_enabled'] = true;
$config['stalwart_api_url'] = 'https://mail-server.example.com/jmap';
$config['stalwart_twofactor_enabled'] = true;
$config['stalwart_app_passwords_enabled'] = true;
```

Enable other features only after reviewing the permission requirements below.
Disabled features have no settings entry or registered feature actions. The
master switch and URL are required for all features. Disabling the TOTP management
page does not bypass OTP verification on password changes.

### Password provider

To use this plugin for password changes, set the driver in the existing Password
configuration, replacing its previous value:

```php
$config['password_driver'] = 'stalwart';
```

Keep the bundled `password` plugin enabled when using its local configuration or
first-login forced-password policy. If the driver is already selected in the
main or Stalwart configuration, this plugin can load Password automatically.
Password's local configuration still has priority and is checked again after loading.
Selecting another provider, such as Mailcow, leaves that provider's page unchanged.
The TOTP entry follows Password regardless of the selected provider.

Length, encoding, strength, force-save, host/login restrictions, disabled state,
logging, expiry and `password_change` hooks retain the built-in Password plugin's
semantics. A missing configured strength driver fails closed. The main password
is required even if `password_confirm_current` is false, because the API requires it.

## Authentication and permissions

Use a trusted HTTPS endpoint for the same server as the signed-in mailbox.
Requests use the current user's refreshed OAuth token or session credential.
No shared administrator key is needed or accepted. TLS verification is mandatory,
redirects are refused, timeouts are five seconds to connect and 15 seconds per
request, and responses are limited to 64 KiB.

For OAuth, use Roundcube's standard `oauth_*` settings and callback routing. No
extra callback is introduced. Password and TOTP changes also require the main
account password and, when 2FA is active, its six-digit code. Do not append the
code to the password.

| Feature | Stalwart permissions |
| --- | --- |
| Password / TOTP | `sysAccountPasswordGet`, `sysAccountPasswordUpdate` |
| Application passwords | `sysAppPasswordGet`, `sysAppPasswordCreate`, `sysAppPasswordDelete` |
| Aliases | `sysAccountSettingsGet`, `sysAccountGet`, `sysAccountUpdate`, `sysDomainGet` |
| Public keys | `sysAccountSettingsGet`, `sysPublicKeyGet`, `sysPublicKeyQuery`, `sysPublicKeyCreate`, `sysPublicKeyUpdate`, `sysPublicKeyDestroy` |
| Masked email | `sysAccountSettingsGet`, `sysMaskedEmailGet`, `sysMaskedEmailQuery`, `sysMaskedEmailCreate`, `sysMaskedEmailUpdate`, `sysMaskedEmailDestroy`; Enterprise license |

IMAP/SMTP permissions are also needed for Webmail. The plugin never grants
permissions and accepts no submitted account ID. Registry queries and mutations
verify ownership, including for accounts with impersonation privileges. The
server remains the final authorization authority.

**Ordinary users normally cannot administer aliases through the current API.**
Its Account/Domain endpoints require broader administrative permissions. Keep
aliases disabled for ordinary users; do not grant broad privileges just for this
page. A UI restriction does not restrict what that credential can do elsewhere.

## Feature behaviour

### TOTP and account passwords

Enabling TOTP from a main-password Webmail session is rejected before any write,
because subsequent IMAP authentication would stop working. Sign in with an app
password or OAuth first. Account-password changes preserve app-password/OAuth
session credentials; primary-password sessions switch to the new password.

QR generation is local. The pending secret is encrypted in the existing session,
bound to the user and setup token, and expires after ten minutes or five failed
attempts. The browser cannot supply a replacement seed. Recovery-code management
is not included; use the server's normal recovery process.

### Application passwords and aliases

Created app passwords inherit account permissions. Secrets are encrypted for
one-time display with a two-minute expiry; listings never request secret hashes.
Revocation accepts only listed app passwords, not the main password or API keys.
Revoking Webmail's credential may require another login. Dates use midnight UTC.

Aliases are delivery addresses, not sender identities. Additions are limited to
the account's primary domain, and only aliases are updated. Stale forms are
rejected after re-reading the list. The API has no mutation-state precondition,
so an external edit between that read and write cannot be completely excluded.

### Public keys and masked email

Import one ASCII-armoured OpenPGP public key or PEM X.509 certificate, up to
16 KiB. Private-key armour and secret OpenPGP packets are rejected before API
submission; Stalwart performs final cryptographic validation. Never upload private keys.

Import does not activate encryption-at-rest policy. Its selected key is labelled
and cannot be deleted here while selected. Manage policy in the server's account
portal and preserve private keys for existing encrypted mail. This page does not
replace Enigma or another client-side decryption plugin.

Masked email requires **Stalwart Enterprise**. The server generates the address;
the supplied site domain describes the website using it, not its delivery domain.
Expiration is encoded in the address and cannot be extended. Expired addresses
cannot be re-enabled. Addresses are not added automatically as sender identities.
Key and masked-address lists show 20 entries per page.

## Update, migrate or uninstall

Back up local configuration and review [CHANGELOG.md](CHANGELOG.md). Select a new
tagged version with `composer require evopixel/stalwart:<version>`, or
use `composer update evopixel/stalwart` when following `dev-main`.
Retain your application's `composer.lock` and test before deploying. The installer
preserves local configuration; review new options in `config.inc.php.dist`.

Before uninstalling, restore a working password driver if needed, remove
`stalwart` from the enabled list, then run
`composer remove evopixel/stalwart`. Back up configuration you want to keep.
Uninstalling does not disable server 2FA, revoke passwords or remove server data.
No Roundcube database migration is needed; short-lived secrets use existing
encrypted session storage. Fork-specific Home/Account links remain independent.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| No settings entries | Plugin list, master/feature flags, URL, and local config overriding the main file |
| Wrong password provider | Password's own configuration, enabled plugin list, host/login restrictions |
| Missing QR | Composer dependencies and XMLWriter in the web PHP runtime, not only CLI |
| Connection/authentication error | Endpoint, TLS chain, outbound HTTPS, same-server credentials and OAuth refresh; never disable TLS validation |
| Unavailable alias or masked-email page | Required permissions; Enterprise license for masked email |
| TOTP setup refuses login method | Reconnect using an app password or OAuth |
| TOTP rejected | Clock synchronization, current six-digit code and unexpired setup session |
| App-password secret disappeared | Display is one-time; revoke an unused password and create another |
| Active key cannot be deleted | Change encryption policy through the account portal first |

## Development and reporting

Use an isolated Roundcube installation with its Composer dependencies:

```sh
composer validate --strict
ROUNDCUBE_ROOT=/path/to/development/roundcube composer test
node --check stalwart.js
```

On PowerShell, set `$env:ROUNDCUBE_ROOT = 'C:/path/to/development/roundcube'` before
running `composer test`. When installed under Roundcube's `plugins` directory,
the tests discover the root automatically.

The API suite uses mock responses, synthetic keys and TOTP vectors. Lifecycle
checks use each version's real `rcube_plugin` class with test adapters. They check
feature gates, action registration, config precedence, menu order and resource
names. Browser fixtures use isolated API/IMAP services and SQLite. None use live
accounts. Live Stalwart validation remains necessary for production claims.

Follow existing four-space PHP formatting and native hooks, actions, HTML helpers,
translations and the `plugin` template. Keep feature-specific helpers separate
and avoid core/skin patches. Update the complete language catalogs together, preserve CSRF and
ownership checks, and add regression checks for security-sensitive changes.
See the [Roundcube Plugin API](https://github.com/roundcube/roundcubemail/wiki/Plugin-API).

Use [GitHub issues](https://github.com/evopixelro/roundcube-stalwart/issues) for
sanitized bug reports. Report vulnerabilities privately through
[GitHub security advisories](https://github.com/evopixelro/roundcube-stalwart/security/advisories/new). Never include credentials, tokens, cookies, TOTP seeds, private keys
or personal mail. Composer derives versions from Git; do not add a fixed `version`
field. Publish future fixes under new tags rather than replacing released tags.

## License and attribution

Copyright (C) 2026 EvoPixel. GNU General Public License version 3 or later;
see [LICENSE](LICENSE).

Password-policy and session code in `stalwart_password.php` is adapted from
Roundcube's [Password plugin](https://github.com/roundcube/roundcubemail/blob/1.6.19/plugins/password/password.php):
Copyright (C) The Roundcube Dev Team; original author Aleksander Machniak
<alec@alec.pl>; GPL-3.0-or-later. Original notices remain in the adapted source.

Composer dependencies retain their own licenses and are not bundled. Public test
keys are synthetic fixtures. This independent plugin is not an official Roundcube
or Stalwart product and includes neither Stalwart server code nor an Enterprise license.
