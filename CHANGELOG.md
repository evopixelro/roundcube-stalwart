# Changelog

## 1.0.0 — 2026-10-08

Initial release of `evopixel/stalwart`; development continues on `dev-main`.

### Corrected

- Respect the effective password driver after loading Password's local configuration.
- Document configuration precedence and development-branch installation explicitly.
- Add native plugin lifecycle checks and compatibility coverage for the beginning
  of the supported Roundcube series.
- Consolidate installation, compatibility, development and attribution documentation.

### Added

- Account-password changes using the current user's Stalwart API credentials.
- TOTP enrolment and removal, with locally generated QR codes and expiring setup sessions.
- Application-password creation, one-time secret display and revocation.
- Email-alias management for accounts with the required administrative permissions.
- Public OpenPGP/S/MIME key management and protection of the selected encryption key.
- Masked email creation, enable/disable and deletion on Stalwart Enterprise.
- Separate feature switches, all disabled by default.
- Native Roundcube settings pages, English and Romanian translations, and a 2FA
  menu entry immediately below Password when that entry is present.
- Composer installation, configuration and permission documentation, and offline checks.

### Validation and limitations

- Offline API/policy checks and browser fixtures cover Roundcube 1.6.19 and 1.7.4,
  stock Elastic and the EvoPixel/Xopsys skins, including mobile layouts.
- The API contract was checked against Stalwart 0.16.25 source. No live Stalwart
  deployment has been validated for this release; test on a staging account first.
- Ordinary users normally cannot administer aliases through the current API.
- Masked email requires Stalwart Enterprise.
- No Roundcube core, skin, Password plugin or database changes are required.
