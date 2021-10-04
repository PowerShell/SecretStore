# CHANGELOG

## 1.0.5 - 2021-10-5

### Fixes

- Fix for Windows platform UserName character casing bug (Issue #62).

### Changes

### New Features

## 1.0.4 - 2021-8-30

### Fixes

- Workaround Windows bug where UserName environment variable is incorrect case (Issue #62).

### Changes

### New Features

## 1.0.3 - 2021-8-12

### Fixes

- Fix race condition where updating store configuration fails with invalid password (Issue #79).

- Update password failure errors are now surfaced to users (Issue #79).

- Fix for random data corruption when password is updated.

### Changes

### New Features

## 1.0.2 - 2021-5-17

### Fixes

- Metadata does not accept datetime from Get-Date (Issue #59).

- Add better error message when running under Windows built-in accounts (Issue #63).

- Store update no longer removes current information on read failure.

### Changes

- Add support for SecretManagement `Unlock-SecretVault` command.

### New Features

## 1.0.0 - 2021-3-25

### Fixes

- `Set-SecretStoreConfiguration` will throw an error when setting a password if a password has already been set. In this case `Set-SecretStorePassword` must be used to reset an existing password.

- Fixed license Url in module manifest.

### Changes

- Minor changes to architecture document.

### New Features

## 0.9.2 - 2021-3-15

### Fixes

- Minor changes to help file format.

### Changes

- The `-Force` parameter was removed from the `Set-SecretStoreConfiguration` command, and instead the `-Confirm:$false` should be used to suppress PowerShell prompting in automation scripts.

### New Features

- `Set-SecretStoreConfiguration` command now takes a `-Password` parameter so that there is no need to prompt for a password (Issue #46).

## 0.9.1 - 2021-3-1

### Fixes

### Changes

- `Set-Secret` vault command now supports optional `Metadata` parameter (Issue #46).

- Add optional `Set-SecretInfo` vault command that sets `Metadata` to an existing vault secret (Issue #46).

### New Features

- Add support for SecretManagement secret metadata (Issue #46).

## 0.9.0 - 2021-1-15

### Fixes

### Changes

- Take SecretStore module to version 0.9.0 release candidate.

### New Features

## 0.5.4-preview4 - 2020-11-16

### Fixes

- Windows PowerShell incompatibility when creating new store files (Issue #28).

### Changes

- SecretStore binary is now built against net461 to provide full compatibility when run in PowerShell 6+ or WindowsPowerShell.

- `System.IO.FileSystem.AccessControl.dll` is now shipped with module to maintain compatibility with WindowsPowerShell.

### New Features

## 0.5.3-Preview3 - 2020-11-4

### Fixes

### Changes

- `Set-SecretStoreConfiguration` now has a `-PassThru` parameter to write the store configuration object to the pipeline, and no longer writes the configuration object by default (Issue #25).

- A `-PasswordTimeout` value of zero now allows the provided password to be used only once (Issue #30).

- When setting a password, an empty password is no longer accepted (Issue #31).

- `Set-SecretStorePassword` now has a parameter set that takes old/new password arguments, to allow setting password by automation (Issue #26).

- `Reset-SecretStore` now has a new `-Password` and `-PassThru` parameter.

- `Reset-SecretStore` will now prompt immediately for a new password, if password authentication is selected and prompt interaction is allowed (Issue #34).

### New Features

## 0.5.2-Preview2 - 2020-10-01

### Breaking Changes

This version of SecretStore is incompatible with previous versions because the configuration format has changed.
The previous file store cannot be read by the new version and you will need to reset the store `Reset-SecretStore` after installing the new version.  

!!! Be sure and save your current stored secrets so they can be re-added !!!

- `Set-SecretStoreConfiguration` now supports `-Authentication` and `-Interaction` parameters instead of `-PasswordRequired` and `-DoNotPrompt`.

- Rename `Update-SecretStorePassword` to `Set-SecretStorePassword`.

- Remove `Unlock-SecretStore` plain text parameter set.

### Fixes

- `Set-SecretStoreConfiguration` now throws an error if called with no parameters.

### Changes

- Add ProjectUri to manifest file.

- `Reset-SecretStore` now defaults to 'No' when prompting to continue.

### New Features
