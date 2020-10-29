# CHANGELOG

## 0.5.3-Preview3 - 2020-11-4

### Fixes

### Changes

- `Set-SecretStoreConfiguration` now has a `-PassThru` parameter to write the store configuration object to the pipeline, and no longer writes the configuration object by default (Issue #25).

- A `-PasswordTimeout` value of zero now allows the provided password to be used only once (Issue #30).

- When setting a password, an empty password is no longer accepted (Issue #31)

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
