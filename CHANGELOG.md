# CHANGELOG

## 0.5.2-Preview2 - 2020-09-25

### Breaking Changes

This version of secretStore is incompatible with previous versions because the configuration format has changed.
The previous file store cannot be read by the new version and you will need to reset the store `Reset-SecretStore` after installing the new version.  

!!! Be sure and save your current stored secrets so they can be re-added !!!

- `Set-SecretStoreConfiguration` now supports `-Authentication` and `-UserInteraction` parameters instead of `-PasswordRequired` and `-DoNotPrompt`.

### Fixes

- `Set-SecretStoreConfiguration` now throws an error if called with no parameters.

### Changes

- Add ProjectUri to manifest file.

- Change `Update-SecretStorePassword` to `Set-SecretStorePassword`.

- `Reset-SecretStore` now defaults to 'No' when prompting to continue.

### New Features
