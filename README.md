# PowerShell SecretStore module

This module is an extension vault for the [PowerShell SecretManagement](https://github.com/PowerShell/SecretManagement) module.
It stores secrets locally on file for the current user account context, and uses .NET crypto APIs to encrypt file contents.
Secrets remain encrypted in-memory, and are only decrypted when retrieved and passed to the user.
This module works over all supported PowerShell platforms on Windows, Linux, and macOS.
In the default configuration, a password is required to store and access secrets, and provides the strongest protection.  

## Secret metadata

Supporting secret metadata is optional for SecretManagement extension vaults.
The SecretStore supports secret metadata through the optional `Set-Secret` vault command `Metadata` parameter, and the optional `Set-SecretInfo` vault command.  

## Configuration

The SecretStore module allows a number of configurations.  

It can be configured to require a password to unlock the store, or operate without a password.  
The no-password option still encrypts secrets on file and in memory.
But the key for decryption is stored on file in the current user location, and is less secure.  

SecretStore can also be configured to prompt the user for the password if needed.
When a password is provided, it applies only to the current PowerShell session and only for a limited time.
The password timeout time is also configurable and set to 15 minutes by default.
Password prompting is useful when SecretStore is used interactively.
For automation scenarios, password prompting can be disabled and will instead return an error.

If password prompting is disabled and a password is required to access secrets, a Microsoft.PowerShell.SecretStore.PasswordRequiredException will be thrown.
In this case, the SecretStore can be unlocked using the `Unlock-SecretStore` cmdlet.  

There is also a SecretStore `Scope` setting, but it is currently set to `CurrentUser` and cannot be changed.  

The default configuration is set to for best security and interactive use.  

```powershell
Get-SecretStoreConfiguration

      Scope Authentication PasswordTimeout Interaction
      ----- -------------- --------------- -----------
CurrentUser       Password             900      Prompt
```

### SecretStore cmdlets

The SecretStore exports five cmdlets for manipulating configuration and store state.  

#### Get-SecretStoreConfiguration

This cmdlet displays the current configuration.  

#### Set-SecretStoreConfiguration

This cmdlet sets configuration options for SecretStore.
Individual configuration options can be set, or the store can be configured to default settings by using the `-Default` parameter switch.  

```powershell
Set-SecretStoreConfiguration -PasswordTimeout 30

      Scope Authentication PasswordTimeout Interaction
      ----- -------------- --------------- -----------
CurrentUser       Password              30      Prompt
```

#### Unlock-SecretStore

This cmdlet unlocks the SecretStore with the provided password.
The password can be passed in as a `SecureString` type or in plain text.  

#### Set-SecretStorePassword

This cmdlet changes the SecretStore password.
It takes no parameters and can only be used interactively, as it prompts the user for old and new passwords.  

#### Reset-SecretStore

This cmdlet deletes all data in the SecretStore, and updates the configuration.
If no configuration parameters are specified, the default settings will be used.  
This cmdlet is intended for cases where the password is forgotten, or store files become corrupt and SecretStore is unusable.

## Code of Conduct

Please see our [Code of Conduct](.github/CODE_OF_CONDUCT.md) before participating in this project.

## Security Policy

For any security issues, please see our [Security Policy](.github/SECURITY.md).
