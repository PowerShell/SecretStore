---
external help file: Microsoft.PowerShell.SecretStore.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretStore
online version:
schema: 2.0.0
---

# Set-SecretStoreConfiguration

## SYNOPSIS
Sets SecretStore configuration properties.

## SYNTAX

### ParameterSet (Default)
```
Set-SecretStoreConfiguration [-Scope <SecureStoreScope>] [-Authentication <Authenticate>]
 [-PasswordTimeout <Int32>] [-Interaction <Interaction>] [-Password <SecureString>] [-PassThru] [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

### DefaultParameterSet
```
Set-SecretStoreConfiguration [-Default] [-Password <SecureString>] [-PassThru] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION
This cmdlet takes individual parameter arguments that determine SecretStore configuration.
Or the '-Default' parameter can be used to restore SecretStore configuration to default settings.

## EXAMPLES

### Example 1
```
PS C:\> Set-SecretStoreConfiguration -Default

Confirm
Are you sure you want to perform this action?
Performing the operation "Changes local store configuration" on target "SecretStore module local store".
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): Y

      Scope Authentication PasswordTimeout Interaction
      ----- -------------- --------------- -----------
CurrentUser       Password             900      Prompt
```

This example uses the command to restore the SecretStore configuration settings to their default values.

### Example 2
```
Install-Module -Name Microsoft.PowerShell.SecretStore -Repository PSGallery -Force
$password = Import-CliXml -Path $securePasswordPath.xml
Set-SecretStoreConfiguration -Scope CurrentUser -Authentication Password -PasswordTimeout 3600 -Interaction None -Password $password -Confirm:$false

Install-Module -Name Microsoft.PowerShell.SecretManagement -Repository PSGallery -Force
Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault

Unlock-SecretStore -Password $password
```

This is an example of automation script that installs and configures the Microsoft.PowerShell.SecretStore module without user prompting.
The configuration requires a password and sets user interaction to None, so that SecretStore will never prompt the user.
The configuration also requires a password, and the password is passed in as a SecureString object.
The \`-Confirm:false\` parameter is used so that PowerShell will not prompt for confirmation.

Next, the SecretManagement module is installed and the SecretStore module registered so that  the SecretStore secrets can be managed.

The \`Unlock-SecretStore\` cmdlet is used to unlock the SecretStore for this session.
The password timeout was configured for 1 hour and SecretStore will remain unlocked in the session for that amount of time, after which it will need to be unlocked again before secrets can be accessed.

### Example 3
```
PS C:\> Get-SecretStoreConfiguration

      Scope Authentication PasswordTimeout Interaction
      ----- -------------- --------------- -----------
CurrentUser       Password             900        None

PS C:\> Set-SecretStoreConfiguration -Authentication Password -Password $password
Set-SecretStoreConfiguration: The Microsoft.PowerShell.SecretStore is already configured to require a password, and a new password cannot be added.
Use the Set-SecretStorePassword cmdlet to change an existing password.
```

This example attempts to set the SecretStore configuration to require a password and provides a new password.
But this results in an error.
This command cannot be used to change an existing password but only to toggle authentication to require or not require a password.
To change an existing SecretStore password, use the \`Set-SecretStorePassword\` command.

## PARAMETERS

### -Authentication
Configuration option to set authentication for store access.
Configuration options are 'Password' or 'None'.
When 'Password' is selected, SecretStore is configured to require a password for accessing secrets.
Default authentication is 'Password', as this provides the strongest protection of secret data.

```yaml
Type: Authenticate
Parameter Sets: ParameterSet
Aliases:

Required: False
Position: Named
Default value: Password
Accept pipeline input: False
Accept wildcard characters: False
```

### -Default
This parameter switch sets SecretStore configuration to its default settings.

```yaml
Type: SwitchParameter
Parameter Sets: DefaultParameterSet
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -PassThru
When used, will write the current SecretStore configuration to the pipeline.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Password
Password to be applied when changing the authentication configuration.
When changing the configuration from no password required to password required, the provided password will be set as the new store password.
When changing the configuration from password required to no password required, the provided password will be used to authorize the configuration change, and must be the current password used to unlock the store.
This command cannot be used to change the store password.
To change an existing password, use the \`Set-SecretStorePassword\` command.

```yaml
Type: SecureString
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PasswordTimeout
Configuration option that provides the session password timeout in seconds.
Takes an argument whose value determines the session password timeout in seconds.
When the timeout value is reached, the current password value is invalidated for the session.

```yaml
Type: Int32
Parameter Sets: ParameterSet
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Scope
Configuration option that determines SecretStore operation scope.
Currently only 'CurrentUser' scope is supported.

```yaml
Type: SecureStoreScope
Parameter Sets: ParameterSet
Aliases:
Accepted values: CurrentUser, AllUsers

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Interaction
Configuration option to allow or suppress user prompting.
Configuration options are 'Prompt' or 'None'.
When 'None' is selected, no prompt will be presented in an interactive session to provide a session password.
Default value is 'Prompt', and users will be prompted for password when needed.
When 'None' is selected and a session password is required, a Microsoft.PowerShell.SecretStore.PasswordRequiredException error is thrown.

```yaml
Type: Interaction
Parameter Sets: ParameterSet
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### Microsoft.PowerShell.SecretStore.SecureStoreConfig
## NOTES

## RELATED LINKS
