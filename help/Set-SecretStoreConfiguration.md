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
 [-PasswordTimeout <Int32>] [-Interaction <Interaction>] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### DefaultParameterSet
```
Set-SecretStoreConfiguration [-Default] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet takes individual parameter arguments that determine SecretStore configuration.
Or the '-Default' parameter can be used to restore SecretStore configuration to default settings.

## EXAMPLES

### Example 1
```powershell
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

### -Force
When used, the user will not be asked to confirm and the SecretStore will be reset without prompting.
Default value is false, and user will be asked to confirm the operation.

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
