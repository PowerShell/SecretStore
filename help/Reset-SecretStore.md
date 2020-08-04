---
external help file: Microsoft.PowerShell.SecretStore.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretStore
online version:
schema: 2.0.0
---

# Reset-SecretStore

## SYNOPSIS
Resets the SecretStore by deleting all secret data and configuring the store with default options.

## SYNTAX

```
Reset-SecretStore [-Scope <SecureStoreScope>] [-PasswordRequired] [-PasswordTimeout <Int32>] [-DoNotPrompt]
 [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet completely resets the SecretStore by deleting all secret data it may contain, and resetting configuration options to their default values.
It is intended to be used only if a required password is lost, or data files become corrupted so that SecretStore no longer functions and secret data cannot be accessed.  
Default configuration options can be overridden by specifying individual command configuration option parameters.

## EXAMPLES

### Example 1
```powershell
PS C:\> Reset-SecretStore
WARNING: !!This operation will completely remove all SecretStore module secrets and reset configuration settings to default values!!

Confirm
Are you sure you want to perform this action?
Performing the operation "Erase all secrets in the local store and reset the configuration settings" on target
"SecretStore module local store".
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): Y

      Scope PasswordRequired PasswordTimeout DoNotPrompt
      ----- ---------------- --------------- -----------
CurrentUser             True             900       False

PS C:\>
```

This example resets the SecretStore for the current user, by deleting all secrets and forcing configuration settings to default values.
The user is warned of the consequences of this action and prompted to confirm before continuing.

## PARAMETERS

### -DoNotPrompt
Configuration option to suppress user prompting.
When true, no prompt will be presented in an interactive session to provide a session password.
Default value is false, and users will be prompted for password when needed.
When true and a session password is required, a Microsoft.PowerShell.SecretStore.PasswordRequiredException error is thrown.

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

### -Force
When true, the user will not be asked to confirm and the SecretStore will be reset without prompting.
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

### -PasswordRequired
Configuration option to require a password for store access.
When true, SecretStore is configured to require a password for accessing secrets.
Default value is true, as this provides the strongest protection of secret data.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: True
Accept pipeline input: False
Accept wildcard characters: False
```

### -PasswordTimeout
Configuration option that provides the session password timeout in seconds.
Takes an argument whose value determines the session password timeout in seconds.
When the timeout value is reached, the current password value is invalidated for the session.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 900
Accept pipeline input: False
Accept wildcard characters: False
```

### -Scope
Configuration option that determines SecretStore operation scope.
Currently only 'CurrentUser' scope is supported.

```yaml
Type: SecureStoreScope
Parameter Sets: (All)
Aliases:
Accepted values: CurrentUser, AllUsers

Required: False
Position: Named
Default value: CurrentUser
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
Default value: None
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
Default value: None
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
