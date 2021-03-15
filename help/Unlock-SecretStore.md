---
external help file: Microsoft.PowerShell.SecretStore.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretStore
online version:
schema: 2.0.0
---

# Unlock-SecretStore

## SYNOPSIS
Unlocks SecretStore with the provided password.

## SYNTAX

```
Unlock-SecretStore -Password <SecureString> [-PasswordTimeout <Int32>] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet unlocks SecretStore for the current user with the provided password.
It can be used to unlock SecretStore when the configuration requires a password and the prompt configuration option is disabled.
The provided password will be applied to the current session, and will become invalid after the 'PasswordTimeout' time elapses.
If no password is provided by parameter argument, the user will be safely prompted for the password.

## EXAMPLES

### Example 1
```
PS C:\> Get-Secret secret1 -Vault LocalStore
Get-Secret: A valid password is required to access the Microsoft.PowerShell.SecretStore vault.
Get-Secret: The secret secret1 was not found.

PS C:\> Unlock-SecretStore

cmdlet Unlock-SecretStore at command pipeline position 1
Supply values for the following parameters:
SecureStringPassword: *******

PS C:\> Get-Secret secret1 -Vault LocalStore
System.Security.SecureString
```

In this example, the SecretManagement 'Get-Secret' command fails to retrieve secret1 because the SecretStore vault is locked.
The 'Unlock-SecretStore' command is run to unlock the vault.
No password parameter argument was provided to the 'Unlock-SecretStore' command, so the user is prompted for the password.
Running 'Get-Secret' again now works and returns the secret as a SecureString object.

## PARAMETERS

### -Password
This parameter takes the password argument as a SecureString object.

```yaml
Type: SecureString
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -PasswordTimeout
This parameter takes a password timeout argument in seconds, and overrides the configuration password timeout value.
The password timeout value remains in effect for the session until changed.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.Security.SecureString
## OUTPUTS

## NOTES

## RELATED LINKS
