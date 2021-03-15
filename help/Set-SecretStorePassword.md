---
external help file: Microsoft.PowerShell.SecretStore.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretStore
online version:
schema: 2.0.0
---

# Set-SecretStorePassword

## SYNOPSIS
Replaces the current SecretStore password with a new one.

## SYNTAX

### NoParameterSet (Default)
```
Set-SecretStorePassword [<CommonParameters>]
```

### ParameterSet
```
Set-SecretStorePassword -NewPassword <SecureString> [-Password <SecureString>] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet updates the password for SecretStore.
It takes no parameters and prompts the user for both the old and new passwords.

## EXAMPLES

### Example 1
```
PS C:\> Set-SecretStorePassword
Old password
Enter password:
*******
New password
Enter password:
*******
Enter password again for verification:
*******
```

This example runs the command with no parameter arguments.
The user is first prompted for the old password.
And then prompted for the new password twice for verification.

### Example 2
```
PS C:\> Set-SecretStorePassword -NewPassword $newPassword -Password $oldPassword
```

This example runs the command passing in both the current store password and the new password to be set.

## PARAMETERS

### -NewPassword
New password to be applied to the store.

```yaml
Type: SecureString
Parameter Sets: ParameterSet
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Password
Existing password needed to unlock the store.
This can be ignored if the store doesn't currently use a password.

```yaml
Type: SecureString
Parameter Sets: ParameterSet
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

### None
## OUTPUTS

## NOTES

## RELATED LINKS
