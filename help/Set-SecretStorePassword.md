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

```
Set-SecretStorePassword [<CommonParameters>]
```

## DESCRIPTION
This cmdlet updates the password for SecretStore.
It takes no parameters and prompts the user for both the old and new passwords.

## EXAMPLES

### Example 1
```powershell
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

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

## OUTPUTS

## NOTES

## RELATED LINKS
