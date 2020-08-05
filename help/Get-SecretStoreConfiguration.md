---
external help file: Microsoft.PowerShell.SecretStore.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretStore
online version:
schema: 2.0.0
---

# Get-SecretStoreConfiguration

## SYNOPSIS
Writes SecretStore configuration information.

## SYNTAX

```
Get-SecretStoreConfiguration [<CommonParameters>]
```

## DESCRIPTION
This cmdlet reads the SecretStore configuration file and writes configuration information to the pipeline.
Configuration information includes:

- Scope

- PasswordRequired

- PasswordTimeout (in seconds)

- DoNotPrompt

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-SecretStoreConfiguration

      Scope PasswordRequired PasswordTimeout DoNotPrompt
      ----- ---------------- --------------- -----------
CurrentUser             True             300       False

PS C:\>
```

This example runs the command from a command shell prompt and displays four SecretStore configuration properties:  
Scope is 'CurrentUser'.  
A password is required to access the SecretStore.  
A session password timeout time is 5 minutes.  
The user will be prompted for a password if the command is run in an interactive session.

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

## OUTPUTS

### Microsoft.PowerShell.SecretStore.SecureStoreConfig

## NOTES

Currently, configuration scope is always 'CurrentUser'.
'AllUsers' scope is not supported.

## RELATED LINKS
