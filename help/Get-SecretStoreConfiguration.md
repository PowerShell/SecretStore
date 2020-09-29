---
external help file: Microsoft.PowerShell.SecretStore.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretStore
online version:
schema: 2.0.0
---

# Get-SecretStoreConfiguration

## SYNOPSIS
Returns SecretStore configuration information.

## SYNTAX

```
Get-SecretStoreConfiguration [<CommonParameters>]
```

## DESCRIPTION
This cmdlet reads the SecretStore configuration file and writes configuration information to the pipeline.
Configuration information includes:

- Scope

- Authentication

- PasswordTimeout (in seconds)

- Interaction

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-SecretStoreConfiguration

      Scope Authentication PasswordTimeout Interaction
      ----- -------------- --------------- -----------
CurrentUser       Password             900      Prompt
```

This example runs the command from a command shell prompt and displays four SecretStore configuration properties:  
Scope : 'CurrentUser'.  
Authentication : A password is required to access the SecretStore.  
PasswordTimeout : The session password timeout time is 15 minutes.  
Interaction : The user will be prompted for a password if the command is run in an interactive session.  

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

## OUTPUTS

### Microsoft.PowerShell.SecretStore.SecureStoreConfig

## NOTES

'AllUsers' scope is currently not supported.  Configuration scope is always 'CurrentUser'.

## RELATED LINKS
