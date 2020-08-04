---
external help file: Microsoft.PowerShell.SecretStore.dll-Help.xml
Module Name: Microsoft.PowerShell.SecretStore
online version:
schema: 2.0.0
---

# Unlock-SecretStore

## SYNOPSIS
{{ Fill in the Synopsis }}

## SYNTAX

### SecureStringParameterSet (Default)
```
Unlock-SecretStore -SecureStringPassword <SecureString> [-PasswordTimeout <Int32>] [<CommonParameters>]
```

### StringParameterSet
```
Unlock-SecretStore [-Password <String>] [-PasswordTimeout <Int32>] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -Password
{{ Fill Password Description }}

```yaml
Type: String
Parameter Sets: StringParameterSet
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PasswordTimeout
{{ Fill PasswordTimeout Description }}

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

### -SecureStringPassword
{{ Fill SecureStringPassword Description }}

```yaml
Type: SecureString
Parameter Sets: SecureStringParameterSet
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.Security.SecureString

## OUTPUTS

### System.Object
## NOTES

## RELATED LINKS
