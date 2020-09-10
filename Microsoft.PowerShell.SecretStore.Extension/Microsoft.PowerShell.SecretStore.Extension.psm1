# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function Get-Secret
{
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "")]
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $errorMsg = ""
    $count = 0
    do
    {
        try
        {
            $outSecret = $null
            if ([Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().ReadObject(
                $Name,
                [ref] $outSecret,
                [ref] $errorMsg))
            {
                Write-Output $outSecret -NoEnumerate
            }

            break
        }
        catch [Microsoft.PowerShell.SecretManagement.PasswordRequiredException]
        {
            if (! [Microsoft.PowerShell.SecretStore.LocalSecretStore]::AllowPrompting -or
                ($count -gt 0))
            {
                throw
            }

            [Microsoft.PowerShell.SecretStore.LocalSecretStore]::PromptAndUnlockVault($VaultName, $PSCmdlet)
        }
    } while ($count++ -lt 1)

    if (! [string]::IsNullOrEmpty($errorMsg))
    {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.Management.Automation.PSInvalidOperationException]::new("Get-Secret error in vault $VaultName : $errorMsg"),
            "SecretStoreGetSecretFailed",
            [System.Management.Automation.ErrorCategory]::InvalidOperation,
            $null)
        Write-Error -ErrorRecord $errorRecord
    }
}

function Get-SecretInfo
{
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "")]
    [CmdletBinding()]
    param (
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $errorMsg = ""
    $count = 0
    do
    {
        try
        {
            $outSecretInfo = $null
            if ([Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().EnumerateObjectInfo(
                $Filter,
                [ref] $outSecretInfo,
                $VaultName,
                [ref] $errorMsg))
            {
                Write-Output $outSecretInfo
            }
            
            break
        }
        catch [Microsoft.PowerShell.SecretManagement.PasswordRequiredException]
        {
            if (! [Microsoft.PowerShell.SecretStore.LocalSecretStore]::AllowPrompting -or
                ($count -gt 0))
            {
                throw
            }

            [Microsoft.PowerShell.SecretStore.LocalSecretStore]::PromptAndUnlockVault($VaultName, $PSCmdlet)
        }
    } while ($count++ -lt 1)

    if (! [string]::IsNullOrEmpty($errorMsg))
    {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.Management.Automation.ItemNotFoundException]::new("Get-SecretInfo error in vault $VaultName : $errorMsg"),
            "SecretStoreGetSecretInfoFailed",
            [System.Management.Automation.ErrorCategory]::InvalidOperation,
            $null)
        Write-Error -ErrorRecord $errorRecord
    }
}

function Set-Secret
{
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "")]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    [CmdletBinding()]
    param (
        [string] $Name,
        [object] $Secret,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $errorMsg = ""
    $count = 0
    do
    {
        try
        {
            if ([Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().WriteObject(
                $Name,
                $Secret,
                [ref] $errorMsg))
            {
                return
            }
        }
        catch [Microsoft.PowerShell.SecretManagement.PasswordRequiredException]
        {
            if (! [Microsoft.PowerShell.SecretStore.LocalSecretStore]::AllowPrompting -or
                ($count -gt 0))
            {
                throw
            }

            [Microsoft.PowerShell.SecretStore.LocalSecretStore]::PromptAndUnlockVault($VaultName, $PSCmdlet)
        }
    } while ($count++ -lt 1)

    if (! [string]::IsNullOrEmpty($errorMsg))
    {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.Management.Automation.ItemNotFoundException]::new("Set-Secret error in vault $VaultName : $errorMsg"),
            "SecretStoreSetSecretFailed",
            [System.Management.Automation.ErrorCategory]::InvalidOperation,
            $null)
        Write-Error -ErrorRecord $errorRecord
    }
}

function Remove-Secret
{
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "")]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $errorMsg = ""
    $count = 0
    do
    {
        try
        {
            if ([Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().DeleteObject(
                $Name,
                [ref] $errorMsg))
            {
                return
            }
        }
        catch [Microsoft.PowerShell.SecretManagement.PasswordRequiredException]
        {
            if (! [Microsoft.PowerShell.SecretStore.LocalSecretStore]::AllowPrompting -or
                ($count -gt 0))
            {
                throw
            }

            [Microsoft.PowerShell.SecretStore.LocalSecretStore]::PromptAndUnlockVault($VaultName, $PSCmdlet)
        }
    } while ($count++ -lt 1)

    if (! [string]::IsNullOrEmpty($errorMsg))
    {
        $Msg = "Remove-Secret error in vault $VaultName : $errorMsg"
    }
    else
    {
        $Msg = "Remove-Secret error in vault $VaultName : Secret not found"
    }

    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
        [System.Management.Automation.ItemNotFoundException]::new($Msg),
        "SecretStoreRemoveSecretFailed",
        [System.Management.Automation.ErrorCategory]::InvalidOperation,
        $null)
    Write-Error -ErrorRecord $errorRecord
}

function Test-SecretVault
{
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "")]
    [CmdletBinding()]
    param (
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $secretName = [System.IO.Path]::GetRandomFileName()
    $secret = [System.IO.Path]::GetRandomFileName()

    # Setting a secret
    $errorMsg = ""
    $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().WriteObject(
        $secretName,
        $secret,
        [ref] $errorMsg)
    if (! $success)
    {
        Write-Error -Message "Test-SecretVault failed to write secret on vault $VaultName with error: $errorMsg"
        return $success
    }

    # Getting secret info
    $errorMsg = ""
    $result = $null
    $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().EnumerateObjectInfo(
        $secretName,
        [ref] $result,
        $VaultName,
        [ref] $errorMsg)
    if (! $success)
    {
        Write-Error -Message "Test-SecretVault failed to get secret information on vault $VaultName with error: $errorMsg"
    }

    # Getting secret value
    $errorMsg = ""
    $result = $null
    $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().ReadObject(
        $secretName,
        [ref] $result,
        [ref] $errorMsg)
    if (! $success)
    {
        Write-Error -Message "Test-SecretVault failed to get secret on vault $VaultName with error: $errorMsg"
    }

    # Removing secret
    $errorMsg = ""
    $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().DeleteObject(
        $secretName,
        [ref] $errorMsg)
    if (! $success)
    {
        Write-Error -Message "Test-SecretVault failed to remove secret on vault $VaultName with error: $errorMsg"
    }

    return $success
}
