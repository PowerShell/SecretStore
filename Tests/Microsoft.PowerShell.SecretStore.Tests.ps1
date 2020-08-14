# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

Describe "Test Microsoft.PowerShell.SecretStore module" -tags CI {

    BeforeAll {

        if ((Get-Module -Name Microsoft.PowerShell.SecretManagement -ErrorAction Ignore) -eq $null)
        {
            Import-Module -Name Microsoft.PowerShell.SecretManagement
        }

        if ((Get-Module -Name Microsoft.PowerShell.SecretStore -ErrorAction Ignore) -eq $null)
        {
            Import-Module -Name ..\Microsoft.PowerShell.SecretStore.psd1
        }

        <#
        $choices = @(
            [System.Management.Automation.Host.ChoiceDescription]::new('Yes'),
            [System.Management.Automation.Host.ChoiceDescription]::new('No'))
        $choice = $host.UI.PromptForChoice(
            "!!! These tests will remove all secrets in the store for the current user !!!",
            "Type 'Yes' to continue",
            $choices,
            1)
        if ($choice -eq 1)
        {
            # User choosed not to run tests
            throw 'Tests aborted'
        }
        #>

        # Reset the SecretStore and configure it for no-password access
        # This deletes all SecretStore data!!
        Write-Warning "!!! These tests will remove all secrets in the store for the current user !!!"
        Reset-SecretStore -Scope CurrentUser -PasswordRequired:$false -PasswordTimeout: -1 -DoNotPrompt -Force
    }

    Context "SecretStore file permission tests" {

        BeforeAll {
            Get-SecretInfo

            if ($IsWindows)
            {
                $storePath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::LocalApplicationData)
                $storePath = Join-Path -Path $storePath -ChildPath 'Microsoft\PowerShell\secretmanagement\localstore'
                $storeConfigFilePath = Join-Path -Path $storePath -ChildPath 'storeconfig'
                $storeFilePath = Join-Path -Path $storePath -ChildPath 'storefile'
                $storeKeyFilePath = Join-Path -Path $storePath -ChildPath 'storeaux'
            }
            else
            {
                $storePath = Join-Path -Path "$home" -ChildPath '.secretmanagement/localstore'
                $storeConfigFilePath = Join-Path -Path $storePath -ChildPath 'storeconfig'
                $storeFilePath = Join-Path -Path $storePath -ChildPath 'storefile'
                $storeKeyFilePath = Join-Path -Path $storePath -ChildPath 'storeaux'
            }
        }

        if ($IsWindows)
        {
            It "Verifies SecretStore directory ACLs" {
                $acl = Get-Acl $storePath
                $acl.Access | Should -HaveCount 1
                $accessRule = $acl.Access[0]

                $accessRule.FileSystemRights | Should -BeExactly 'FullControl'
                $accessRule.AccessControlType | Should -BeExactly 'Allow'
                $accessRule.IdentityReference | Should -BeExactly ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
                $accessRule.IsInherited | Should -BeFalse
                $accessRule.InheritanceFlags | Should -BeExactly 'ContainerInherit, ObjectInherit'
                $accessRule.PropagationFlags | Should -BeExactly 'None'
            }

            It "Verifies SecretStore configuration file ACLs" {
                $acl = Get-Acl $storeConfigFilePath
                $acl.Access | Should -HaveCount 1
                $accessRule = $acl.Access[0]

                $accessRule.FileSystemRights | Should -BeExactly 'FullControl'
                $accessRule.AccessControlType | Should -BeExactly 'Allow'
                $accessRule.IdentityReference | Should -BeExactly ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
                $accessRule.IsInherited | Should -BeTrue
                $accessRule.InheritanceFlags | Should -BeExactly 'None'
                $accessRule.PropagationFlags | Should -BeExactly 'None'
            }

            It "Verifies SecretStore file ACLs" {
                $acl = Get-Acl $storeFilePath
                $acl.Access | Should -HaveCount 1
                $accessRule = $acl.Access[0]

                $accessRule.FileSystemRights | Should -BeExactly 'FullControl'
                $accessRule.AccessControlType | Should -BeExactly 'Allow'
                $accessRule.IdentityReference | Should -BeExactly ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
                $accessRule.IsInherited | Should -BeTrue
                $accessRule.InheritanceFlags | Should -BeExactly 'None'
                $accessRule.PropagationFlags | Should -BeExactly 'None'
            }

            It "Verifies SecretStore key file ACLs" {
                $acl = Get-Acl $storeKeyFilePath
                $acl.Access | Should -HaveCount 1
                $accessRule = $acl.Access[0]

                $accessRule.FileSystemRights | Should -BeExactly 'FullControl'
                $accessRule.AccessControlType | Should -BeExactly 'Allow'
                $accessRule.IdentityReference | Should -BeExactly ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
                $accessRule.IsInherited | Should -BeTrue
                $accessRule.InheritanceFlags | Should -BeExactly 'None'
                $accessRule.PropagationFlags | Should -BeExactly 'None'
            }
        }
        else
        {
            # drwx------ 2 <user> <user> 4096 Jun 30 16:03 <path>
            $userName = [System.Environment]::GetEnvironmentVariable("USER")

            It "Verifies SecretStore directory permissions" {
                $permissions = (ls -ld "$storePath").Split(' ')
                $permissions[0] | Should -BeExactly 'drwx------'
                $permissions[2] | Should -BeExactly $userName
                $permissions[3] | Should -BeExactly $userName
            }

            It "Verfies SecretStore configuration file permissions" {
                $permissions = (ls -ld "$storeConfigFilePath").Split(' ')
                $permissions[0] | Should -BeExactly '-rw-------'
                $permissions[2] | Should -BeExactly $userName
                $permissions[3] | Should -BeExactly $userName
            }

            It "Verifes SecretStore file permissions" {
                $permissions = (ls -ld "$storeFilePath").Split(' ')
                $permissions[0] | Should -BeExactly '-rw-------'
                $permissions[2] | Should -BeExactly $userName
                $permissions[3] | Should -BeExactly $userName
            }

            It "Verifes SecretStore key file permissions" {
                $permissions = (ls -ld "$storeKeyFilePath").Split(' ')
                $permissions[0] | Should -BeExactly '-rw-------'
                $permissions[2] | Should -BeExactly $userName
                $permissions[3] | Should -BeExactly $userName
            }
        }
    }

    Context "SecretStore Vault cmdlet tests" {

        It "Verifies SecretStore configuration for tests" {
            $config = Get-SecretStoreConfiguration
            $config.Scope | Should -BeExactly "CurrentUser"
            $config.PasswordRequired | Should -BeFalse
            $config.PasswordTimeout | Should -Be -1
            $config.DoNotPrompt | Should -BeTrue
        }

        It "Verifies SecretStore AllUsers option is not implement" {
            { Set-SecretStoreConfiguration -Scope AllUsers } | Should -Throw -ErrorId 'SecretStoreConfigurationNotSupported,Microsoft.PowerShell.SecretStore.SetSecretStoreConfiguration'
        }

        It "Verifies Unlock-SecretStore throws expected error when in no password mode" {
            { Unlock-SecretStore -Password None } | Should -Throw -ErrorId 'InvalidOperation,Microsoft.PowerShell.SecretStore.UnlockSecretStoreCommand'
        }
    }

    Context "SecretStore Vault Byte[] type" {

        $secretName = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName())
        $bytesToWrite = [System.Text.Encoding]::UTF8.GetBytes("TestBytesStringToTest")
        $errorMsg = ""

        It "Verifies byte[] write to SecretStore" {
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().WriteObject(
                $secretName,
                $bytesToWrite,
                [ref] $errorMsg)

            $success | Should -BeTrue
            $errorMsg | Should -Be ""
        }

        It "Verifes byte[] read from SecretStore" {
            $outBytes = $null;
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().ReadObject(
                $secretName,
                [ref] $outBytes,
                [ref] $errorMsg)
            
            $success | Should -BeTrue
            $errorMsg | Should -Be ""
            [System.Text.Encoding]::UTF8.GetString($outBytes) | Should -BeExactly "TestBytesStringToTest"
        }

        It "Verifies byte[] enumeration from SecretStore" {
            $outInfo = $null
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().EnumerateObjectInfo(
                $secretName,
                [ref] $outInfo,
                "MyVault",
                [ref] $errorMsg)
            
            $success | Should -BeTrue
            $errorMsg | Should -Be ""
            $outInfo.Name | Should -BeExactly $secretName
            $outInfo.Type | Should -BeExactly "ByteArray"
            $outInfo.VaultName | Should -BeExactly "MyVault"
        }

        It "Verifies Remove byte[] secret" {
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().DeleteObject(
                $secretName,
                [ref] $errorMsg)
            $success | Should -BeTrue
            $errorMsg | Should -Be "" 

            $outBytes = $null
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().ReadObject(
                $secretName,
                [ref] $outBytes,
                [ref] $errorMsg)
            $success | Should -BeFalse -Because "Secret has been removed."
        }
    }

    Context "SecretStore Vault String type" {

        $secretName = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName())
        $stringToWrite = "TestStoreString"
        $errorMsg = ""

        It "Verifes String write to SecretStore" {
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().WriteObject(
                $secretName,
                $stringToWrite,
                [ref] $errorMsg)

            $success | Should -BeTrue
            $errorMsg | Should -Be ""
        }

        It "Verifies String read from SecretStore" {
            $outString = $null;
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().ReadObject(
                $secretName,
                [ref] $outString,
                [ref] $errorMsg)
            
            $success | Should -BeTrue
            $errorMsg | Should -Be ""
            $outString | Should -BeExactly $stringToWrite
        }

        It "Verifies String enumeration from SecretStore" {
            $outInfo = $null
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().EnumerateObjectInfo(
                $secretName,
                [ref] $outInfo,
                "MyVault",
                [ref] $errorMsg)
            
            $success | Should -BeTrue
            $errorMsg | Should -Be ""
            $outInfo.Name | Should -BeExactly $secretName
            $outInfo.Type | Should -BeExactly "String"
            $outInfo.VaultName | Should -BeExactly "MyVault"
        }

        It "Verifies String remove from SecretStore" {
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().DeleteObject(
                $secretName,
                [ref] $errorMsg)
            $success | Should -BeTrue
            $errorMsg | Should -Be "" 

            $outString = $null
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().ReadObject(
                $secretName,
                [ref] $outString,
                [ref] $errorMsg)
            $success | Should -BeFalse -Because "Secret has been removed."
        }
    }

    Context "SecretStore Vault SecureString type" {

        $secretName = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName())
        $randomSecret = [System.IO.Path]::GetRandomFileName()
        $secureStringToWrite = ConvertTo-SecureString -String $randomSecret -AsPlainText -Force
        $errorMsg = ""

        It "Verifies SecureString write to SecretStore" {
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().WriteObject(
                $secretName,
                $secureStringToWrite,
                [ref] $errorMsg)

            $success | Should -BeTrue
            $errorMsg | Should -Be ""
        }

        It "Verifies SecureString read from SecretStore" {
            $outSecureString = $null;
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().ReadObject(
                $secretName,
                [ref] $outSecureString,
                [ref] $errorMsg)
            
            $success | Should -BeTrue
            $errorMsg | Should -Be ""
            $outString | Should -BeExactly $stringToWrite
            [System.Net.NetworkCredential]::new('',$outSecureString).Password | Should -BeExactly $randomSecret
        }

        It "Verifies SecureString enumeration from SecretStore" {
            $outInfo = $null
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().EnumerateObjectInfo(
                $secretName,
                [ref] $outInfo,
                "MyVault",
                [ref] $errorMsg)
            
            $success | Should -BeTrue
            $errorMsg | Should -Be ""
            $outInfo.Name | Should -BeExactly $secretName
            $outInfo.Type | Should -BeExactly "SecureString"
            $outInfo.VaultName | Should -BeExactly "MyVault"
        }

        It "Verifies SecureString remove from SecretStore" {
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().DeleteObject(
                $secretName,
                [ref] $errorMsg)
            $success | Should -BeTrue
            $errorMsg | Should -Be "" 

            $outSecureString = $null
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().ReadObject(
                $secretName,
                [ref] $outSecureString,
                [ref] $errorMsg)
            $success | Should -BeFalse -Because "Secret has been removed."
        }
    }

    Context "SecretStore Vault PSCredential type" {

        $secretName = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName())
        $randomSecret = [System.IO.Path]::GetRandomFileName()
        $errorMsg = ""

        It "Verifies PSCredential type write to SecretStore" {
            $cred = [pscredential]::new('UserL', (ConvertTo-SecureString $randomSecret -AsPlainText -Force))
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().WriteObject(
                $secretName,
                $cred,
                [ref] $errorMsg)

            $success | Should -BeTrue
            $errorMsg | Should -Be ""
        }

        It "Verifies PSCredential read from SecretStore" {
            $outCred = $null;
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().ReadObject(
                $secretName,
                [ref] $outCred,
                [ref] $errorMsg)
            
            $success | Should -BeTrue
            $errorMsg | Should -Be ""
            $outString | Should -BeExactly $stringToWrite
            $outCred.UserName | Should -BeExactly "UserL"
            [System.Net.NetworkCredential]::new('', ($outCred.Password)).Password | Should -BeExactly $randomSecret
        }

        It "Verifies PSCredential enumeration from SecretStore" {
            $outInfo = $null
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().EnumerateObjectInfo(
                $secretName,
                [ref] $outInfo,
                "MyVault",
                [ref] $errorMsg)
            
            $success | Should -BeTrue
            $errorMsg | Should -Be ""
            $outInfo.Name | Should -BeExactly $secretName
            $outInfo.Type | Should -BeExactly "PSCredential"
            $outInfo.VaultName | Should -BeExactly "MyVault"
        }

        It "Verifies PSCredential remove from SecretStore" {
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().DeleteObject(
                $secretName,
                [ref] $errorMsg)
            $success | Should -BeTrue
            $errorMsg | Should -Be "" 

            $outCred = $null
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().ReadObject(
                $secretName,
                [ref] $outCred,
                [ref] $errorMsg)
            $success | Should -BeFalse -Because "Secret has been removed."
        }
    }

    Context "SecretStore Vault Hashtable type" {

        $secretName = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName())
        $randomSecretA = [System.IO.Path]::GetRandomFileName()
        $randomSecretB = [System.IO.Path]::GetRandomFileName()
        $errorMsg = ""

        It "Verifies Hashtable type write to SecretStore" {
            $ht = @{
                Blob = ([byte[]] @(1,2))
                Str = "TestHashtableString"
                SecureString = (ConvertTo-SecureString $randomSecretA -AsPlainText -Force)
                Cred = ([pscredential]::New("UserA", (ConvertTo-SecureString $randomSecretB -AsPlainText -Force)))
            }

            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().WriteObject(
                $secretName,
                $ht,
                [ref] $errorMsg)

            $success | Should -BeTrue
            $errorMsg | Should -Be ""
        }

        It "Verifies Hashtable read from SecretStore" {
            $outHT = $null;
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().ReadObject(
                $secretName,
                [ref] $outHT,
                [ref] $errorMsg)
            
            $success | Should -BeTrue
            $errorMsg | Should -Be ""
            $outHT.Blob.Count | Should -Be 2
            $outHT.Str | Should -BeExactly "TestHashtableString"
            [System.Net.NetworkCredential]::new('', ($outHT.SecureString)).Password | Should -BeExactly $randomSecretA
            $outHT.Cred.UserName | Should -BeExactly "UserA"
            [System.Net.NetworkCredential]::New('', ($outHT.Cred.Password)).Password | Should -BeExactly $randomSecretB
        }

        It "Verifies Hashtable enumeration from SecretStore" {
            $outInfo = $null
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().EnumerateObjectInfo(
                $secretName,
                [ref] $outInfo,
                "MyVault",
                [ref] $errorMsg)
            
            $success | Should -BeTrue
            $errorMsg | Should -Be ""
            $outInfo.Name | Should -BeExactly $secretName
            $outInfo.Type | Should -BeExactly "Hashtable"
            $outInfo.VaultName | Should -BeExactly "MyVault"
        }

        It "Verifies Hashtable remove from SecretStore" {
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().DeleteObject(
                $secretName,
                [ref] $errorMsg)
            $success | Should -BeTrue
            $errorMsg | Should -Be "" 

            $outHT = $null
            $success = [Microsoft.PowerShell.SecretStore.LocalSecretStore]::GetInstance().ReadObject(
                $secretName,
                [ref] $outHT,
                [ref] $errorMsg)
            $success | Should -BeFalse -Because "Secret has been removed."
        }
    }
}
