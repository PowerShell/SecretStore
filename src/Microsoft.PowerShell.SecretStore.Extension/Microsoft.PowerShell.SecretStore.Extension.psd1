@{
    ModuleVersion = '1.0'
    GUID = 'b8977c8d-309d-4732-ba29-6233fdd6278b'
    Author = 'Microsoft Corporation'
    CompanyName = 'Microsoft Corporation'
    Copyright = '(c) Microsoft Corporation. All rights reserved.'
    Description = 'Extension vault submodule for SecretStore.'
    PowerShellVersion = '5.1'
    DotNetFrameworkVersion = '4.6.1'
    CLRVersion = '4.0.0'    
    RootModule = 'Microsoft.PowerShell.SecretStore.Extension.psm1'
    RequiredAssemblies = '../Microsoft.PowerShell.SecretStore.dll'
    FunctionsToExport = @('Set-Secret','Set-SecretInfo','Get-Secret','Remove-Secret','Get-SecretInfo','Unlock-SecretVault','Test-SecretVault')
    PrivateData = @{ PSData = @{ ProjectUri = 'https://github.com/powershell/secretstore' } }
}
