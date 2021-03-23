# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{

# Script module or binary module file associated with this manifest.
RootModule = '.\Microsoft.PowerShell.SecretStore.dll'

NestedModules = @('.\Microsoft.PowerShell.SecretStore.Extension')

RequiredModules = @('Microsoft.PowerShell.SecretManagement')

# Version number of this module.
ModuleVersion = '0.9.2'

# Supported PSEditions
CompatiblePSEditions = @('Core')

# ID used to uniquely identify this module
GUID = '6b983e67-c297-431a-916c-f4ce24dd7bac'

# Author of this module
Author = 'Microsoft Corporation'

# Company or vendor of this module
CompanyName = 'Microsoft Corporation'

# Copyright statement for this module
Copyright = '(c) Microsoft Corporation. All rights reserved.'

# Description of the functionality provided by this module
Description = "
This PowerShell module is an extension vault for the PowerShell SecretManagement module.
As an extension vault, this module stores secrets to the local machine based on the current user
account context. The secrets are encrypted on file using .NET Crypto APIs. A password is required
in the default configuration. The configuration can be changed with the provided cmdlets.

Go to GitHub for more information about this module and to submit issues:
https://github.com/powershell/SecretStore
"

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '5.1'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @('Unlock-SecretStore','Set-SecretStorePassword','Get-SecretStoreConfiguration','Set-SecretStoreConfiguration','Reset-SecretStore')

FunctionsToExport = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('SecretManagement')

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/PowerShell/SecretStore/blob/master/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/powershell/secretstore'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        # ExternalModuleDependencies = @()
    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
HelpInfoURI = 'https://aka.ms/ps-modules-help'

}
