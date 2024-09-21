# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug"
)

#Requires -Modules @{ ModuleName = "InvokeBuild"; ModuleVersion = "5.0.0" }

task FindDotNet -Before Clean, Build {
    Assert (Get-Command dotnet -ErrorAction SilentlyContinue) "The dotnet CLI was not found, please install it: https://aka.ms/dotnet-cli"
    $DotnetVersion = dotnet --version
    Assert ($?) "The required .NET SDK was not found, please install it: https://aka.ms/dotnet-cli"
    Write-Host "Using dotnet $DotnetVersion at path $((Get-Command dotnet).Source)" -ForegroundColor Green
}

task Clean {
    Remove-BuildItem ./artifacts, ./module, ./out
    Invoke-BuildExec { dotnet clean ./src/code }
}

task BuildDocs -If { Test-Path -LiteralPath ./help } {
    New-ExternalHelp -Path ./help -OutputPath ./module/en-US
}

task BuildModule {
    New-Item -ItemType Directory -Force ./module | Out-Null

    Invoke-BuildExec { dotnet publish ./src/code -c $Configuration }

    $FullModuleName = "Microsoft.PowerShell.SecretStore"

    $CSharpArtifacts = @(
        "$FullModuleName.dll",
        "$FullModuleName.pdb",
        "System.IO.FileSystem.AccessControl.dll",
        "System.Runtime.InteropServices.RuntimeInformation.dll")

    $CSharpArtifacts | ForEach-Object {
        $item = "./artifacts/publish/$FullModuleName/$($Configuration.ToLower())/$_"
        Copy-Item -Force -LiteralPath $item -Destination ./module
    }

    $BaseArtifacts = @(
        "README.md",
        "LICENSE",
        "ThirdPartyNotices.txt")

    $BaseArtifacts | ForEach-Object {
        $itemToCopy = Join-Path $PSScriptRoot $_
        Copy-Item -Force -LiteralPath $itemToCopy -Destination ./module
    }

    Copy-Item -Force -Recurse "./src/$FullModuleName.Extension/" -Destination ./module

    [xml]$xml = Get-Content Directory.Build.props
    $moduleVersion = $xml.Project.PropertyGroup.ModuleVersion
    $manifestContent = Get-Content -LiteralPath "./src/$FullModuleName.psd1" -Raw
    $newManifestContent = $manifestContent -replace '{{ModuleVersion}}', $moduleVersion
    Set-Content -LiteralPath "./module/$FullModuleName.psd1" -Encoding utf8 -Value $newManifestContent
}

task Package {
    New-Item -ItemType Directory -Force ./out | Out-Null

    try {
        Register-PSResourceRepository -Name SecretStore -Uri ./out -ErrorAction Stop
        Publish-PSResource -Path ./module -Repository SecretStore -SkipDependenciesCheck -Verbose
    } finally {
        Unregister-PSResourceRepository -Name SecretStore
    }
}

task Test {
    Invoke-Pester -CI -Output Diagnostic
}

task Build BuildModule, BuildDocs

task . Clean, Build
