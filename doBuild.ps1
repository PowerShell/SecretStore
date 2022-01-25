# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

<#
.DESCRIPTION
Implement build and packaging of the package and place the output $OutDirectory/$ModuleName
#>
function DoBuild
{
    Write-Verbose -Verbose -Message "Starting DoBuild with configuration: $BuildConfiguration, framework: $BuildFramework"

    # Module build out path
    $BuildOutPath = "${OutDirectory}/${ModuleName}"
    Write-Verbose -Verbose -Message "Module output file path: '$BuildOutPath'"

    # Module build source path
    $BuildSrcPath = "bin/${BuildConfiguration}/${BuildFramework}/publish"
    Write-Verbose -Verbose -Message "Module build source path: '$BuildSrcPath'"

    # Copy psd1 file
    Write-Verbose -Verbose "Copy-Item ${SrcPath}/${ModuleName}.psd1 to ${OutDirectory}/${ModuleName}"
    Copy-Item "${SrcPath}/${ModuleName}.psd1" "${OutDirectory}/${ModuleName}"

    # Copy vault extension module files here
    Write-Verbose -Verbose "Copy-Item ${ExtensionModulePath} to ${OutDirectory}/${ModuleName}"
    Copy-Item "${ExtensionModulePath}" "${OutDirectory}/${ModuleName}" -Recurse

    # Copy help
    Write-Verbose -Verbose -Message "Copying help files to '$BuildOutPath'"
    copy-item -Recurse "${HelpPath}/${Culture}" "$BuildOutPath"

    # Copy license
    Write-Verbose -Verbose -Message "Copying LICENSE file to '$BuildOutPath'"
    Copy-Item -Path "./LICENSE" -Dest "$BuildOutPath"

    # Copy notice
    Write-Verbose -Verbose -Message "Copying ThirdPartyNotices.txt to '$BuildOutPath'"
    Copy-Item -Path "./ThirdPartyNotices.txt" -Dest "$BuildOutPath"

    if ( Test-Path "${SrcPath}/code" ) {
        Write-Verbose -Verbose -Message "Building assembly and copying to '$BuildOutPath'"
        # build code and place it in the staging location
        Push-Location "${SrcPath}/code"
        try {
            # Build source
            Write-Verbose -Verbose -Message "Building with configuration: $BuildConfiguration, framework: $BuildFramework"
            Write-Verbose -Verbose -Message "Building location: PSScriptRoot: $PSScriptRoot, PWD: $pwd"
            dotnet publish --configuration $BuildConfiguration --framework $BuildFramework --output $BuildSrcPath

            # Place build results
            if (! (Test-Path -Path "$BuildSrcPath/${ModuleName}.dll"))
            {
                throw "Expected binary was not created: $BuildSrcPath/${ModuleName}.dll"
            }

            Write-Verbose -Verbose -Message "Copying $BuildSrcPath/${ModuleName}.dll to $BuildOutPath"
            Copy-Item -Path "$BuildSrcPath/${ModuleName}.dll" -Dest "$BuildOutPath"
            
            if (Test-Path -Path "$BuildSrcPath/${ModuleName}.pdb")
            {
                Write-Verbose -Verbose -Message "Copying $BuildSrcPath/${ModuleName}.pdb to $BuildOutPath"
                Copy-Item -Path "$BuildSrcPath/${ModuleName}.pdb" -Dest "$BuildOutPath"
            }

            Write-Verbose -Verbose "$BuildSrcPath/System.IO.FileSystem.AccessControl.dll to $BuildOutPath"
            Copy-Item -Path "$BuildSrcPath/System.IO.FileSystem.AccessControl.dll" -Dest "$BuildOutPath"

            Write-Verbose -Verbose "$BuildSrcPath/System.Runtime.InteropServices.RuntimeInformation.dll to $BuildOutPath"
            Copy-Item -Path "$BuildSrcPath/System.Runtime.InteropServices.RuntimeInformation.dll" -Dest "$BuildOutPath"
        }
        catch {
            # Write-Error "dotnet build failed with error: $_"
            Write-Verbose -Verbose -Message "dotnet build failed with error: $_"
        }
        finally {
            Pop-Location
        }
    }
    else {
        Write-Verbose -Verbose -Message "No code to build in '${SrcPath}/code'"
    }

    ## Add build and packaging here
    Write-Verbose -Verbose -Message "Ending DoBuild"
}
