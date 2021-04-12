<#
.Synopsis
    Used as When to Call Install Complete custom script for SetupEx.ps1
 .NOTES
    Created:   	    April, 2021
    Created by:	    Phil Helmling, @philhelmling
    Organization:   VMware, Inc.
    Filename:       Command to run script: powershell.exe -ep bypass -file .\TestInstalled.ps1 -Version 2801
    GitHub:         https://github.com/helmlingp/apps_SharedDeviceModule
    Used to read registry stamp of Shared Device Module version installed. Return exitcode 0 if same as level specified or exitcode 1 if not.
    
    Used in conjunction with SetupEx.ps1 in same repo for When to Call Install Complete logic
    When to Call Install Complete:
    Identify Application By: Using Custom Script
    Script Type: Powershell
    Command to run script: powershell.exe -ep bypass -file .\TestInstalled.ps1 -Version 2801
    Success Exit Code: 0

.EXAMPLE
    Test if version 2801 of Shared Device Module is installed 
    powershell.exe -ep bypass -file .\TestInstalled.ps1 -Version 2801
#>
param (
    [Parameter(Mandatory=$true)]
    [string]$Version=$script:Version
)

$ec = 1
$SharedIVersion = Get-ItemProperty "HKLM:\Software\AirWatch\ProductProvisioning" | Select -ExpandProperty "SharedIVersion"
if ($SharedIVersion -eq $version) {
  $ec = 0
} else {
  $ec = 1
}

exit $ec