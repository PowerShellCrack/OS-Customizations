<#
	.SYNOPSIS
        Remove built-in apps (modern apps) from Windows 10 all Versions

    .DESCRIPTION
		Remove Built-in apps when creating a Windows 10 reference image using a whitelist.
        Utilizes MDT/SCCM TaskSequence property control
            Configurable using custom variables in MDT/SCCM

	.NOTES
	===========================================================================
	 Created with: 	Powershell
	 Created by:   	Richard Tracy
	 Filename:     Invoke-RemoveBuiltinApps.ps1
	===========================================================================

    .INFO
        Author:         Richard Tracy
        Email:          richard.tracy@hotmail.com
        Twitter:        @rick2_1979
        Website:        www.powershellcrack.com
        Last Update:    04/04/2019
        Version:        2.0.0
        Thanks to:      @NickolajA

    .DISCLOSURE
        THE SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
        OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. BY USING OR DISTRIBUTING THIS SCRIPT, YOU AGREE THAT IN NO EVENT
        SHALL RICHARD TRACY OR ANY AFFILATES BE HELD LIABLE FOR ANY DAMAGES WHATSOEVER RESULTING FROM USING OR DISTRIBUTION OF THIS SCRIPT, INCLUDING,
        WITHOUT LIMITATION, ANY SPECIAL, CONSEQUENTIAL, INCIDENTAL OR OTHER DIRECT OR INDIRECT DAMAGES. BACKUP UP ALL DATA BEFORE PROCEEDING.

    .NOTES
        In case you have removed the apps for good, you can try to restore the files using installation ISO as follows
        Insert or mount ISO
        New-Item C:\Mount -Type Directory | Out-Null
        DISM /Mount-Image /ImageFile:D:\sources\install.wim /index:1 /ReadOnly /MountDir:C:\Mount
        robocopy /S /SEC /R:0 "C:\Mount\Program Files\WindowsApps" "C:\Program Files\WindowsApps"
        DISM /Unmount-Image /Discard /MountDir:C:\Mount
        Remove-Item -Path C:\Mount -Recurse

    .CHANGE LOGS
        2.0.1 - Dec 7, 2019 - Added additional info and disclosure
        2.0.0 - Jun 4, 2019  - added progress bar for tasksequence
        1.0.1 - May 30, 2019 - fixed Write-LogEntry
        1.0.0 - May 16, 2018 - initial; forked from

    .LINK
         - https://docs.microsoft.com/en-us/windows/application-management/apps-in-windows-10
         - https://www.scconfigmgr.com/2016/03/01/remove-built-in-apps-when-creating-a-windows-10-reference-image/
         - https://github.com/SCConfigMgr/ConfigMgr/blob/master/Operating%20System%20Deployment/Invoke-RemoveBuiltinApps.ps1

#>



##*===========================================================================
##* FUNCTIONS
##*===========================================================================

#region FUNCTION: Check if running in ISE
Function Test-IsISE {
    # trycatch accounts for:
    # Set-StrictMode -Version latest
    try {
        return ($null -ne $psISE);
    }
    catch {
        return $false;
    }
}
#endregion

#region FUNCTION: Check if running in Visual Studio Code
Function Test-VSCode{
    if($env:TERM_PROGRAM -eq 'vscode') {
        return $true;
    }
    Else{
        return $false;
    }
}
#endregion

#region FUNCTION: Find script path for either ISE or console
Function Get-ScriptPath {
    <#
        .SYNOPSIS
            Finds the current script path even in ISE or VSC
        .LINK
            Test-VSCode
            Test-IsISE
    #>
    param(
        [switch]$Parent
    )

    Begin{}
    Process{
        if ($PSScriptRoot -eq "")
        {
            if (Test-IsISE)
            {
                $ScriptPath = $psISE.CurrentFile.FullPath
            }
            elseif(Test-VSCode){
                $context = $psEditor.GetEditorContext()
                $ScriptPath = $context.CurrentFile.Path
            }Else{
                $ScriptPath = (Get-location).Path
            }
        }
        else
        {
            $ScriptPath = $PSCommandPath
        }
    }
    End{

        If($Parent){
            Split-Path $ScriptPath -Parent
        }Else{
            $ScriptPath
        }
    }

}


##*===========================================================================
##* VARIABLES
##*===========================================================================
# Use function to get paths because Powershell ISE and other editors have differnt results
$scriptPath = Get-ScriptPath
[string]$scriptDirectory = Split-Path $scriptPath -Parent
[string]$scriptName = Split-Path $scriptPath -Leaf
[string]$scriptBaseName = [System.IO.Path]::GetFileNameWithoutExtension($scriptName)

$FunctionPath = Join-Path $scriptDirectory -ChildPath 'Functions'


##*========================================================================
##* Additional Runtime Function - REQUIRED
##*========================================================================
#Load functions from external files
. "$FunctionPath\ApplicationControl.ps1"
. "$FunctionPath\Environment.ps1"
. "$FunctionPath\Logging.ps1"

#build log name
[string]$FileName = $scriptBaseName +'.log'
#build global log fullpath
If(Test-SMSTSENV){
    $Global:LogFilePath = Join-Path (Test-SMSTSENV -ReturnLogPath -Verbose) -ChildPath $FileName
}Else{
    $RelativeLogPath = Join-Path -Path $scriptDirectory -ChildPath 'Logs'
}

Write-Host "Logging to file: $LogFilePath" -ForegroundColor Cyan

##*========================================================================
##* MAIN
##*========================================================================
# Get a list of all apps
Write-LogEntry -Message "Starting built-in AppxPackage and AppxProvisioningPackage removal process..." -Outhost
$AppArrayList = Get-AppxPackage -PackageTypeFilter Bundle -AllUsers | Select-Object -Property Name, PackageFullName | Sort-Object -Property Name

# White list of appx packages to keep installed
$WhiteListedApps = @(
    "Microsoft.DesktopAppInstaller",
    "Microsoft.MSPaint",
    "Microsoft.Windows.Photos",
    "Microsoft.StorePurchaseApp",
    "Microsoft.MicrosoftStickyNotes",
    "Microsoft.WindowsAlarms",
    "Microsoft.WindowsCalculator",
    #"Microsoft.WindowsCommunicationsApps", # Mail, Calendar etc
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.RemoteDesktop",
    "Microsoft.WindowsStore"
)

$p = 1
$c = 0
# Loop through the list of All installed appx packages
foreach ($App in $AppArrayList) {

    # If application name not in appx package white list, remove AppxPackage and AppxProvisioningPackage
    if (($App.Name -in $WhiteListedApps)) {
        $status = "Skipping excluded application package: $($App.Name)"
        Write-LogEntry -Message $status -Outhost
    }
    else {
        # Gather package names
        $AppPackageFullName = Get-AppxPackage -Name $App.Name -AllUsers | Select-Object -ExpandProperty PackageFullName
        $AppProvisioningPackageName = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $App.Name } | Select-Object -ExpandProperty PackageName

        # Attempt to remove AppxPackage
        if ($AppPackageFullName -ne $null) {
            $status = "Removing application package: $($App.Name)"
            Write-LogEntry -Message $status -Outhost
            try {
                Remove-AppxPackage -Package $AppPackageFullName -AllUsers -ErrorAction Stop | Out-Null
                Write-LogEntry -Message "Successfully removed application package: $($App.Name)" -Outhost
                $c++
            }
            catch [System.Exception] {
                Write-LogEntry -Message "Failed removing AppxPackage: $($_.Exception.Message)" -Severity 3 -Outhost
            }
        }
        else {
            Write-LogEntry -Message "Unable to locate AppxPackage for app: $($App.Name)" -Outhost
        }

        # Attempt to remove AppxProvisioningPackage
        if ($null -ne $AppProvisioningPackageName) {
            Write-LogEntry -Message "Removing application provisioning package: $($AppProvisioningPackageName)"
            try {
                Remove-AppxProvisionedPackage -PackageName $AppProvisioningPackageName -Online -ErrorAction Stop | Out-Null
                Write-LogEntry -Message "Successfully removed application provisioning package: $AppProvisioningPackageName" -Outhost
            }
            catch [System.Exception] {
                Write-LogEntry -Message "Failed removing AppxProvisioningPackage: $($_.Exception.Message)" -Severity 3 -Outhost
            }
        }
        else {
            Write-LogEntry -Message "Unable to locate AppxProvisioningPackage for app: $($App.Name)" -Outhost
        }

    }

    #Status is what shows up in MDT progressUI
    Write-Progress -Id 1 -Activity ("App Removal [{0} of {1}]" -f $p,$AppArrayList.count) -Status $status -CurrentOperation ("Processing App [{0}]" -f $App.Name) -PercentComplete ($p / $AppArrayList.count * 100)

    $p++
}

Write-LogEntry -Message ("Removed {0} built-in AppxPackage and AppxProvisioningPackage" -f $c) -Outhost


# White list of Features On Demand V2 packages
Write-LogEntry -Message "Starting Features on Demand V2 removal process"
$WhiteListOnDemand = "NetFX3|Tools.Graphics.DirectX|Tools.DeveloperMode.Core|Language|Browser.InternetExplorer|ContactSupport|OneCoreUAP|Media.WindowsMediaPlayer|Rsat"

# Get Features On Demand that should be removed
$OnDemandFeatures = Get-WindowsCapability -Online | Where-Object { $_.Name -notmatch $WhiteListOnDemand -and $_.State -like "Installed"} | Select-Object -ExpandProperty Name

try {

    # Handle cmdlet limitations for older OS builds
    if ($OSBuildNumber -le "16299") {
        $OnDemandFeatures = Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.Name -notmatch $WhiteListOnDemand -and $_.State -like "Installed"} | Select-Object -ExpandProperty Name
    }
    else {
        $OnDemandFeatures = Get-WindowsCapability -Online -LimitAccess -ErrorAction Stop | Where-Object { $_.Name -notmatch $WhiteListOnDemand -and $_.State -like "Installed"} | Select-Object -ExpandProperty Name
    }

    foreach ($Feature in $OnDemandFeatures) {
        try {
            Write-LogEntry -Message "Removing Feature on Demand V2 package: $($Feature)" -Outhost

            # Handle cmdlet limitations for older OS builds
            if ($OSBuildNumber -le "16299") {
                Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.Name -like $Feature } | Remove-WindowsCapability -Online -ErrorAction Stop | Out-Null
            }
            else {
                Get-WindowsCapability -Online -LimitAccess -ErrorAction Stop | Where-Object { $_.Name -like $Feature } | Remove-WindowsCapability -Online -ErrorAction Stop | Out-Null
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Message "Failed to remove Feature on Demand V2 package: $($_.Exception.Message)" -Severity 3 -Outhost
        }
    }
}
catch [System.Exception] {
    Write-LogEntry -Message "Failed attempting to list Feature on Demand V2 packages: $($_.Exception.Message)" -Severity 3 -Outhost
}
# Complete
Write-LogEntry -Message "Completed built-in AppxPackage and AppxProvisioningPackage removal process" -Outhost