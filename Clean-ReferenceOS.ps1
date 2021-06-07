<#
    .NOTES
	===========================================================================
	 Originally Created by:   	SHISHIR KUSHAWAHA (srktcet@gmail.com)
     changes by:                Richard Tracy
	 Filename:     	            Clean-ReferenceOS.ps1
     Last Updated:              02/25/2019
     Thanks to:                 unixuser011,W4RH4WK
	===========================================================================

    1. Run the script with Administrative access.
    2. Put # chanracter Display-MessageCleanup delete() function if you want to skip any folder.
    4. To add any new folder , need to declare the folder and call delete function with that folder variable

    .DESCRIPTION

		This script is created to automate the cleanup activity Display-MessageCleanup sysprep and capturing started. Doing so will reduce the size of .WIM file.

        This script will perform the following
        1. Clear windows temp and user temp folder
        2. Empty recycle bin
        3. Disk Cleanup
        4. Clear CBS cabinet log files
        5. Clear downloaded patches
        6. Clear downloaded driver
        7. Clean download folder


    . PARAM

    . LINKs

    https://www.gngrninja.com/script-ninja/2016/5/24/powershell-calculating-folder-sizes


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
. "$FunctionPath\Environment.ps1"
. "$FunctionPath\Cleanup.ps1"
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
[int]$OSBuildNumber = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber

#variables
$objShell = New-Object -ComObject Shell.Application
$Recyclebin = $objShell.Namespace(0xA)
$temp = (Get-ChildItem "env:\TEMP").Value
$WinTemp = "$env:SystemDrive\Windows\Temp\*"
$CBS="$env:SystemDrive\Windows\Logs\CBS\*"
$swtools="$env:SystemDrive\swtools\*"
$drivers="$env:SystemDrive\drivers\*"
$swsetup="$env:SystemDrive\swsetup\*"
$downloads="$env:SystemDrive\users\administrator\downloads\*"
$Prefetch="$env:SystemDrive\Windows\Prefetch\*"
$DowloadeUpdate="$env:SystemDrive\Windows\SoftwareDistribution\Download\*"

##*===========================================================================
##* MAIN
##*===========================================================================
# Remove temp files located in "C:\Users\USERNAME\AppData\Local\Temp"
Write-LogEntry "Emptying $temp..." -Severity 1 -Source $scriptName -Outhost
Remove-FolderContent "$temp\*"

# Remove content of folder created during installation of driver
Write-LogEntry "Emptying $swtools..." -Severity 1 -Source $scriptName -Outhost
Remove-FolderContent $swtools

# Remove content of folder created during installation of Lenovo driver
Write-LogEntry "Emptying $drivers..." -Severity 1 -Source $scriptName -Outhost
Remove-FolderContent $drivers

# Remove content of folder created during installation of HP driver
Write-LogEntry "Emptying $swsetup..." -Severity 1 -Source $scriptName -Outhost
Remove-FolderContent $swsetup

# Remove content of download folder of administrator account
Write-LogEntry "Emptying $downloads..." -Severity 1 -Source $scriptName -Outhost
Remove-FolderContent $downloads

# Empty Recycle Bin
Write-LogEntry "Emptying Recycle Bin..." -Severity 1 -Source $scriptName -Outhost
$Recyclebin.items() | %{ Remove-FolderContent($_.path)}

# Remove Windows Temp Directory
Write-LogEntry "Emptying $WinTemp..." -Severity 1 -Source $scriptName -Outhost
Remove-FolderContent $WinTemp

# Remove Prefetch folder content
Write-LogEntry "Emptying $Prefetch..." -Severity 1 -Source $scriptName -Outhost
Remove-FolderContent $Prefetch

# Remove CBS log file
Write-LogEntry "Emptying $CBS..." -Severity 1 -Source $scriptName -Outhost
Remove-FolderContent $CBS

# Remove downloaded update
Remove-FolderContent $DowloadeUpdate

Initialize-DiskCleanupMgr -VolumeCache All