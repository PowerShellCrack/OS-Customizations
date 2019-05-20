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
Function Test-IsISE {
    # try...catch accounts for:
    # Set-StrictMode -Version latest
    try {    
        return $psISE -ne $null;
    }
    catch {
        return $false;
    }
}

Function Get-ScriptPath {
    If (Test-Path -LiteralPath 'variable:HostInvocation') { $InvocationInfo = $HostInvocation } Else { $InvocationInfo = $MyInvocation }

    # Makes debugging from ISE easier.
    if ($PSScriptRoot -eq "")
    {
        if (Test-IsISE)
        {
            $psISE.CurrentFile.FullPath
            #$root = Split-Path -Parent $psISE.CurrentFile.FullPath
        }
        else
        {
            $context = $psEditor.GetEditorContext()
            $context.CurrentFile.Path
            #$root = Split-Path -Parent $context.CurrentFile.Path
        }
    }
    else
    {
        #$PSScriptRoot
        $PSCommandPath
        #$MyInvocation.MyCommand.Path
    }
}

Function Get-SMSTSENV{
    param([switch]$LogPath,[switch]$NoWarning)
    
    Begin{
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process{
        try{
            # Create an object to access the task sequence environment
            $Script:tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment 
            #test if variables exist
            $tsenv.GetVariables()  #| % { Write-Output "$ScriptName - $_ = $($tsenv.Value($_))" }
        }
        catch{
            If(${CmdletName}){$prefix = "${CmdletName} ::" }Else{$prefix = "" }
            If(!$NoWarning){Write-Warning ("{0}Task Sequence environment not detected. Running in stand-alone mode." -f $prefix)}
            
            #set variable to null
            $Script:tsenv = $null
        }
        Finally{
            #set global Logpath
            if ($tsenv){
                #grab the progress UI
                $Script:TSProgressUi = New-Object -ComObject Microsoft.SMS.TSProgressUI

                # Query the environment to get an existing variable
                # Set a variable for the task sequence log path
                #$UseLogPath = $tsenv.Value("LogPath")
                $UseLogPath = $tsenv.Value("_SMSTSLogPath")

                # Convert all of the variables currently in the environment to PowerShell variables
                $tsenv.GetVariables() | % { Set-Variable -Name "$_" -Value "$($tsenv.Value($_))" }
            }
            Else{
                $UseLogPath = $env:Temp
            }
        }
    }
    End{
        If($LogPath){return $UseLogPath}
    }
}

Function Format-ElapsedTime($ts) {
    $elapsedTime = ""
    if ( $ts.Minutes -gt 0 ){$elapsedTime = [string]::Format( "{0:00} min. {1:00}.{2:00} sec.", $ts.Minutes, $ts.Seconds, $ts.Milliseconds / 10 );}
    else{$elapsedTime = [string]::Format( "{0:00}.{1:00} sec.", $ts.Seconds, $ts.Milliseconds / 10 );}
    if ($ts.Hours -eq 0 -and $ts.Minutes -eq 0 -and $ts.Seconds -eq 0){$elapsedTime = [string]::Format("{0:00} ms.", $ts.Milliseconds);}
    if ($ts.Milliseconds -eq 0){$elapsedTime = [string]::Format("{0} ms", $ts.TotalMilliseconds);}
    return $elapsedTime
}

Function Format-DatePrefix{
    [string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
	[string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
    $CombinedDateTime = "$LogDate $LogTime"
    return ($LogDate + " " + $LogTime)
}


Function Write-LogEntry{
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [Parameter(Mandatory=$false,Position=2)]
		[string]$Source = '',
        [parameter(Mandatory=$false)]
        [ValidateSet(0,1,2,3,4)]
        [int16]$Severity,

        [parameter(Mandatory=$false, HelpMessage="Name of the log file that the entry will written to.")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputLogFile = $Global:LogFilePath,

        [parameter(Mandatory=$false)]
        [switch]$Outhost
    )
    ## Get the name of this function
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

    [string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
	[string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
	[int32]$script:LogTimeZoneBias = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now).TotalMinutes
	[string]$LogTimePlusBias = $LogTime + $script:LogTimeZoneBias
    #  Get the file name of the source script

    Try {
	    If ($script:MyInvocation.Value.ScriptName) {
		    [string]$ScriptSource = Split-Path -Path $script:MyInvocation.Value.ScriptName -Leaf -ErrorAction 'Stop'
	    }
	    Else {
		    [string]$ScriptSource = Split-Path -Path $script:MyInvocation.MyCommand.Definition -Leaf -ErrorAction 'Stop'
	    }
    }
    Catch {
	    $ScriptSource = ''
    }
    
    
    If(!$Severity){$Severity = 1}
    $LogFormat = "<![LOG[$Message]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$ScriptSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$Severity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
    
    # Add value to log file
    try {
        Out-File -InputObject $LogFormat -Append -NoClobber -Encoding Default -FilePath $OutputLogFile -ErrorAction Stop
    }
    catch {
        Write-Host ("[{0}] [{1}] :: Unable to append log entry to [{1}], error: {2}" -f $LogTimePlusBias,$ScriptSource,$OutputLogFile,$_.Exception.ErrorMessage) -ForegroundColor Red
    }
    If($Outhost){
        If($Source){
            $OutputMsg = ("[{0}] [{1}] :: {2}" -f $LogTimePlusBias,$Source,$Message)
        }
        Else{
            $OutputMsg = ("[{0}] [{1}] :: {2}" -f $LogTimePlusBias,$ScriptSource,$Message)
        }

        Switch($Severity){
            0       {Write-Host $OutputMsg -ForegroundColor Green}
            1       {Write-Host $OutputMsg -ForegroundColor Gray}
            2       {Write-Warning $OutputMsg}
            3       {Write-Host $OutputMsg -ForegroundColor Red}
            4       {If($Global:Verbose){Write-Verbose $OutputMsg}}
            default {Write-Host $OutputMsg}
        }
    }
}

function Show-ProgressStatus
{
    <#
    .SYNOPSIS
        Shows task sequence secondary progress of a specific step
    
    .DESCRIPTION
        Adds a second progress bar to the existing Task Sequence Progress UI.
        This progress bar can be updated to allow for a real-time progress of
        a specific task sequence sub-step.
        The Step and Max Step parameters are calculated when passed. This allows
        you to have a "max steps" of 400, and update the step parameter. 100%
        would be achieved when step is 400 and max step is 400. The percentages
        are calculated behind the scenes by the Com Object.
    
    .PARAMETER Message
        The message to display the progress
    .PARAMETER Step
        Integer indicating current step
    .PARAMETER MaxStep
        Integer indicating 100%. A number other than 100 can be used.
    .INPUTS
         - Message: String
         - Step: Long
         - MaxStep: Long
    .OUTPUTS
        None
    .EXAMPLE
        Set's "Custom Step 1" at 30 percent complete
        Show-ProgressStatus -Message "Running Custom Step 1" -Step 100 -MaxStep 300
    
    .EXAMPLE
        Set's "Custom Step 1" at 50 percent complete
        Show-ProgressStatus -Message "Running Custom Step 1" -Step 150 -MaxStep 300
    .EXAMPLE
        Set's "Custom Step 1" at 100 percent complete
        Show-ProgressStatus -Message "Running Custom Step 1" -Step 300 -MaxStep 300
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string] $Message,
        [Parameter(Mandatory=$true)]
        [int]$Step,
        [Parameter(Mandatory=$true)]
        [int]$MaxStep,
        [string]$SubMessage,
        [int]$IncrementSteps,
        [switch]$Outhost
    )

    Begin{

        If($SubMessage){
            $StatusMessage = ("{0} [{1}]" -f $Message,$SubMessage)
        }
        Else{
            $StatusMessage = $Message

        }
    }
    Process
    {
        If($Script:tsenv){
            $Script:TSProgressUi.ShowActionProgress(`
                $Script:tsenv.Value("_SMSTSOrgName"),`
                $Script:tsenv.Value("_SMSTSPackageName"),`
                $Script:tsenv.Value("_SMSTSCustomProgressDialogMessage"),`
                $Script:tsenv.Value("_SMSTSCurrentActionName"),`
                [Convert]::ToUInt32($Script:tsenv.Value("_SMSTSNextInstructionPointer")),`
                [Convert]::ToUInt32($Script:tsenv.Value("_SMSTSInstructionTableSize")),`
                $StatusMessage,`
                $Step,`
                $Maxstep)
        }
        Else{
            Write-Progress -Activity "$Message ($Step of $Maxstep)" -Status $StatusMessage -PercentComplete (($Step / $Maxstep) * 100) -id 1
        }
    }
    End{
        Write-LogEntry $Message -Severity 1 -Outhost:$Outhost
    }
}


Function Get-FolderSize{
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $false,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Alias('Path')]
        [String[]]
        $BasePath = 'C:\', 
               
        [Parameter(Mandatory = $false)]
        [Alias('User')]
        [String[]]
        $FolderName = 'all',

        [Parameter()]
        [String[]]
        $OmitFolders,

        [Parameter()]
        [Switch]
        $AddTotal
    )

    ## Get the name of this function
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

    #Get a list of all the directories in the base path we're looking for.
    if ($folderName -eq 'all') {

        $allFolders = Get-ChildItem $BasePath -Directory -Force | Where-Object {$_.FullName -notin $OmitFolders}

    }
    else {

        $allFolders = Get-ChildItem $basePath -Directory -Force | Where-Object {($_.BaseName -like $FolderName) -and ($_.FullName -notin $OmitFolders)}

    }

    #Create array to store folder objects found with size info.
    [System.Collections.ArrayList]$folderList = @()

    #Go through each folder in the base path.
    ForEach ($folder in $allFolders) {

        #Clear out the variables used in the loop.
        $fullPath = $null        
        $folderObject = $null
        $folderSize = $null
        $folderSizeInMB = $null
        $folderSizeInGB = $null
        $folderBaseName = $null

        #Store the full path to the folder and its name in separate variables
        $fullPath = $folder.FullName
        $folderBaseName = $folder.BaseName     

        Write-Verbose "Working with [$fullPath]..."            

        #Get folder info / sizes
        $folderSize = Get-Childitem -Path $fullPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue       
        
        #We use the string format operator here to show only 2 decimals, and do some PS Math.
        $folderSizeInMB = "{0:N2} MB" -f ($folderSize.Sum / 1MB)
        $folderSizeInGB = "{0:N2} GB" -f ($folderSize.Sum / 1GB)

        #Here we create a custom object that we'll add to the array
        $folderObject = [PSCustomObject]@{

            FolderName    = $folderBaseName
            'Size(Bytes)' = $folderSize.Sum
            'Size(MB)'    = $folderSizeInMB
            'Size(GB)'    = $folderSizeInGB

        }                        

        #Add the object to the array
        $folderList.Add($folderObject) | Out-Null

    }

    if ($AddTotal) {

        $grandTotal = $null

        if ($folderList.Count -gt 1) {
    
            $folderList | ForEach-Object {

                $grandTotal += $_.'Size(Bytes)'    

            }

            $totalFolderSizeInMB = "{0:N2} MB" -f ($grandTotal / 1MB)
            $totalFolderSizeInGB = "{0:N2} GB" -f ($grandTotal / 1GB)

            $folderObject = [PSCustomObject]@{

                FolderName    = 'GrandTotal'
                'Size(Bytes)' = $grandTotal
                'Size(MB)'    = $totalFolderSizeInMB
                'Size(GB)'    = $totalFolderSizeInGB
            }

            #Add the object to the array
            $folderList.Add($folderObject) | Out-Null
        }   

    }

    return $folderObject
}


function Display-MessageCleanup{
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        [Parameter(Mandatory=$true,Position=1)]
        [ValidateSet("Before","After")]
        [string]$When
    )
    ## Get the name of this function
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

    [string]$x = (Get-FolderSize $Path)."Size(Bytes)"
    [string]$sizemsg = (Get-FolderSize $Path)."Size(MB)"

    switch($When){
     "Before" {$msg="Total size before deletion: $sizemsg"}
     "After" {$msg="Total size after deletion: $sizemsg" }
     "During" {}
    }

    Write-LogEntry $msg -Source ${CmdletName} -Severity 1 -Outhost
    return $x 
} 

function Tally-FolderSize{
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Sum
    )
    ## Get the name of this function
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

    Write-LogEntry ("Total space cleared in MB from [{0}]: {1}" -f [string]$Path,$Sum) -Source ${CmdletName} -Severity 0 -Outhost
} 
 

function Remove-FolderContent{ 
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    Begin{
    ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process{
        If(Test-Path $Path){
            #grab 
            $a = Display-MessageCleanup $Path -When Before
            Write-LogEntry ("Attempting to remove files in {0}." -f $Path) -Source ${CmdletName} -Severity 2 -Outhost
            
            Try{
                #Remove all except folder contents of SMSTSlog and its logs
                Get-ChildItem -Path $Path -Recurse | Where {($_.FullName -notlike '*SMSTSLog*') -and ($_.FullName -ne $Global:LogFilePath)} |
                    Remove-Item -Recurse -Force -Verbose -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        
                #Remove All folders
                #Remove-Item -Recurse $Path -Force -Verbose -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        
            } 
            Catch [System.Management.Automation.ItemNotFoundException] {
                Write-LogEntry ("Unable to remove item from [{0}] because it does not exist anylonger" -f $Path.FullName) -Source ${CmdletName} -Severity 2 -Outhost
            }
            Catch [System.UnauthorizedAccessException]{
                Write-LogEntry ("[{0}] is in use. Unable to remove item from " -f $Path.FullName) -Source ${CmdletName} -Severity 2 -Outhost
            }
            Catch{
                $ErrorMessage = $_.Exception.Message
                Write-LogEntry ("Unable to remove item from [{0}]. Error [{1}]" -f $Path.FullName,$ErrorMessage) -Source ${CmdletName} -Severity 3 -Outhost
            }
            Finally{
                $b = Display-MessageCleanup $Path -When After 
                $total = $a-$b 
                Tally-FolderSize $Path $total
            }
        } 
        Else{
            Write-LogEntry ("Unable to remove items from [{0}] because it does not exist" -f $Path) -Source ${CmdletName} -Severity 1 -Outhost
        }
    }
    End{
        $a = 0 
        $b = 0 
        $total = 0
    }
} 
 

function Initialize-DiskCleanupMgr{ 
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("All","Active Setup Temp Folders","Content Indexer Cleaner","Device Driver Packages","Downloaded Program Files",
        "GameNewsFiles","GameStatisticsFiles","GameUpdateFiles","Internet Cache Files","Offline Pages Files","Old ChkDsk Files",
        "Previous Installations","Recycle Bin","Service Pack Cleanup","Setup Log Files","System error memory dump files","System error minidump files",
        "Temporary Setup Files","Temporary Sync Files","Thumbnail Cache","Update Cleanup","Upgrade Discarded Files","Windows Defender",
        "Windows Error Reporting Archive Files","Windows Error Reporting Queue Files","Windows Error Reporting System Archive Files",
        "Windows Error Reporting System Queue Files","Windows Error Reporting Temp Files","Windows ESD installation files","Windows Upgrade Log Files")]
        [string]$VolumeCache = "All"
    )
    Begin{
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
           
        $HKLM = [UInt32] "0x80000002"
        $strKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches" 
        If($VolumeCache -eq "All"){
            $subkeys = Get-ChildItem -Path $strKeyPath -Name 
        }
        Else{
            #$strKeyPath = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Upgrade Log Files"
            $subkeys = $VolumeCache
        }
        $strValueName = "StateFlags0065"
    }
    Process{
        #set the cleanup Stateflags registry keys for each volume prior to running cleanup
        ForEach($subkey in $subkeys){
            New-ItemProperty -Path $strKeyPath\$subkey -Name $strValueName -PropertyType DWord -Value 2 -ea SilentlyContinue -wa SilentlyContinue | Out-Null
        }

        Try{
            Write-LogEntry "Starting Windows disk Clean up Tool" -Source ${CmdletName} -Severity 1 -Outhost
            Start-Process cleanmgr -ArgumentList "/sagerun:65" -Wait -NoNewWindow -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        }
        Catch{
            $ErrorMessage = $_.Exception.Message
            Write-LogEntry ("Windows Disk Clean up Tool failed to run for Volume Cache [{0}]. Error [{1}]" -f $VolumeCache,$ErrorMessage) -Source ${CmdletName} -Severity 3 -Outhost
        }
        Finally{
            Write-LogEntry "Clean Up completed" -Source ${CmdletName} -Severity 1 -Outhost
        }
    }
    End{
        #remove the cleanup Stateflags registry keys for each volume after running cleanup
        ForEach($subkey in $subkeys){
            Remove-ItemProperty -Path $strKeyPath\$subkey -Name $strValueName -ea SilentlyContinue -wa SilentlyContinue | Out-Null
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

[int]$OSBuildNumber = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber

#build log name
[string]$FileName = $scriptBaseName +'.log'
#build global log fullpath
$Global:LogFilePath = Join-Path (Get-SMSTSENV -LogPath -NoWarning) -ChildPath $FileName
Write-Host "logging to file: $LogFilePath" -ForegroundColor Cyan

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
Write-LogEntry "Emptying $temp..." -Severity 1 -Outhost
Remove-FolderContent "$temp\*"

# Remove content of folder created during installation of driver
Write-LogEntry "Emptying $swtools..." -Severity 1 -Outhost
Remove-FolderContent $swtools 
 
# Remove content of folder created during installation of Lenovo driver
Write-LogEntry "Emptying $drivers..." -Severity 1 -Outhost
Remove-FolderContent $drivers

# Remove content of folder created during installation of HP driver
Write-LogEntry "Emptying $swsetup..." -Severity 1 -Outhost
Remove-FolderContent $swsetup

# Remove content of download folder of administrator account
Write-LogEntry "Emptying $downloads..." -Severity 1 -Outhost
Remove-FolderContent $downloads    
 
# Empty Recycle Bin
Write-LogEntry "Emptying Recycle Bin..." -Severity 1 -Outhost
$Recyclebin.items() | %{ Remove-FolderContent($_.path)}
 
# Remove Windows Temp Directory
Write-LogEntry "Emptying $WinTemp..." -Severity 1 -Outhost
Remove-FolderContent $WinTemp 

# Remove Prefetch folder content
Write-LogEntry "Emptying $Prefetch..." -Severity 1 -Outhost
Remove-FolderContent $Prefetch
    
# Remove CBS log file
Write-LogEntry "Emptying $CBS..." -Severity 1 -Outhost
Remove-FolderContent $CBS

# Remove downloaded update 
Remove-FolderContent $DowloadeUpdate

Initialize-DiskCleanupMgr -VolumeCache All