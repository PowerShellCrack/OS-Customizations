<# 
    .NOTES
	===========================================================================
	 Created with: 	Powershell
	 Created by:   	Richard Tracy
	 Filename:     ApplicationScanner.ps1
	===========================================================================
	.DESCRIPTION
		Scans and Monitors applications installation status. Useful when its another system delivering the install

    .PARAMETER Applications
    .PARAMETER ScanMethod
        Options are: ARProduct,Uninstall,Executable,Event,Registry
    
    .PARAMETER DurationSec
        Duration of each application scan
        Default is 60 seconds (1 minute)
    
    .PARAMETER TimeOutSec
        If scanning detection or install is taking long than timeout, exits
        Default is 1800 seconds (30 minutes) 
    
    .PARAMETER WaitForInstall
        Default is false
        Builds a hash table with each application set to not installed, then scans the system for each application as the get installed
    
    .PARAMETER CommonName
        Adds a label to the log to identify what your scanning
    .EXAMPLE
    ApplicationScanner -Applications "McAfee Agent","McAfee Endpoint Security Platform","McAfee Endpoint Security Threat Prevention","McAfee Endpoint Security Adaptive Threat Protection","McAfee Policy Auditor Agent","McAfee DLP Endpoint","ACCM","McAfee Active Response","McAfee Host Intrusion Prevention","McAfee Data Exchange Layer", "McAfee Solidifier" -ScanMethod Uninstall -Duration 60 -WaitForInstall
    Duration 60


    Events1040_1042: MPAAgt.msi,ACCM_MSI.msi,DLPAgentInstaller.msi, AgentInstaller.msi,McAfeeHIP_ClientSetup_X64.msi,dxclient.msi
    Event11707

#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false,ParameterSetName="Applications",ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias("Application")]
    [string[]]$Applications,

    [Parameter(Mandatory=$false,ParameterSetName="Property",ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias("MDTProperty,SCCMProperty")]
    $Property,

    [Parameter(Mandatory=$true)]
    [ValidateSet("ARProduct", "Uninstall","Processes","Event","Registry")]
    [Alias("Scan")]
    [string]$ScanMethod = "Uninstall",

    [Parameter(Mandatory=$false)]
    [ValidateSet("File","Event","Registry")]
    [string]$StopTrigger = "Registry",

    [string]$StopValue = "HKLM:\SOFTWARE\McAfee\Agent\Applications\MAR_____1000",

    [Parameter(Mandatory=$false)]
    [ValidateRange(0,120)]
    [Alias("Duration")]
    [int32]$DurationSec = 30,

    [Parameter(Mandatory=$false)]
    [Alias("TimeOut")]
    [int32]$TimeOutSec = 1800,

    [Parameter(Mandatory=$false)]
    [switch]$WaitForInstall,

    [Parameter(Mandatory=$false)]
    [string]$CommonName
)

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
    param(
        [switch]$ReturnLogPath,
        [switch]$NoWarning
    )
    
    Begin{
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process{
        try{
            # Create an object to access the task sequence environment
            $Script:tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment 
        }
        catch{
            If(${CmdletName}){$prefix = "${CmdletName} ::" }Else{$prefix = "" }
            If(!$NoWarning){Write-Warning ("{0}Task Sequence environment not detected. Running in stand-alone mode." -f $prefix)}
            
            #set variable to null
            $Script:tsenv = $null
        }
        Finally{
            #set global Logpath
            if ($Script:tsenv){
                #grab the progress UI
                $Script:TSProgressUi = New-Object -ComObject Microsoft.SMS.TSProgressUI

                # Convert all of the variables currently in the environment to PowerShell variables
                $tsenv.GetVariables() | % { Set-Variable -Name "$_" -Value "$($tsenv.Value($_))" }
                
                # Query the environment to get an existing variable
                # Set a variable for the task sequence log path
                
                #Something like: C:\MININT\SMSOSD\OSDLOGS
                #[string]$LogPath = $tsenv.Value("LogPath")
                #Somthing like C:\WINDOWS\CCM\Logs\SMSTSLog
                [string]$LogPath = $tsenv.Value("_SMSTSLogPath")
                
            }
            Else{
                [string]$LogPath = $env:Temp
            }
        }
    }
    End{
        If($ReturnLogPath){return $LogPath}
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

function Update-ApplicationList{
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        $List

    )
    ## Get the name of this function
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

    # clone a copy of the hashtable to make it writable
    # loop it and check if software is installed
    # mark it as true
    Foreach($key in $List.Clone().GetEnumerator()){
        
        #Write-Progress -Id 1 -Activity ("Monitoring Applications [{0} of {1}]" -f $p,$Applications.count) -Status $Status -CurrentOperation ("Application [{0}]" -f $ValidateApps.key) -PercentComplete ($p / $Applications.count * 100)
        Write-LogEntry ("Waiting for [{0}] to install..." -f $key.key) -Outhost

        $appName = $key.key
        $appValue = $key.Value
        $AppInstalledx64 = Get-InstalledApplication -Application $appName -Arch x64
        $AppInstalledx86 = Get-InstalledApplication -Application $appName -Arch x86

        #Write-Host "Checking [$appName] with value [$appexist]"

        If($appValue -eq $False){
            
           # If($key.key -in $InstallApplication){
                
                #check if applications is installed
                If($AppInstalledx64 -or $AppInstalledx86){
                    $List.Set_Item($appName,$true)
                    Write-LogEntry "[$appName] is installed" -Source ${CmdletName} -Outhost
                } 
                               
           # }

        }
        Else{
            Write-LogEntry "[$appName] is not installed" -Source ${CmdletName} -Outhost
        }
    }

    return $List
}

function Check-InstalledApplication{
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string[]]$Applications
    )
    ## Get the name of this function
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

    # loop it and check if software is installed
    # mark it as true
    Foreach($App in $Applications){
        Write-LogEntry "Checking for install application [$App]" -Source ${CmdletName} -Severity 3 -Outhost

        $AppInstalledx64 = Get-InstalledApplication -Application $App -Arch x64
        $AppInstalledx86 = Get-InstalledApplication -Application $App -Arch x86
        #check if applications is installed
        If($AppInstalledx64 -or $AppInstalledx86){
            Write-LogEntry "[$App] is installed" -Source ${CmdletName} -Outhost
        } 
        Else{
            Write-LogEntry "[$App] is not installed" -Source ${CmdletName} -Outhost
        }
    }

}


function Get-InstalledApplication{
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]

        [string[]]$Application,
        
        [ValidateSet("x64","amd64","i386","x86")]
        [Alias("Bit")]
        [string]$Arch
    )
    ## Get the name of this function
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

    switch($Arch){
      "x64"    {$InstallApplication = Get-ItemProperty Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.Displayname -eq $Application} | Select -ExpandProperty DisplayName}
      "amd64"  {$InstallApplication = Get-ItemProperty Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.Displayname -eq $Application} | Select -ExpandProperty DisplayName}
      "i386"   {$InstallApplication = Get-ItemProperty Registry::HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*| Where {$_.Displayname -eq $Application} | Select -ExpandProperty DisplayName}
      "x86"    {$InstallApplication = Get-ItemProperty Registry::HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*| Where {$_.Displayname -eq $Application} | Select -ExpandProperty DisplayName}
      default  {$InstallApplication = Get-ItemProperty Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.Displayname -eq $Application} | Select -ExpandProperty DisplayName}
    }
    
    If($InstallApplication){
        return $true
    }
    Else{
        return $false
    }
}

Function ConvertTo-RegistryItem{
    [CmdletBinding()]
    param (
    [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Value
    )
    $RegKeyHive = ($Value).Split('\')[0].Replace('Registry::','').Replace(':','')

    Switch($RegKeyHive){
        HKEY_LOCAL_MACHINE {$LGPOHive = 'Computer';$RegProperty = 'HKLM:'}
        MACHINE {$LGPOHive = 'Computer';$RegProperty = 'HKLM:'}
        HKLM {$LGPOHive = 'Computer';$RegProperty = 'HKLM:'}
        HKEY_CURRENT_USER {$LGPOHive = 'User';$RegProperty = 'HKCU:'}
        HKEY_USERS {$LGPOHive = 'User';$RegProperty = 'HKCU:'}
        HKCU {$LGPOHive = 'User';$RegProperty = 'HKCU:'}
        HKU {$LGPOHive = 'User';$RegProperty = 'HKCU:'}
        USER {$LGPOHive = 'User';$RegProperty = 'HKCU:'}
        default {$LGPOHive = 'Computer';$RegProperty = 'HKLM:'}
    }

    
    $Value -match ","

    $RegKeyPath = Split-Path ($Value).Split('\',2)[1] -Parent
    $RegKeyName = Split-Path ($Value).Split('\',2)[1] -Leaf    

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
[string]$Global:LogFilePath = Join-Path (Get-SMSTSENV -ReturnLogPath -NoWarning) -ChildPath $FileName
Write-Host "logging to file: $LogFilePath" -ForegroundColor Cyan

##*===========================================================================
##* MAIN
##*===========================================================================
#build counter
$p = 1

If($CommonName){$label=($CommonName + " applications")}Else{$label="applications"}

<#
If($WaitForInstall){
    #put the applications in a hash table with install as false
    $ValidateApps = @{}


    Foreach($App in $Applications){
        $ValidateApps.add($App, $false)
    }

    Write-LogEntry "Monitor until all $label are installed..." -Outhost

    while($False -in $ValidateApps.Values){
        
        #timeout if process is taking longer than an 30 minutes
        #exit with an error timedout
        If($checkSum -le $TimeOutSec){
            #add sleep time to checksum
            $checkSum = $checkSum + $DurationSec
            
            $ValidateApps = Update-ApplicationList -List $ValidateApps
            
            Start-Sleep -s $DurationSec

            Get-ItemProperty "$StopTrigger::$StopValue"
        }
        Else{
            Write-LogEntry "McAfee Installation process timed-out after [$TimeOutSec] seconds" -Severity 3 -Outhost
            #exit $checkSum
        }
    }

    Write-LogEntry "All $label are installed, ending script." -Outhost
    #exit 0

}
Else{
      Write-LogEntry "Checking if $label are installed..." -Outhost
      Check-InstalledApplication $Applications
}
#>


Try{
    $timer = [Diagnostics.Stopwatch]::StartNew()

    While( ($timer.Elapsed.TotalSeconds -lt $TimeOutSec) -and (-not (Get-ItemProperty $StopValue -ErrorAction SilentlyContinue)) -and $WaitForInstall ){
        
        Start-Sleep -s $DurationSec
        $totalsecs = [math]::Round($Timer.Elapsed.TotalSeconds, 0)
   
        Show-ProgressStatus -Message ("Waiting [{0}] for {1} to be installed" -f $totalsecs,$label) -Step $totalsecs -MaxStep $TimeOutSec -Outhost
    }

    $timer.Stop()

    If($timer.Elapsed.TotalSeconds -gt $TimeOutSec){
        Write-LogEntry ("{0} timed-out after [{1}] seconds" -f $label,$TimeOutSec) -Severity 3 -Outhost
    }
    Else{
        Write-LogEntry ("All {0} are installed in [{0} secs]." -f $label,$timer.Elapsed.TotalSeconds) -Outhost
        exit 0
    }
}
Catch{
    Write-LogEntry -Message ("Error {0}" -f $_.Exception.Mesage) -Severity 3 -Outhost
}