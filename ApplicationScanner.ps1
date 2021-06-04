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

$FunctionsPath = Join-Path $scriptDirectory -ChildPath 'Functions'

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