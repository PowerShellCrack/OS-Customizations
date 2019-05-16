#requires -version 3

param(
    [string[]]$ComputerName = $env:ComputerName,
    [string[]]$Name,
    [switch]$Test
)

#do not allow script to delete builtin accounts
$DoNotDeleteProfile = @("Public", "Default")
$DoNotRemoveSID = @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')

#build WMI paramaters
$params = @{
    ComputerName = $ComputerName 
    Namespace    = 'root\cimv2'
    Class        = 'Win32_UserProfile'
}

#build filter for name based on path
if($Name.Count -gt 1) {
    $params.Add('Filter', ($Name | % { "LocalPath = '{0}'" -f $_ }) -join ' OR ')
} elseif($Name -match '\\') {
    $params.Add('Filter', "LocalPath LIKE '%{0}%'" -f ($Name.split('\')[1]))
} else {
    $params.Add('Filter', "LocalPath LIKE '%{0}%'" -f ($Name -replace '\*','%'))
}

   
#Call WMI and loop 
Get-WmiObject @params | ForEach-Object {

    $WouldBeRemoved = $false
    if( ($_.SID -notin $DoNotRemoveSID) ) {
        $WouldBeRemoved = $true
    }

    #build PSObject of profiles found
    $prf = [pscustomobject]@{
        PSComputerName = $_.PSComputerName
        #Account = (New-Object System.Security.Principal.SecurityIdentifier($_.Sid)).Translate([System.Security.Principal.NTAccount]).Value
        LocalPath = $_.LocalPath
        LastUseTime = if($_.LastUseTime) { ([WMI]'').ConvertToDateTime($_.LastUseTime) } else { $null }
        Loaded = $_.Loaded
    }

    #If in test mode, 
    if($Test) {
        $prf | Select-Object -Property *, @{N='WouldBeRemoved'; E={$WouldBeRemoved}}
    }

    if(-not $Test -and $WouldBeRemoved) { 
        try {
            $_.Delete()
            $Removed = $true
            write-host ("Deleted profile folder: {0} " -f $_.LocalPath) -ForegroundColor Green
        } catch {
            $Removed = $false
            write-host ("Unable to delete profile folder: {0}, " -f $_.Exception) -ForegroundColor Red
        }
    }
}
