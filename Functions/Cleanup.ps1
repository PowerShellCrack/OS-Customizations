
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


Function Clean-Profile{
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
}