function Pin-App ([string]$appname, [switch]$unpin, [switch]$start, [switch]$taskbar, [string]$path) {
    if ($unpin.IsPresent) {
        $action = "Unpin"
    } else {
        $action = "Pin"
    }

    if (-not $taskbar.IsPresent -and -not $start.IsPresent) {
        Write-Error "Specify -taskbar and/or -start!"
    }

    if ($taskbar.IsPresent) {
        try {
            $exec = $false
            if ($action -eq "Unpin") {
                ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Unpin from taskbar'} | %{$_.DoIt(); $exec = $true}
                if ($exec) {
                    Write "App '$appname' unpinned from Taskbar"
                } else {
                    if (-not $path -eq "") {
                        Pin-AppXPath $path -Action $action
                    } else {
                        Write "'$appname' not found or 'Unpin from taskbar' not found on item!"
                    }
                }
            } else {
                ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Pin to taskbar'} | %{$_.DoIt(); $exec = $true}

                if ($exec) {
                    Write "App '$appname' pinned to Taskbar"
                } else {
                    if (-not $path -eq "") {
                        Pin-AppXPath $path -Action $action
                    } else {
                        Write "'$appname' not found or 'Pin to taskbar' not found on item!"
                    }
                }
            }
        } catch {
            Write-Error "Error Pinning/Unpinning $appname to/from taskbar!"
        }
    }

    if ($start.IsPresent) {
        try {
            $exec = $false
            if ($action -eq "Unpin") {
                ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Unpin from Start'} | %{$_.DoIt(); $exec = $true}

                if ($exec) {
                    Write "App '$appname' unpinned from Start"
                } else {
                    if (-not $path -eq "") {
                        Pin-AppXPath $path -Action $action -start
                    } else {
                        Write "'$appname' not found or 'Unpin from Start' not found on item!"
                    }
                }
            } else {
                ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Pin to Start'} | %{$_.DoIt(); $exec = $true}

                if ($exec) {
                    Write "App '$appname' pinned to Start"
                } else {
                    if (-not $path -eq "") {
                        Pin-AppXPath $path -Action $action -start
                    } else {
                        Write "'$appname' not found or 'Pin to Start' not found on item!"
                    }
                }
            }
        } catch {
            Write-Error "Error Pinning/Unpinning $appname to/from Start!"
        }
    }
}

function Pin-AppXPath([string]$Path, [string]$Action, [switch]$start) {
    if ($Path -eq "") {
        Write-Error -Message "You need to specify a Path" -ErrorAction Stop
    }
    if ($Action -eq "") {
        Write-Error -Message "You need to specify an action: Pin or Unpin" -ErrorAction Stop
    }
    if ((Get-Item -Path $Path -ErrorAction SilentlyContinue) -eq $null){
        Write-Error -Message "$Path not found" -ErrorAction Stop
    }
    $Shell = New-Object -ComObject "Shell.Application"
    $ItemParent = Split-Path -Path $Path -Parent
    $ItemLeaf = Split-Path -Path $Path -Leaf
    $Folder = $Shell.NameSpace($ItemParent)
    $ItemObject = $Folder.ParseName($ItemLeaf)
    $Verbs = $ItemObject.Verbs()

    if ($start.IsPresent) {
        switch($Action){
            "Pin"   {$Verb = $Verbs | Where-Object -Property Name -EQ "&Pin to Start"}
            "Unpin" {$Verb = $Verbs | Where-Object -Property Name -EQ "Un&pin from Start"}
            default {Write-Error -Message "Invalid action, should be Pin or Unpin" -ErrorAction Stop}
        }
    } else {
        switch($Action){
            "Pin"   {$Verb = $Verbs | Where-Object -Property Name -EQ "Pin to Tas&kbar"}
            "Unpin" {$Verb = $Verbs | Where-Object -Property Name -EQ "Unpin from Tas&kbar"}
            default {Write-Error -Message "Invalid action, should be Pin or Unpin" -ErrorAction Stop}
        }
    }

    if($Verb -eq $null){
        Write-Error -Message "That action is not currently available on this Path" -ErrorAction Stop
    } else {
        $Result = $Verb.DoIt()
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
