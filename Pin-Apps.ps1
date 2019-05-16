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