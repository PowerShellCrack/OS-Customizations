# Parameters from the commandline to set the default variables
<# 
' Modded date: 05/18/2018
' Modded Author: Richard Tracy
' Mods: 

#>
[CmdletBinding()]
    param(
      [Parameter(Mandatory = $True)]
      [string]$Username,
      [Parameter(Mandatory = $True)]
      [String]$Password,
      [switch]$NeverExpire,
      [string]$Description,
      [switch]$DisableBuiltin
    )

$computer = $env:Computername
$SecurePassword = ConvertTo-SecureString -AsPlainText -Force $Password

#clean up user and get only name
if ($Username -match '\\([^\\]+)$'){
    $LocalUser = $matches[1]
}Else{
    $LocalUser = $Username
}

$UserAccount = Get-LocalUser -Name $LocalUser -ErrorAction SilentlyContinue
If(!$UserAccount)
{
    Try{
        New-LocalUser -Name $LocalUser -Description $Description -AccountNeverExpires:$NeverExpire -Password $SecurePassword -PasswordNeverExpires:$NeverExpire
        Add-LocalGroupMember -Group Administrators -Member $LocalUser
        Write-Host ("Local User Acount [{0}] built successfully!" -f $Username) -ForegroundColor Green
    }
    Catch{
        Write-Host ("Unable to create the account [{0}]! Error: {1}" -f $Username, $Error[0]) -ForegroundColor Red
    }
}
Else{
    Write-Host ("User account [{0}] already exists, reseting password and checking admin permissions..." -f $Username) -ForegroundColor Yellow
    Set-LocalUser -Name $LocalUser -Description $Description -AccountNeverExpires:$NeverExpire -Password $SecurePassword -PasswordNeverExpires:$NeverExpire
    
    $isAdmin = (Get-LocalGroupMember Administrators).Name -contains $LocalUser
    If($isAdmin){
        Write-Host ("User account [{0}] is an administrator already." -f $Username) -ForegroundColor Gray
    }Else{
        Add-LocalGroupMember -Group Administrators -Member $LocalUser
    }
}

If($DisableBuiltin){
    Disable-LocalUser -Name Administrator -Confirm:$false
}

