<#
 
' Modded date: 05/24/2018
' Modded Author: Richard Tracy
' Mods: 

#>
[CmdletBinding()]
    param(
      [Parameter(Mandatory = $True)]
      [string]$Username,
      [Parameter(Mandatory = $True)]
      [String]$Password,
      [string]$Description,
      [switch]$NeverExpire,
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

#Set Boolean for Never expire
If(!$NeverExpire){$bExpire = $false}Else{$bExpire = $true}

#check to see if local user already exists
$UserAccount = Get-LocalUser -Name $LocalUser -ErrorAction SilentlyContinue
If(!$UserAccount)
{
    #attempt to create new account and add it to the local adminsitrators group
    Try{
        New-LocalUser -Name $LocalUser -Description $Description -AccountNeverExpires:$bExpire -Password $SecurePassword -PasswordNeverExpires:$bExpire
        Add-LocalGroupMember -Group Administrators -Member $LocalUser
        Write-Host ("Local User Acount [{0}] built successfully!" -f $Username) -ForegroundColor Green
    }
    Catch{
        Write-Host ("Unable to create the account [{0}]! Error: {1}" -f $Username, $Error[0]) -ForegroundColor Red
    }
}
Else{
    #if account already exists, reset password and add it to the local adminsitrators group
    Write-Host ("User account [{0}] already exists, reseting password and checking admin permissions..." -f $Username) -ForegroundColor Yellow
    Set-LocalUser -Name $LocalUser -Description $Description -AccountNeverExpires:$bExpire -Password $SecurePassword -PasswordNeverExpires:$bExpire
    
    #check to see if local user is already an admin
    $isAdmin = (Get-LocalGroupMember Administrators).Name -contains $LocalUser
    If($isAdmin){
        Write-Host ("User account [{0}] is an administrator already." -f $Username) -ForegroundColor Gray
    }
    Else{
        Add-LocalGroupMember -Group Administrators -Member $LocalUser
    }
}



If($DisableBuiltin){
    #get current name of builtin administrator acount (this could be renamed if GPO is set)
    $builtinAdmin = Get-LocalUser | Where{$_.Description -eq "Built-in account for administering the computer/domain"}

    #check to ensure at least one OTHER acount is a local admin
    If( ((Get-LocalGroupMember Administrators) | Where {$_.PrincipalSource -eq 'Local'}).count -gt 1){
        Write-Host ("Disabling Builtin local Administrator account [{0}]" -f $builtinAdmin.Name) -ForegroundColor Gray
        #disable the bultin account
        Disable-LocalUser -Name $builtinAdmin.Name -Confirm:$false | Out-Null
    }
    Else{
        Write-Host ("Unable to disable local Administrator account [{0}] because there is no other local administrator account that exists." -f $builtinAdmin.Name) -ForegroundColor Yellow
    }
}

