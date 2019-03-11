#Developer: Joseph Quigley 
#Date: 02/13/19

#Requires -Version 3 -RunAsAdministrator

#region Functions
Function Write-Log {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$False)]
    [ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
    [String]
    $Level = "INFO",

    [Parameter(Mandatory=$True)]
    [string]
    $Message,

    [Parameter(Mandatory=$False)]
    [string]
    $logfile
    )

    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $Line = "$Stamp $Level $Message"
    If($logfile) {
        Add-Content $logfile -Value $Line
    }
    Else {
        Write-Output $Line
    }
}
Function Show-Menu {
    param (
        [string]$Title = 'Powershell Common Tool Script'
    )
    Clear-Host
    Write-Host "=========== $Title =========="
    Write-Host "=================== Version 2.2 ===================="
    
    Write-Host "1: Press '1' for StickyKeys."
    Write-Host "2: Press '2' to Implement Clean user profile."
    Write-Host "3: Press '3' to Reset Settings."
    Write-Host "4: Press '4' to Refresh Wifi Settings."
    Write-Host "5: Press '5' to Grab Wifi Passwords."
    Write-Host "6: Press '6' to Generate system reports."
    Write-Host "7: Press '7' to Add a New Admin Account."
    Write-Host "Q: Press 'Q' to quit."
    
    Write-Host "================= By SecurityGhost ================="
}
Function Enable-Stickykey {
Takeown /F "C:\Windows\System32\cmd.exe" /D Y
Takeown /F "C:\Windows\System32\sethc.exe" /D Y
Icacls "C:\Windows\System32\cmd.exe" /grant "%username%":F 
Icacls "C:\Windows\System32\sethc.exe" /grant "%username%":F
# Old cmd commands
# move "C:\Windows\System32\sethc.exe" "C:\Windows\System32\sethc.old.exe"
# copy "C:\Windows\System32\cmd.exe" "C:\Windows\System32\sethc.exe"
Move-Item -Path "C:\Windows\System32\sethc.exe" -Destination "C:\Windows\System32\sethc.old.exe" -Force
Copy-Item -Path "C:\Windows\System32\cmd.exe" -Destination "C:\Windows\System32\sethc.exe" -Force
}
function Remove-UserProfile {
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=$false)]
        [String[]]$Exclude,
        [Parameter(Position=1,Mandatory=$false)]
        [DateTime]$Before,
        [Parameter(Position=2,Mandatory=$false)]
        [Switch]$DirectoryCleanup
    )

    Write-Verbose "Gathering List of Profiles on $env:COMPUTERNAME to Remove..."

    $userProfileFilter = "Loaded = 'False' AND Special = 'False'"
    $cleanupExclusions = @("Administrator", "All Users", "UpdatusUser", "Default", "Default User", "Public", "Guest", "josep")

    if ($Exclude)
    {
        foreach ($exclusion in $Exclude)
        {
            $userProfileFilter += "AND NOT LocalPath LIKE '%$exclusion'"
            $cleanupExclusions += $exclusion
        }
    }

    if ($Before)
    {
        $userProfileFilter += "AND LastUseTime < '$Before'"

        $keepUserProfileFilter = "Special = 'False' AND LastUseTime >= '$Before'"
        $profilesToKeep = Get-WmiObject -Class Win32_UserProfile -Filter $keepUserProfileFilter -ErrorAction Stop

        foreach ($profileToKeep in $profilesToKeep)
        {
            try
            {
                $userSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier($($profileToKeep.SID))
                $userName = $userSID.Translate([System.Security.Principal.NTAccount])
                
                $keepUserName = $userName.Value -replace ".*\\", ""
                $cleanupExclusions += $keepUserName
            }
            catch [System.Security.Principal.IdentityNotMappedException]
            {
                Write-Warning "Cannot Translate SID to UserName - Not Adding Value to Exceptions List"
            }
        }
    }

    $profilesToDelete = Get-WmiObject -Class Win32_UserProfile -Filter $userProfileFilter -ErrorAction Stop

    if ($DirectoryCleanup)
    {
        $usersChildItem = Get-ChildItem -Path "C:\Users" -Exclude $cleanupExclusions

        foreach ($usersChild in $usersChildItem)
        {
            if ($profilesToDelete.LocalPath -notcontains $usersChild.FullName)
            {    
                try
                {
                    Write-Verbose "Additional Directory Cleanup - Removing $($usersChild.Name) on $env:COMPUTERNAME..."
                    
                    Remove-Item -Path $($usersChild.FullName) -Recurse -Force -ErrorAction Stop
                }
                catch [System.InvalidOperationException]
                {
                    Write-Verbose "Skipping Removal of $($usersChild.Name) on $env:COMPUTERNAME as Item is Currently In Use..."
                }
            }
        }
    }

    foreach ($profileToDelete in $profilesToDelete)
    {
        Write-Verbose "Removing Profile $($profileToDelete.LocalPath) & Associated Registry Keys on $env:COMPUTERNAME..."
                
        Remove-WmiObject -InputObject $profileToDelete -ErrorAction Stop
    }

    $finalChildItem = Get-ChildItem -Path "C:\Users" | Select-Object -Property Name, FullName, LastWriteTime
                
    return $finalChildItem
}
Function Reset-Settings {
secedit /configure /cfg "$Env:WinDir\inf\defltbase.inf" /db defltbase.sdb /verbose
}
Function Refresh-Wifi {
Clear-DnsClientCache
Register-DnsClient
# look for nic w/ gateway
$GWNic=(Get-NetIPConfiguration -All |Where {$_.IPv4DefaultGateway -ne $null}).interfaceindex
# set dns servers to both ipv4/ipv6, reference https://developers.google.com/speed/public-dns/docs/using
Set-DnsClientServerAddress -InterfaceIndex $GWNic -ServerAddresses ("8.8.8.8","8.8.4.4","2001:4860:4860::8888","2001:4860:4860::8844")
}
function Show-Wifi {

    [CmdLetBinding()]
    param( [string]$network )

    if ( $network ) {

        Write-Host ""
        Write-Host ""
        Write-Host "Wireless Network Details:" -ForegroundColor Cyan
        Write-Host "===================================" -ForegroundColor Gray
        netsh.exe wlan show profiles name=$network key=clear
        Write-Host "===================================" -ForegroundColor Gray
        Write-Host ""

    } else {

        $networks = netsh.exe wlan show profiles key=clear | findstr "All"
        $networkNames = @($networks.Split(":") | findstr -v "All").Trim()

        Write-Host ""
        Write-Host ""
        Write-Host "Wireless Networks and Passwords" -ForegroundColor Cyan
        Write-Host "===================================" -ForegroundColor Gray
        Write-Host ""
        Write-Host "SSID : Password"-ForegroundColor Gray
        
        $result = New-Object -TypeName PSObject
 
        foreach ( $ap in $networkNames ) {
            
            try {
            
                $password = netsh.exe wlan show profiles name=$ap key=clear | findstr "Key" | findstr -v "Index"
                $passwordDetail = @($password.Split(":") | findstr -v "Key").Trim()
                #if ( -Not $password ) {
                #    $password = netsh.exe wlan show profiles name=$ap key=clear | findstr "Auth"
                #    $passwordDetail = "$password"
                #}
                Write-Host "$ap" -NoNewline
                Write-Host " : " -NoNewline
                Write-Host "$passwordDetail" -ForegroundColor Green
            } catch {
                Write-Host "Unable to obtain password for $ap - Likely using 802.1x or Open Network" -ForegroundColor Red
            }
        }
        Write-Host ""
        Write-Host "===================================" -ForegroundColor Gray
        Write-Host ""
    }
    Get-Variable | Remove-Variable -EA 0
}
Function Get-Reports {
# System reports
mkdir "$env:USERPROFILE\Desktop\reports"
$basedpath="$env:USERPROFILE\Desktop\reports"
net start |Out-File "$basedpath\services.txt"
tasklist /svc |Out-File "$basedpath\processes.txt"
netstat /a /b |Out-File "$basedpath\netstat.txt"
driverquery |Out-File "$basedpath\driverinfo.txt"
# User reports
Write-output "All user Accounts:" >> "$basedpath\usersreport.txt"
get-wmiobject Win32_UserAccount -filter 'LocalAccount=TRUE' | select-object -expandproperty Name|Out-File -Append "$basedpath\usersreport.txt"
Write-output "" >> "$basedpath\usersreport.txt"
Write-output "Admin Accounts:" >> "$basedpath\usersreport.txt"
net localgroup administrators | where {$_ -AND $_ -notmatch "command completed successfully"} | select -skip 4|Out-File -Append "$basedpath\usersreport.txt"
Write-output "" >> "$basedpath\usersreport.txt"
Write-output "Disabled Accounts:" >> "$basedpath\usersreport.txt"
get-wmiobject Win32_UserAccount -filter 'Disabled=TRUE or Lockout=TRUE' | select-object -expandproperty Name|Out-File -Append "$basedpath\usersreport.txt"
# Media Reports
$Include = @('*.mp3','*.mp4','*.m4a','*.jpg','*.jpeg','*.wav','*.ogg','*.wma','*.mov','*.mp4v','*.mpeg4','*.gif','*.png')
$exclude = [RegEx]'^C:\\Windows|^C:\\Program Files'
Get-ChildItem "C:\" -Directory |
  Where FullName -notmatch $exclude|ForEach {
  Get-ChildItem -Path $_.FullName -Include $Include -Recurse| 
  Select-Object -ExpandProperty FullName |Out-File "$basedpath\media.txt"
}
}
Function Add-Admin {
Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [string] $User,
         [Parameter(Mandatory=$true, Position=1)]
         [string] $Password 
    )
$Pwd = ConvertTo-SecureString $Password -AsPlainText -Force
New-LocalUser $User -Password $Pwd
Add-LocalGroupMember -Group "Administrators" -Member $User
}
#endregion Functions
#region Menu
do
 {
     Show-Menu
     Write-Host
     $selection = Read-Host "Please make a selection"
     switch ($selection)
     {
         '1' 
         {
         Enable-StickyKey
         } 
         '2' 
         {
         Remove-UserProfile -DirectoryCleanup
         } 
         '3' 
         {
         Reset-Settings
         } 
         '4'
         {
         Refresh-Wifi
         } 
         '5'
         {
         Show-Wifi
         }
         '6'
         {
         Get-Reports
         } 
         '7'
         {
         $User = Read-Host Username
         $Password = Read-Host Password
         
         Add-Admin $User $Password
         }

     }
     pause
 }
 until ($selection -eq 'q')
#endregion Menu 