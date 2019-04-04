<#
김경민kdr - CUI 작업관리자
#>

$ScriptName = "tmgr"
$SUCCESS = "SUCCESS"
$FAILED = "FAILED"
$Startup = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

$ErrorActionPreference = "Stop"

$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

if ($isAdmin -eq $true) { <# Pass #> }
else { Write-Output "`nIf you are not an administrator, you may have restrictions on your use." }

function SFWrite([string]$STATUS, [string]$CSTRING)
{
    if($STATUS -eq $SUCCESS)
    {
        Write-Output "`n[+] $CSTRING `n"
    }

    if($STATUS -eq $FAILED)
    {
        Write-Output "`n[-] $CSTRING `n"
    }
}

Write-Output "`n +---------------------------+"
Write-Output " |        Made by kdr        |  "
Write-Output " |      CUI Task Manager     |  "
Write-Output " +---------------------------+`n"

if($args[0] -eq "--help")
{
    Write-Output " Usage : $ScriptName [Option] `n"
    Write-Output "  -proc : Processes             "
    Write-Output "  -perf : Performance           "
    Write-Output "  -apps : App History           "
    Write-Output "  -stup : Startup               "
    Write-Output "  -usrs : Users                 "
    Write-Output "  -dets : Details               "
    Write-Output "  -srvs : Services            `n"
}

elseif($args[0] -eq "-proc")
{
    if($args[1] -eq "--help")
    {
        Write-Output " Usage : $ScriptName -proc [Option]                                    `n"
        Write-Output "  -show  [ -apps | -srvs | -all ]                 : Show Processes List  "
        Write-Output "  -start [ -admin ] [ Process ]                   : Start Process        "
        Write-Output "  -kill  [ -pid ProcessID | -pname ProcessName ]  : Kill Process       `n"
    }

    elseif($args[1] -eq "-show")
    {

        if($args[2] -eq "--help")
        {
            Write-Output " Usage : $ScriptName -proc -show [Option]  `n"
            Write-Output "  -apps : Show Applications Process          "
            Write-Output "  -srvs : Show Services Process              "
            Write-Output "  -all  : Show All Process                 `n"
        }

        elseif($args[2] -eq "-apps")
        {
            Write-Output "[Applications Process]"
            Get-Process
        }

        elseif($args[2] -eq "-srvs")
        {
            Write-Output "[Services Process]"
            Get-Service
        }

        elseif($args[2] -eq "-all")
        {
            Write-Output "`n[Applications Process]"
            Get-Process
            Write-Output "`n[Services Process]"
            Get-Service
        }

        else
        {
            SFWrite $FAILED "Type '$ScriptName -proc -show --help'"
        }    
        
    }

    elseif($args[1] -eq "-start")
    {
        if($args[2] -eq "--help")
        {
            Write-Output " Usage : $ScriptName -proc -start [Option] [ Process ]         `n"
            Write-Output "  -admin : Start Process as Administrator                        "
            Write-Output "   If you don't use -admin Option, Process will start with User`n"
        }

        elseif($args[2] -eq "-admin")
        {
            if($args[3] -eq "--help")
            {
                Write-Output " Usage : $ScriptName -proc -start -admin [ Process ]`n"
            }

            elseif($null -ne $args[3])
            {
                try 
                {
                    Start-Process $args[3] -Verb runas
                    SFWrite $SUCCESS "Executed Successfully as Administrator : ", $args[3]
                }
                catch [Microsoft.PowerShell.Commands.ProcessCommandException]
                {
                    SFWrite $FAILED "Failed to Execute : ", $args[3]
                }
            }

            else
            {
                SFWrite $FAILED "Type '$ScriptName -proc -start -admin --help'"
            }
        }

        elseif($null -ne $args[2])
        {
            try
            {
                Start-Process $args[2]
                SFWrite $SUCCESS "Executed Successfully : ", $args[2]
            }
            catch [Microsoft.PowerShell.Commands.ProcessCommandException]
            {
                SFWrite $FAILED "Failed to Execute : ", $args[2]
            }
            catch [System.InvalidOperationException]
            {
                SFWrite $FAILED "Failed to Execute : ", $args[2]
            }
        }

        else
        {
            SFWrite $FAILED "Type '$ScriptName -proc -start --help'"
        }
    }

    elseif($args[1] -eq "-kill")
    {
        if($args[2] -eq "--help")
        {
            Write-Output " Usage : $ScriptName -proc -kill [Option]               `n"
            Write-Output "  -pid [ ProcessID ]     : Kill Process with ProcessID    "
            Write-Output "  -pname [ ProcessName ] : Kill Process with ProcessName`n"
        }

        elseif($args[2] -eq "-pid")
        {
            if($args[3] -eq "--help")
            {
                Write-Output " Usage : $ScriptName -proc -kill -pid [ ProcessID ]`n"
            }   

            elseif($null -ne $args[3])
            {
                try 
                {
                    Stop-Process -Id $args[3] -Force
                    SFWrite $SUCCESS "Killed Process Successfully with ID : ", $args[3]   
                }
                catch [Microsoft.PowerShell.Commands.ProcessCommandException] 
                {
                    SFWrite $FAILED "Failed to Kill Process with ID : ", $args[3]
                }   
            }

            else
            {
                SFWrite $FAILED "Type '$ScriptName -proc -kill -pid --help'"
            }
        }

        elseif($args[2] -eq "-pname")
        {
            if($args[3] -eq "--help")
            {
                Write-Output "Usage : $ScriptName -proc -kill -pname [ ProcessName ]`n"
            }

            elseif($null -ne $args[3])
            {
                try
                {
                    Stop-Process -Name $args[3] -Force
                    SFWrite $SUCCESS "Killed Process Successfully with Name : ", $args[3]
                }
                catch [Microsoft.PowerShell.Commands.ProcessCommandException]
                {
                    SFWrite $FAILED "Failed to Kill with Process Name : ", $args[3]
                }
            }

            else
            {
                SFWrite $FAILED "Type '$ScriptName -proc -kill -pname --help'"
            }
        }

        else
        {
            SFWrite $FAILED "Type '$ScriptName -proc -kill --help'"
        }
    }

    else
    {
        SFWrite $FAILED "Type '$ScriptName -proc --help'"
    }
}

elseif($args[0] -eq "-perf")
{
    if($args[1] -eq "--help")
    {
        Write-Output " Usage : $ScriptName -perf [Option]`n"
        Write-Output "  -cpu  : Show CPU Info, Status      "
        Write-Output "  -mem  : Show Memory Info, Status   "
        Write-Output "  -disk : Show Disk Info, Status     "
        Write-Output "  -net  : Show Network Info, Status  "
        Write-Output "  -gpu  : Show GPU Info, Status    `n"
    }

    elseif($args[1] -eq "-cpu")
    {
        Write-Output "[CPU Information]" 
        Get-WmiObject -Class Win32_Processor
        Write-Output "[CPU Percentaeg]" 
        Get-WmiObject Win32_Processor | 
        Select-Object LoadPercentage
    }

    elseif($args[1] -eq "-mem")
    {
        Write-Output "`n[Memory Information]"
        Get-WmiObject -Class win32_physicalmemory | 
        Format-Table Manufacturer,Banklabel,Configuredclockspeed,
        Devicelocator,Capacity,Serialnumber -autosize
        
        Write-Output "`n[Total Physical Memory (GB)]" 
        Get-CimInstance -Class Win32_ComputerSystem |
        ForEach-Object {$_.TotalPhysicalMemory / 1GB}

        Write-Output "`n[Free Physical Memory (GB)]" 
        Get-WmiObject -Class Win32_OperatingSystem |
        ForEach-Object {$_.FreePhysicalMemory / 1MB}
    }

    elseif($args[1] -eq "-disk")
    {
        Write-Output "`n[Disk Information]" 
        Get-WmiObject -Class Win32_LogicalDisk | 
        Select-Object -Property DeviceID, DriveType, VolumeName, 
        @{L='FreeSpace(GB)';E={"{0:N2}" -f ($_.FreeSpace / 1GB)}},
        @{L="TotalDiskSpace(GB)";E={"{0:N2}" -f ($_.Size/ 1GB)}}

        Write-Output "[Disk Percentage]`n"  
        (Get-Counter -Counter "\physicaldisk(_total)\% disk time").CounterSamples.CookedValue
    }

    elseif($args[1] -eq "-net")
    {
        Write-Output "[Network Information]" 
        Get-WmiObject -Class Win32_NetworkAdapter |
        Where-Object {($_.Speed -ne $null) -and ($_.MACAddress -ne $null)} |
        Format-Table -Property SystemName, Name, NetConnectionID, Speed
    }

    elseif($args[1] -eq "-gpu")
    {
        Write-Output "[GPU Information]" 
        Get-WmiObject -Class Win32_VideoController |
        Format-Table -Property Name
    }

    else
    {
        SFWrite $FAILED "Type '$ScriptName -perf --help'"
    }
}

elseif($args[0] -eq "-apps")
{
    Write-Output "[ CPU Time ]`n" 
    Get-Counter '\Processor(*)\% Processor Time'

    Write-Output "[ All Network ]`n" 
    Get-NetAdapterStatistics
}

elseif($args[0] -eq "-stup")
{
    if($args[1] -eq "--help")
    {
        Write-Output " Usage : $ScriptName -stup [Option]      `n"
        Write-Output "  -show          : Show Startup Program    "
        Write-Output "  -add  [ Path ] : Add Startup Program     "
        Write-Output "  -del  [ Path ] : Delete Startup Program`n"
    }

    elseif($args[1] -eq "-show")
    {
        Get-ItemProperty -Path $Startup
    }

    elseif($args[1] -eq "-add")
    {
        if($args[2] -eq "--help")
        {
            Write-Output " Usage : $ScriptName -stup -add [ Path ]`n"
        }

        elseif($null -ne $args[2])
        {
            try 
            {
                New-ItemProperty -Path $Startup -Name $args[2] -Value $args[2]
                SFWrite $SUCCESS "Added Startup Program Successfully : ", $args[2]
            }
            catch [System.IO.IOException] 
            {
                SFWrite $FAILED "Already Existed Startup Program : ", $args[2]
            }
        }

        else
        {
            SFWrite $FAILED "Type '$ScriptName -stup -add --help'"
        }
    }

    elseif($args[1] -eq "-del")
    {
        if($args[2] -eq "--help")
        {
            Write-Output " Usage : $ScriptName -stup -del [ Path ]"
        }

        elseif($null -ne $args[2])
        {
            try
            {
                Remove-ItemProperty -Path $Startup -Name $args[2]
                SFWrite $SUCCESS "Delete Startup Program Successfully : ", $args[2]
            }
            catch [System.Management.Automation.PSArgumentException]
            {
                SFWrite $FAILED "Failed to Delete Startup Program : ", $args[2]
            }
        }

        else
        {
            SFWrite $FAILED "Type '$ScriptName -stup -del --help'"
        }
    }

    else
    {
        SFWrite $FAILED "Type '$ScriptName -stup --help'"
    }
}

elseif($args[0] -eq '-usrs')
{
    if($args[1] -eq "--help")
    {
        Write-Output " Usage : $ScriptName -usrs [Option]           `n"
        Write-Output "  -show            : Show Logged on User        "
        Write-Output "  -en  [ Account ] : Enable User                "
        Write-Output "  -dis [ Account ] : Disable User             `n"
    }

    elseif($args[1] -eq "-show")
    {
        Write-Output "[ User List ]`n" 
        Get-LocalUser | Select-Object Name, Enabled
    }

    elseif($args[1] -eq "-en")
    {
        if($args[2] -eq "--help")
        {
            Write-Output " Usage : $ScriptName -usrs -en [Option] `n"
            Write-Output "  -en [ Account ]                       `n"
        }

        elseif($null -ne $args[2])
        {
            try
            {
                Enable-LocalUser -Name $args[2]
                SFWrite $SUCCESS "Enabled Local User Successfully : ", $args[2]
            }
            catch [Microsoft.PowerShell.Commands.AccessDeniedException]
            {
                SFWrite $FAILED "Failed to Enable Local User : ", $args[2]
                SFWrite $FAILED "REASON : Access Denied"
            }
            catch [Microsoft.PowerShell.Commands.UserNotFoundException]
            {
                SFWrite $FAILED "Failed to Enable Local User : ", $args[2]
                SFWrite $FAILED "REASON : User Not Found"
            }
        }

        else
        {
            SFWrite $FAILED "Type 'Type $ScriptName -usrs -en --help'"
        }
    }

    elseif($args[1] -eq "-dis")
    {
        if($args[2] -eq "--help")
        {
            Write-Output " Usage : $ScriptName -usrs -dis [Option] `n"
            Write-Output "  -dis [ Account ]                       `n"
        }

        elseif($null -ne $args[2])
        {
            try
            {
                Enable-LocalUser -Name $args[2]
                SFWrite $SUCCESS "Disabled Local User Successfully : ", $args[2]
            }
            catch [Microsoft.PowerShell.Commands.AccessDeniedException]
            {
                SFWrite $FAILED "Failed to Disable Local User : ", $args[2]
                SFWrite $FAILED "REASON : Access Denied"
            }
            catch [Microsoft.PowerShell.Commands.UserNotFoundException]
            {
                SFWrite $FAILED "Failed to Disable Local User : ", $args[2]
                SFWrite $FAILED "REASON : User Not Found"
            }
        }

        else
        {
            SFWrite $FAILED "Type '$ScriptName -usrs -dis --help'"
        }
    }

    else
    {
        SFWrite $FAILED "Type '$ScriptName -usrs --help'"
    }
}

elseif($args[0] -eq "-dets")
{
    Get-Process | Where-Object {$_.MainWindowHandle -ne 0} |
    Select-Object Name, MainWindowTitle
}

elseif($args[0] -eq "-srvs")
{
    if($args[1] -eq "--help")
    {
        Write-Output " Usage : $ScriptName -srvs [Option]                          `n"
        Write-Output "  -show    [ -running | -stopped | -all ]  : Show Services     "
        Write-Output "  -start   [ Service ]                     : Start Service     "
        Write-Output "  -stop    [ Service ]                     : Stop Service      "
        Write-Output "  -restart [ Service ]                     : Restart Service `n" 
    }

    elseif($args[1] -eq "-show")
    {
        if($args[2] -eq "--help")
        {
            Write-Output " Usage : $ScriptName -srvs [Option] `n"
            Write-Output "  -running : Show Running Services    "
            Write-Output "  -stopped : Show Stopped Services    " 
            Write-Output "  -all     : Show All Services      `n"
        }

        elseif($args[2] -eq "-running")
        {
            Get-Service |
            Where-Object {$_.Status -eq "Running"}
        }

        elseif($args[2] -eq "-stopped")
        {
            Get-Service |
            Where-Object {$_.Status -eq "Stopped"}

        }

        elseif($args[2] -eq "-all")
        {
            Get-Service
        }

        else
        {
            SFWrite $FAILED "Type '$ScriptName -srvs -show --help'"
        }
    }
    
    elseif($args[1] -eq "-start")
    {
        if($args[2] -eq "--help")
        {
            Write-Output " Usage : $ScriptName -srvs -start [ Service ]`n"
        }

        elseif($null -ne $args[2])
        {
            try
            {
                Start-Service -Name $args[2]
                SFWrite $SUCCESS "Started Successfully : ", $args[2]
            }
            catch [Microsoft.PowerShell.Commands.ServiceCommandException]
            {
                SFWrite $FAILED "Failed to Start Service : ", $args[2]
            }
        }

        else
        {
            SFWrite $FAILED "Type '$ScriptName -srvs -start --help'"
        }
    }

    elseif($args[1] -eq "-stop")
    {
        if($args[2] -eq "--help")
        {
            Write-Output " Usage : $ScriptName -srvs -stop [ Service ]`n"
        }

        elseif($null -ne $args[2])
        {
            try
            {
                Stop-Service -Name $args[2]
                SFWrite $SUCCESS "Stopped Successfully : ", $args[2]
            }
            catch [Microsoft.PowerShell.Commands.ServiceCommandException]
            {
                SFWrite $FAILED "Failed to Stop Service : ", $args[2]
            }
        }

        else
        {
            SFWrite $FAILED "Type '$ScriptName -srvs -stop --help'"
        }
    }

    elseif($args[1] -eq "-restart")
    {
        if($args[2] -eq "--help")
        {
            Write-Output " Usage : $ScriptName -srvs -restart [ Service ]"
            
        }

        elseif($null -ne $args[2])
        {
            try 
            {
                Stop-Service -Name $args[2]
                Start-Service -Name $args[2]
                SFWrite $SUCCESS "Restarted Successfully : ", $args[2]
            }
            catch [Microsoft.PowerShell.Commands.ServiceCommandException] 
            {
                SFWrite $FAILED "Failed to Restart Service : ", $args[2]
            }
        }

        else
        {
            SFWrite $FAILED "Type '$ScriptName -srvs -restart --help'"
        }
    }

    else
    {
        SFWrite $FAILED "Type '$ScriptName -srvs --help'"
    }
}

else 
{
    SFWrite $FAILED "Type '$ScriptName --help'"
}
