
<#
[Program Information]
Name   : Win32 Task Manager
Date   : 2019-02-18
Author : kdr(김경민)
#>

$ScriptName = "Win32tmgr"
$SUCCESS = "SUCCESS"
$FAILED = "FAILED"
$Startup = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

$ErrorActionPreference = "Stop"

function SFWrite([string]$STATUS, [string]$CSTRING) 
{
    if($STATUS -eq $SUCCESS)
    {
        Write-Host "`n[+] " -ForegroundColor Blue -NoNewline
        Write-Host "$CSTRING `n" -ForegroundColor Yellow
    }

    if($STATUS -eq $FAILED)
    {
        Write-Host "`n[-] " -ForegroundColor Red -NoNewline
        Write-Host "$CSTRING `n" -ForegroundColor Yellow
    }
}

function OPTWrite([string]$CSTRING) 
{
    Write-Host "$CSTRING" -ForegroundColor Cyan
}

function Cwrite([string]$CSTRING, [string]$COLOR)
{
    Write-Host "$CSTRING" -ForegroundColor $COLOR -NoNewline
}

Write-Output "
     _ _ _  _       ___  ___      
    | | | ||_| ___ |_  ||_  |                   
    | | | || ||   ||_  ||  _|     
    |_____||_||_|_||___||___|     
    _____  _____  _____  _____    
   |_   _||     ||   __|| __  |   
     | |  | | | ||  |  ||    -|   
     |_|  |_|_|_||_____||__|__|  
        Win32 Task Manager   `n`n" 



if($args[0] -eq "--help")
{
    OPTWrite " Usage : $ScriptName [Option] `n"
    OPTWrite "  -proc : Processes             "
    OPTWrite "  -perf : Performance           "
    OPTWrite "  -apps : App History           "
    OPTWrite "  -stup : Startup               "
    OPTWrite "  -usrs : Users                 "
    OPTWrite "  -dets : Details               "
    OPTWrite "  -srvs : Services            `n"
}

elseif($args[0] -eq "-proc")
{
    if($args[1] -eq "--help")
    {
        OPTWrite " Usage : $ScriptName -proc [Option]                                    `n"
        OPTWrite "  -show  [ -apps | -srvs | -all ]                 : Show Processes List  "
        OPTWrite "  -start [ -admin ] [ Process ]                   : Start Process        "
        OPTWrite "  -kill  [ -pid ProcessID | -pname ProcessName ]  : Kill Process       `n"
    }

    elseif($args[1] -eq "-show")
    {

        if($args[2] -eq "--help")
        {
            OPTWrite " Usage : $ScriptName -proc -show [Option]  `n"
            OPTWrite "  -apps : Show Applications Process          "
            OPTWrite "  -srvs : Show Services Process              "
            OPTWrite "  -all  : Show All Process                 `n"
        }

        elseif($args[2] -eq "-apps")
        {
            Cwrite` "[Applications Process]" Red
            Get-Process
        }

        elseif($args[2] -eq "-srvs")
        {
            Cwrite "[Services Process]" Red
            Get-Service
        }

        elseif($args[2] -eq "-all")
        {
            Cwrite "`n[Applications Process]" Red
            Get-Process
            Cwrite "`n[Services Process]" Red
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
            OPTWrite " Usage : $ScriptName -proc -start [Option] [ Process ]         `n"
            OPTWrite "  -admin : Start Process as Administrator                        "
            OPTWrite "   If you don't use -admin Option, Process will start with User`n"
        }

        elseif($args[2] -eq "-admin")
        {
            if($args[3] -eq "--help")
            {
                OPTWrite " Usage : $ScriptName -proc -start -admin [ Process ]`n"
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
            OPTWrite " Usage : $ScriptName -proc -kill [Option]               `n"
            OPTWrite "  -pid [ ProcessID ]     : Kill Process with ProcessID    "
            OPTWrite "  -pname [ ProcessName ] : Kill Process with ProcessName`n"
        }

        elseif($args[2] -eq "-pid")
        {
            if($args[3] -eq "--help")
            {
                OPTWrite " Usage : $ScriptName -proc -kill -pid [ ProcessID ]`n"
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
                OPTWrite "Usage : $ScriptName -proc -kill -pname [ ProcessName ]`n"
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
        OPTWrite " Usage : $ScriptName -perf [Option]`n"
        OPTWrite "  -cpu  : Show CPU Info, Status      "
        OPTWrite "  -mem  : Show Memory Info, Status   "
        OPTWrite "  -disk : Show Disk Info, Status     "
        OPTWrite "  -net  : Show Network Info, Status  "
        OPTWrite "  -gpu  : Show GPU Info, Status    `n"
    }

    elseif($args[1] -eq "-cpu")
    {
        Cwrite "[CPU Information]" Red
        Get-WmiObject -Class Win32_Processor
        Cwrite "[CPU Percentaeg]" Red
        Get-WmiObject Win32_Processor | 
        Select-Object LoadPercentage
    }

    elseif($args[1] -eq "-mem")
    {
        Cwrite "`n[Memory Information]"
        Get-WmiObject -Class win32_physicalmemory | 
        Format-Table Manufacturer,Banklabel,Configuredclockspeed,
        Devicelocator,Capacity,Serialnumber -autosize
        
        Cwrite "`n[Total Physical Memory (GB)]" Red
        Get-CimInstance -Class Win32_ComputerSystem |
        ForEach-Object {$_.TotalPhysicalMemory / 1GB}

        Cwrite "`n[Free Physical Memory (GB)]" Red
        Get-WmiObject -Class Win32_OperatingSystem |
        ForEach-Object {$_.FreePhysicalMemory / 1MB}
    }

    elseif($args[1] -eq "-disk")
    {
        Cwrite "`n[Disk Information]" Red
        Get-WmiObject -Class Win32_LogicalDisk | 
        Select-Object -Property DeviceID, DriveType, VolumeName, 
        @{L='FreeSpace(GB)';E={"{0:N2}" -f ($_.FreeSpace / 1GB)}},
        @{L="TotalDiskSpace(GB)";E={"{0:N2}" -f ($_.Size/ 1GB)}}

        Cwrite "[Disk Percentage]`n" Red 
        (Get-Counter -Counter "\physicaldisk(_total)\% disk time").CounterSamples.CookedValue
    }

    elseif($args[1] -eq "-net")
    {
        Cwrite "[Network Information]" Red
        Get-WmiObject -Class Win32_NetworkAdapter |
        Where-Object {($_.Speed -ne $null) -and ($_.MACAddress -ne $null)} |
        Format-Table -Property SystemName, Name, NetConnectionID, Speed
    }

    elseif($args[1] -eq "-gpu")
    {
        Cwrite "[GPU Information]" Red
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
    Cwrite "[ CPU Time ]`n" Red
    Get-Counter '\Processor(*)\% Processor Time'

    Cwrite "[ All Network ]`n" Red
    Get-NetAdapterStatistics
}

elseif($args[0] -eq "-stup")
{
    if($args[1] -eq "--help")
    {
        OPTWrite " Usage : $ScriptName -stup [Option]      `n"
        OPTWrite "  -show          : Show Startup Program    "
        OPTWrite "  -add  [ Path ] : Add Startup Program     "
        OPTWrite "  -del  [ Path ] : Delete Startup Program`n"
    }

    elseif($args[1] -eq "-show")
    {
        Get-ItemProperty -Path $Startup
    }

    elseif($args[1] -eq "-add")
    {
        if($args[2] -eq "--help")
        {
            OPTWrite " Usage : $ScriptName -stup -add [ Path ]`n"
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
            OPTWrite " Usage : $ScriptName -stup -del [ Path ]"
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
        OPTWrite " Usage : $ScriptName -usrs [Option]           `n"
        OPTWrite "  -show            : Show Logged on User        "
        OPTWrite "  -en  [ Account ] : Enable User                "
        OPTWrite "  -dis [ Account ] : Disable User             `n"
    }

    elseif($args[1] -eq "-show")
    {
        Cwrite "[ User List ]`n" Red
        Get-LocalUser | Select-Object Name, Enabled
    }

    elseif($args[1] -eq "-en")
    {
        if($args[2] -eq "--help")
        {
            OPTWrite " Usage : $ScriptName -usrs -en [Option] `n"
            OPTWrite "  -en [ Account ]                       `n"
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
            OPTWrite " Usage : $ScriptName -usrs -dis [Option] `n"
            OPTWrite "  -dis [ Account ]                       `n"
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
        OPTWrite " Usage : $ScriptName -srvs [Option]                          `n"
        OPTWrite "  -show    [ -running | -stopped | -all ]  : Show Services     "
        OPTWrite "  -start   [ Service ]                     : Start Service     "
        OPTWrite "  -stop    [ Service ]                     : Stop Service      "
        OPTWrite "  -restart [ Service ]                     : Restart Service `n" 
    }

    elseif($args[1] -eq "-show")
    {
        if($args[2] -eq "--help")
        {
            OPTWrite " Usage : $ScriptName -srvs [Option] `n"
            OPTWrite "  -running : Show Running Services    "
            OPTWrite "  -stopped : Show Stopped Services    " 
            OPTWrite "  -all     : Show All Services      `n"
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
            OPTWrite " Usage : $ScriptName -srvs -start [ Service ]`n"
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
            OPTWrite " Usage : $ScriptName -srvs -stop [ Service ]`n"
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
            OPTWrite " Usage : $ScriptName -srvs -restart [ Service ]"
            
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
