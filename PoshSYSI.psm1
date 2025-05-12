function Invoke-Decode {
    <#
    .SYNOPSIS
        Decodes an array of ASCII values to a string.
    .DESCRIPTION
        This function takes an array of byte values (presumably ASCII) and converts them into a readable string.
        It is typically used for decoding certain WMI property values.
    .PARAMETER Data
        An array of byte values to be decoded.
    .EXAMPLE
        Invoke-Decode $Monitor.ManufacturerName
        Decodes the manufacturer name byte array from a WMI monitor object.
    #>
    param (
        [Parameter(Mandatory=$false, Position=0)]
        [object]$Data
    )
    If ($Data -is [System.Array]) {
        [System.Text.Encoding]::ASCII.GetString($Data)
    }
    Else {
        "No results!"
    }
}

# "Basic" system info
function Get-SYSISystemInfo {
    <#
    .SYNOPSIS
        Retrieves and displays basic system information.
    .DESCRIPTION
        Collects and shows fundamental system details like computer name, current user, model, and OS installation date.
        It also stores this information in the $Script:PoshSYSIData.System object.
    .PARAMETER SystemInfo
        A CIM instance object containing system information (e.g., from Win32_ComputerSystem).
    .PARAMETER SystemInstallDateInfo
        The installation date of the operating system.
    .EXAMPLE
        Get-SYSISystemInfo $ComputerSystem $ComputerSystemInstallDate
        Displays and stores system information.
    #>
    param (
        [Parameter(Mandatory=$true)]$SystemInfo,
        [Parameter(Mandatory=$true)]$SystemInstallDateInfo
    )
    $temp = [PSCustomObject]@{
        Name        = $SystemInfo.Name
        User        = ($SystemInfo.UserName).Replace("$($env:COMPUTERNAME)\","")
        Model       = $SystemInfo.Model
        InstallDate = $SystemInstallDateInfo
    }
    $Script:PoshSYSIData.System = $temp
    Write-Host "Name:" $SystemInfo.Name
    Write-Host "User:" ($SystemInfo.UserName).Replace("$($env:COMPUTERNAME)\","")
    Write-Host "Model:" $SystemInfo.Model
    Write-Host "Install (approx):" $SystemInstallDateInfo -ForegroundColor Yellow
}

# Bios info
function Get-SYSIBiosInfo {
    <#
    .SYNOPSIS
        Retrieves and displays BIOS information.
    .DESCRIPTION
        Collects and shows BIOS details such as firmware type, version, and serial number.
        It also stores this information in the $Script:PoshSYSIData.Bios object.
    .PARAMETER BiosInfo
        A CIM instance object containing BIOS information (e.g., from Win32_Bios).
    .PARAMETER BiosType
        An object containing BIOS firmware type information (e.g., from Get-ComputerInfo).
    .EXAMPLE
        Get-SYSIBiosInfo $Bios $WinVersionObject
        Displays and stores BIOS information.
    #>
    param (
        [Parameter(Mandatory=$true)]$BiosInfo,
        [Parameter(Mandatory=$true)]$BiosType
    )
    $temp = [PSCustomObject]@{
        Type    = $BiosType.BiosFirmwareType
        Version = $BiosInfo.SMBIOSBIOSVersion
        SN      = $BiosInfo.SerialNumber
    }
    $Script:PoshSYSIData.Bios = $temp
    Write-Host "Type:" $BiosType.BiosFirmwareType
    Write-Host "Version:" $BiosInfo.SMBIOSBIOSVersion
    Write-Host "S/N:" $BiosInfo.SerialNumber
}

# BitLocker status
function Get-SYSIBLStatus {
    <#
    .SYNOPSIS
        Displays a human-readable BitLocker status.
    .DESCRIPTION
        Translates a numerical BitLocker protection status code into a descriptive string with color coding.
    .PARAMETER BLStatus
        The numerical BitLocker protection status code.
        (e.g., 0 = Off, 1 = On, 2 = Encryption in Progress, etc.)
    .EXAMPLE
        Get-SYSIBLStatus $BitLockerStatusCode
        Displays the BitLocker status in a user-friendly format.
    #>
    param (
        [Parameter(Mandatory=$true)]$BLStatus
    )
    switch ($BLStatus) {
        1 { Write-Host -ForegroundColor DarkGreen "BitLocker on (Encrypted)"; break }
        2 { Write-Host -ForegroundColor DarkRed "BitLocker off (Decrypted)"; break }
        3 { Write-Host -ForegroundColor Yellow "Encryption In Progress/Paused"; break }
        4 { Write-Host -ForegroundColor Red "Decryption In Progress/Paused"; break }
        5 { Write-Host -ForegroundColor Yellow "BitLocker suspended (Encrypted)"; break }
        6 { Write-Host -ForegroundColor DarkRed "BitLocker on (Locked)"; break }
        8 { Write-Host -ForegroundColor Magenta "BitLocker waiting for activation (Encrypted)"; break }
        Default { Write-Host -ForegroundColor DarkRed "Unknown value"; break }
    }
}

# BitLocker info
function Get-SYSIBitLockerInfo {
    <#
    .SYNOPSIS
        Retrieves and displays BitLocker information for the C: drive.
    .DESCRIPTION
        Gets the BitLocker protection status for the C: drive and displays it using Get-SYSIBLStatus.
        It also stores the raw status in $Script:PoshSYSIData.BitLocker.
    .PARAMETER BitLockerStatus
        The BitLocker protection status for the C: drive.
    .EXAMPLE
        Get-SYSIBitLockerInfo $BLStatusValue
        Displays and stores BitLocker status for C:.
    #>
    param (
        [Parameter(Mandatory=$true)]$BitLockerStatus
    )
    $Script:PoshSYSIData.BitLocker = $BitLockerStatus
    Get-SYSIBLStatus $BitLockerStatus
}

# Processor info
function Get-SYSIProcessorInfo {
    <#
    .SYNOPSIS
        Retrieves and displays processor information.
    .DESCRIPTION
        Collects and shows CPU details like manufacturer, socket, model, number of cores, and logical processors.
        It also stores this information in the $Script:PoshSYSIData.Processor object.
    .PARAMETER ProcessorInfo
        A CIM instance object containing processor information (e.g., from Win32_Processor).
    .EXAMPLE
        Get-SYSIProcessorInfo $ProcessorObject
        Displays and stores processor information.
    #>
    param (
        [Parameter(Mandatory=$true)]$ProcessorInfo
    )
    $temp = [PSCustomObject]@{
        Manufacturer = $ProcessorInfo.Manufacturer
        Socket       = $ProcessorInfo.SocketDesignation
        Model        = $ProcessorInfo.Name
        Cores        = $ProcessorInfo.NumberOfCores
        LogicalCores = $ProcessorInfo.NumberOfLogicalProcessors
    }
    $Script:PoshSYSIData.Processor = $temp
    Write-Host "Manufacturer:" $ProcessorInfo.Manufacturer
    Write-Host "Socket:" $ProcessorInfo.SocketDesignation
    Write-Host "Model:" $ProcessorInfo.Name
    Write-Host "C/LC:" $ProcessorInfo.NumberOfCores "/" $ProcessorInfo.NumberOfLogicalProcessors
}

# Memory info
function Get-SYSIMemoryInfo {
    <#
    .SYNOPSIS
        Retrieves and displays physical memory information.
    .DESCRIPTION
        Collects and shows details about physical memory modules, including total capacity, manufacturer, part number, and serial number.
        It also stores this information in the $Script:PoshSYSIData.Memory object.
    .PARAMETER MemoryInfo
        A CIM instance object (or array of objects) containing physical memory details (e.g., from Win32_PhysicalMemory).
        The function primarily uses the first object for manufacturer, P/N, S/N if multiple are present.
    .PARAMETER MemoryInfoCap
        The total physical memory capacity in GB.
    .EXAMPLE
        Get-SYSIMemoryInfo $PhysicalMemoryObjects $TotalMemoryCapacityGB
        Displays and stores memory information.
    #>
    param (
        [Parameter(Mandatory=$true)]$MemoryInfo,
        [Parameter(Mandatory=$true)]$MemoryInfoCap
    )
    $temp = [PSCustomObject]@{
        Available  = $MemoryInfoCap
        Manufacturer = $MemoryInfo.Manufacturer
        PartNumber   = $MemoryInfo.PartNumber
        SerialNumber = $MemoryInfo.SerialNumber
    }
    $Script:PoshSYSIData.Memory = $temp
    Write-Host "Available:" $MemoryInfoCap "GB"
    Write-Host "Manufacturer:" $MemoryInfo.Manufacturer
    Write-Host "P/N:" $MemoryInfo.PartNumber
    Write-Host "S/N:" $MemoryInfo.SerialNumber
}

# Attached monitors
function Get-SYSIMonitors {
    <#
    .SYNOPSIS
        Retrieves and displays information about attached monitors.
    .DESCRIPTION
        Collects and shows details for each attached monitor, including manufacturer, model name, product code ID, serial number, and year of manufacture.
        Decoded values are stored in the $Script:PoshSYSIData.Monitors list.
    .PARAMETER Monitors
        An array of CIM instance objects containing monitor information (e.g., from WmiMonitorID).
    .EXAMPLE
        Get-SYSIMonitors $MonitorWMIObjects
        Displays and stores information for all attached monitors.
    #>
    param (
        [Parameter(Mandatory=$true)]$Monitors
    )
    ForEach ($Monitor in $Monitors) {
        $MonitorManufacturer = Invoke-Decode $Monitor.ManufacturerName
        $MonitorModel = Invoke-Decode $Monitor.UserFriendlyName
        $MonitorPCID = Invoke-Decode $Monitor.ProductCodeID
        $MonitorSerial = Invoke-Decode $Monitor.SerialNumberID
        $MonitorYoM = Invoke-Decode $Monitor.YearOfManufacture
        $temp = [PSCustomObject]@{
            Manufacturer = $MonitorManufacturer
            Name         = $MonitorModel
            PCID         = $MonitorPCID
            Serial       = $MonitorSerial
            Year         = $MonitorYoM
        }
        $Script:PoshSYSIData.Monitors.Add($temp)
        Write-Host "Manufacturer:" $MonitorManufacturer "`nName:" $MonitorModel "`nPCID:" $MonitorPCID "`nS/N:" $MonitorSerial "`nYoM:" $MonitorYoM "`n"
    }
}

# Disk Info (C:\)
function Get-SYSIDiskCInfo {
    <#
    .SYNOPSIS
        Retrieves and displays disk information for the C: drive.
    .DESCRIPTION
        Collects and shows capacity and free space for the C: drive in GB.
        It also stores this information in the $Script:PoshSYSIData.Disk object.
    .PARAMETER DiskCInfo
        A CIM instance object containing logical disk information for the C: drive (e.g., from Win32_LogicalDisk where DeviceID='C:').
    .EXAMPLE
        Get-SYSIDiskCInfo $DiskCObject
        Displays and stores C: drive disk information.
    #>
    param (
        [Parameter(Mandatory=$true)]$DiskCInfo
    )
    $Capacity = "{0:N2}" -f ($DiskCInfo.Size /1GB)
    $Free = "{0:N2}" -f ($DiskCInfo.FreeSpace /1GB)
    $temp = [PSCustomObject]@{
        CapacityGB = $Capacity
        FreeGB     = $Free
    }
    $Script:PoshSYSIData.Disk = $temp
    Write-Host "Capacity:" $Capacity "GB"
    Write-Host "Free:" $Free "GB"
}

# Windows license status
function Get-SYSILicenseStatus {
    <#
    .SYNOPSIS
        Displays a human-readable Windows license status.
    .DESCRIPTION
        Translates a numerical Windows license status code into a descriptive string with color coding.
    .PARAMETER WLStatus
        The numerical Windows license status code.
    .EXAMPLE
        Get-SYSILicenseStatus $WindowsLicenseStatusCode
        Displays the Windows license status in a user-friendly format.
    #>
    param (
        [Parameter(Mandatory=$true)]$WLStatus
    )
    switch ($WLStatus) {
        0 { Write-Host -ForegroundColor DarkRed "Unlicensed"; break }
        1 { Write-Host -ForegroundColor DarkGreen "Licensed"; break }
        2 { Write-Host -ForegroundColor Magenta "OOBGrace (Out-Of-Box Grace Period)"; break }
        3 { Write-Host -ForegroundColor Magenta "OOTGrace (Out-Of-Tolerance Grace Period)"; break }
        4 { Write-Host -ForegroundColor Magenta "Non-Genuine Grace Period"; break }
        5 { Write-Host -ForegroundColor Magenta "Notification"; break }
        6 { Write-Host -ForegroundColor Magenta "Extended Grace"; break }
        Default { Write-Host -ForegroundColor DarkRed "Unknown value"; break }
    }
}

# Windows info
function Get-SYSIWindowsInfo {
    <#
    .SYNOPSIS
        Retrieves and displays Windows operating system information.
    .DESCRIPTION
        Collects and shows OS details like architecture, product name, version, build number, and license status.
        It also stores this information in the $Script:PoshSYSIData.Windows object.
    .PARAMETER WindowsInfo
        An object containing Windows OS information (e.g., from Get-ComputerInfo).
    .PARAMETER WindowsLicInfo
        The Windows license status code.
    .EXAMPLE
        Get-SYSIWindowsInfo $OSInfoObject $LicenseStatus
        Displays and stores Windows OS information.
    #>
    param (
        [Parameter(Mandatory=$true)]$WindowsInfo,
        [Parameter(Mandatory=$true)]$WindowsLicInfo
    )
    $temp = [PSCustomObject]@{
        Architecture = $WindowsInfo.OsArchitecture
        ProductName  = $WindowsInfo.OsName
        Version      = $WindowsInfo.WindowsVersion
        Build        = $WindowsInfo.OsBuildNumber
        LicenseStatus= $WindowsLicInfo
    }
    $Script:PoshSYSIData.Windows = $temp
    Write-Host "Architecture:" $WindowsInfo.OsArchitecture
    Write-Host "Product name:" $WindowsInfo.OsName
    Write-Host "Version:" $WindowsInfo.WindowsVersion
    Write-Host "Build:" $WindowsInfo.OsBuildNumber
    Get-SYSILicenseStatus $WindowsLicInfo
}

# Installed programs (x64 + x86)
function Get-SYSIInstalledProgs {
    <#
    .SYNOPSIS
        Retrieves and displays a list of installed programs.
    .DESCRIPTION
        Queries the registry for installed programs (both 32-bit and 64-bit applications) and displays their names and versions.
        The list is sorted by display name and stored in $Script:PoshSYSIData.InstalledPrograms.
    .EXAMPLE
        Get-SYSIInstalledProgs
        Displays and stores a list of installed programs.
    #>
    try {
        $InstalledPrograms = @()
        $InstalledPrograms += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion
        $InstalledPrograms += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion
        
        $FilteredPrograms = $InstalledPrograms | Where-Object { $_.DisplayName } | Sort-Object -Property DisplayName
        
        $FilteredPrograms | Format-Table -HideTableHeaders -Wrap
        
        foreach ($prog in $FilteredPrograms) {
            $Script:PoshSYSIData.InstalledPrograms.Add($prog)
        }
    } catch {
        Write-Error "Error retrieving installed programs: $($_.Exception.Message)"
    }
}

# Modes functions
function Invoke-SYSIMinimal {
    <#
    .SYNOPSIS
        Invokes the minimal set of system information gathering functions.
    .DESCRIPTION
        Calls functions to get basic system, BIOS, processor, and memory information.
        This corresponds to the 'Minimal' PoshSYSIMode.
    .PARAMETER ComputerSystem
        A CIM instance object containing system information (e.g., from Win32_ComputerSystem).
    .PARAMETER ComputerSystemInstall
        The installation date of the operating system.
    .PARAMETER Bios
        A CIM instance object containing BIOS information (e.g., from Win32_Bios).
    .PARAMETER WinVersion
        An object containing OS and BIOS firmware type information (e.g., from Get-ComputerInfo).
    .PARAMETER Processor
        A CIM instance object containing processor information (e.g., from Win32_Processor).
    .PARAMETER PhysicalMemory
        A CIM instance object (or array) for physical memory (e.g., from Win32_PhysicalMemory).
    .PARAMETER PhysicalMemoryCap
        Total physical memory capacity in GB.
    .EXAMPLE
        Invoke-SYSIMinimal -ComputerSystem $cs -ComputerSystemInstall $csi -Bios $bios -WinVersion $wv -Processor $proc -PhysicalMemory $pm -PhysicalMemoryCap $pmc
        Gathers and displays minimal system information.
    #>
    param(
        [Parameter(Mandatory=$true)]$ComputerSystem,
        [Parameter(Mandatory=$true)]$ComputerSystemInstall,
        [Parameter(Mandatory=$true)]$Bios,
        [Parameter(Mandatory=$true)]$WinVersion,
        [Parameter(Mandatory=$true)]$Processor,
        [Parameter(Mandatory=$true)]$PhysicalMemory,
        [Parameter(Mandatory=$true)]$PhysicalMemoryCap
    )
    # System
    Write-Host -ForegroundColor Cyan ">> System"
    Get-SYSISystemInfo $ComputerSystem $ComputerSystemInstall

    # Bios
    Write-Host -ForegroundColor Cyan "`n>> Bios"
    Get-SYSIBiosInfo $Bios $WinVersion

    # Processor
    Write-Host -ForegroundColor Cyan "`n>> Processor"
    Get-SYSIProcessorInfo $Processor

    # Memory
    Write-Host -ForegroundColor Cyan "`n>> Memory"
    Get-SYSIMemoryInfo $PhysicalMemory $PhysicalMemoryCap
}

function Invoke-SYSINormal {
    <#
    .SYNOPSIS
        Invokes an additional set of system information gathering functions for 'Normal' mode.
    .DESCRIPTION
        Calls functions to get BitLocker status, C: drive storage, monitor details, and Windows OS information.
        This is typically called after Invoke-SYSIMinimal for the 'Normal' PoshSYSIMode.
    .PARAMETER BitLockerStatus
        The BitLocker protection status for the C: drive.
    .PARAMETER DiskC
        A CIM instance object for the C: drive (e.g., from Win32_LogicalDisk).
    .PARAMETER Monitors
        An array of CIM instance objects for monitors (e.g., from WmiMonitorID).
    .PARAMETER WinVersion
        An object containing OS information (e.g., from Get-ComputerInfo).
    .PARAMETER WinLicenseStatus
        The Windows license status code.
    .EXAMPLE
        Invoke-SYSINormal -BitLockerStatus $bls -DiskC $dc -Monitors $mon -WinVersion $wv -WinLicenseStatus $wls
        Gathers and displays 'Normal' level system information.
    #>
    param(
        [Parameter(Mandatory=$true)]$BitLockerStatus,
        [Parameter(Mandatory=$true)]$DiskC,
        [Parameter(Mandatory=$true)]$Monitors,
        [Parameter(Mandatory=$true)]$WinVersion,
        [Parameter(Mandatory=$true)]$WinLicenseStatus
    )
    # BitLocker
    Write-Host -ForegroundColor Cyan "`n>> BitLocker (C:\)"
    Get-SYSIBitLockerInfo $BitLockerStatus

    # Storage
    Write-Host -ForegroundColor Cyan "`n>> Storage (C:\)"
    Get-SYSIDiskCInfo $DiskC

    # Monitor
    Write-Host -ForegroundColor Cyan "`n>> Monitor(s)"
    Get-SYSIMonitors $Monitors

    # Windows
    Write-Host -ForegroundColor Cyan "`n>> Windows"
    Get-SYSIWindowsInfo $WinVersion $WinLicenseStatus
}

function Invoke-SYSIFull {
    <#
    .SYNOPSIS
        Invokes functions to gather all system information, including installed programs.
    .DESCRIPTION
        Calls the function to get a list of installed programs.
        This is typically called after Invoke-SYSINormal for the 'Full' PoshSYSIMode.
    .EXAMPLE
        Invoke-SYSIFull
        Gathers and displays installed programs information.
    #>
    Write-Host -ForegroundColor Cyan "`n>> Installed programs"
    Get-SYSIInstalledProgs
}

function Get-PoshSYSI {
    <#
    .SYNOPSIS
        Retrieves system information from local or remote computers.

    .DESCRIPTION
        Get-PoshSYSI retrieves detailed system information including hardware, 
        operating system, and installed software from local or remote computers.

    .PARAMETER ComputerName
        Specifies the remote computers to retrieve information from. Used with -PoshSYSIRunMode Remote.

    .PARAMETER PoshSYSIMode
        Specifies the level of detail for system information.
        Minimal: Basic system info (System, BIOS, Processor, Memory).
        Normal: Minimal info plus BitLocker (C:\), Storage (C:\), Monitor(s), Windows OS details. (Default)
        Full: Normal info plus a list of installed programs.

    .PARAMETER PoshSYSIRunMode
        Specifies whether to run the command locally or remotely.
        Local: Gathers information from the local machine.
        Remote: Gathers information from computers specified by -ComputerName.

    .PARAMETER Report
        If specified as $true, outputs the console display to a log file.
        Defaults to $false (no log file generated).

    .PARAMETER ReportPath
        Specifies the directory path where the report log files will be saved.
        Defaults to "C:\Temp\PoshSYSI\" if not specified. This parameter is only used if -Report is $true.

    .EXAMPLE
        Get-PoshSYSI -PoshSYSIRunMode Local -PoshSYSIMode Minimal
        Retrieves minimal system information from the local computer and displays it to the console.

    .EXAMPLE
        Get-PoshSYSI -ComputerName "Server01", "Workstation05" -PoshSYSIMode Full -PoshSYSIRunMode Remote -Report $true
        Retrieves full system information from Server01 and Workstation05, displays it to the console, and saves the output to log files in the default path.

    .EXAMPLE
        Get-PoshSYSI -PoshSYSIRunMode Local -Report $true -ReportPath "C:\PoshSYSIReports\"
        Retrieves system information from the local computer and saves the report to "C:\PoshSYSIReports\".

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a PSCustomObject ($Script:PoshSYSIData) containing all collected information.
        The console output is for display purposes; the object contains the structured data.
    #>
    [CmdletBinding(DefaultParameterSetName = 'LOCAL')]
    param (
        [Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true,ParameterSetName="REMOTE")]
        [ValidateNotNullOrEmpty()]
        [Alias("CN","MachineName")]
        [String[]]$ComputerName,
        [Parameter(Position=0,ParameterSetName="LOCAL")]
        [Parameter(Position=1,ParameterSetName="REMOTE")]
        [ValidateSet("Minimal", "Normal", "Full")]
        [String]$PoshSYSIMode = "Normal",
        [Parameter(Mandatory=$true,Position=1,ParameterSetName="LOCAL")]
        [Parameter(Mandatory=$true,Position=2,ParameterSetName="REMOTE")]
        [ValidateSet("Local", "Remote")]
        [String]$PoshSYSIRunMode,
        [Parameter(Mandatory=$false,Position=2,ParameterSetName="LOCAL")]
        [Parameter(Mandatory=$false,Position=3,ParameterSetName="REMOTE")]
        [bool]$Report = $false,
        [Parameter(Mandatory=$false,Position=3,ParameterSetName="LOCAL")]
        [Parameter(Mandatory=$false,Position=4,ParameterSetName="REMOTE")]
        [string]$ReportPath = "C:\Temp\PoshSYSI\"
    )

    # Report variables
    $PoshSYSIRunTime = (Get-Date).ToString('yyyy-MM-dd-HH-mm-ss')

    # Ensure ReportPath ends with a backslash if it's a directory
    if ($Report -and $ReportPath -and !(Test-Path -PathType Leaf -Path $ReportPath) -and !($ReportPath.EndsWith('\'))) {
        $ReportPath = Join-Path -Path $ReportPath -ChildPath '\'
    }

    # Script-level PSCustomObject for report details
    $Script:PoshSYSIData = [PSCustomObject]@{
        System           = $null
        Bios             = $null
        Processor        = $null
        Memory           = $null
        Disk             = $null
        Windows          = $null
        BitLocker        = $null
        Monitors         = [System.Collections.Generic.List[PSObject]]::new()
        InstalledPrograms= [System.Collections.Generic.List[PSObject]]::new()
    }

    # Invoke mode function
    function Invoke-SYSIMode {
        <#
        .SYNOPSIS
            Internal helper function to orchestrate information gathering based on PoshSYSIMode.
        .DESCRIPTION
            This function is not intended for direct external use. It calls the appropriate Invoke-SYSIMinimal, 
            Invoke-SYSINormal, and Invoke-SYSIFull functions based on the $PoshSYSIMode parameter of Get-PoshSYSI.
            It uses variables from the Get-PoshSYSI scope (e.g., $ComputerSystem, $Bios, etc.).
        #>
        switch ($PoshSYSIMode)
            {
                'Minimal' {
                    Write-Verbose "Mode: Minimal"
                    Invoke-SYSIMinimal -ComputerSystem $ComputerSystem -ComputerSystemInstall $ComputerSystemInstall -Bios $Bios -WinVersion $WinVersion -Processor $Processor -PhysicalMemory $PhysicalMemory -PhysicalMemoryCap $PhysicalMemoryCap
                }
                'Normal' {
                    Write-Verbose "Mode: Normal"
                    Invoke-SYSIMinimal -ComputerSystem $ComputerSystem -ComputerSystemInstall $ComputerSystemInstall -Bios $Bios -WinVersion $WinVersion -Processor $Processor -PhysicalMemory $PhysicalMemory -PhysicalMemoryCap $PhysicalMemoryCap
                    Invoke-SYSINormal -BitLockerStatus $BitLockerStatus -DiskC $DiskC -Monitors $Monitors -WinVersion $WinVersion -WinLicenseStatus $WinLicenseStatus
                }
                'Full' {
                    Write-Verbose "Mode: Full"
                    Invoke-SYSIMinimal -ComputerSystem $ComputerSystem -ComputerSystemInstall $ComputerSystemInstall -Bios $Bios -WinVersion $WinVersion -Processor $Processor -PhysicalMemory $PhysicalMemory -PhysicalMemoryCap $PhysicalMemoryCap
                    Invoke-SYSINormal -BitLockerStatus $BitLockerStatus -DiskC $DiskC -Monitors $Monitors -WinVersion $WinVersion -WinLicenseStatus $WinLicenseStatus
                    Invoke-SYSIFull
                }
            }
    }

    # RunMode
    switch ($PoshSYSIRunMode)
    {
        'Local' {
            Write-Verbose "RunMode: Local"
            try {
                $Bios = Get-CimInstance -ClassName Win32_Bios
            } catch {
                Write-Error "Error retrieving BIOS info: $($_.Exception.Message)"
            }
            try {
                $BitLockerStatus = (New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')
            } catch {
                Write-Error "Error retrieving BitLocker status: $($_.Exception.Message)"
            }
            try {
                $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
                $ComputerSystemInstall = (Get-ChildItem -Path "C:\Windows\debug\NetSetup.LOG" | Select-Object CreationTime).CreationTime
                $DiskC = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
                $Monitors = Get-CimInstance -ClassName WmiMonitorID -Namespace root\wmi
                $PhysicalMemory = Get-CimInstance -ClassName Win32_PhysicalMemory
                $PhysicalMemoryCap = ($PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum/1GB
                $Processor = Get-CimInstance -ClassName Win32_Processor
                $WinLicenseStatus = (Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "Name like 'Windows%'" | Where-Object { $_.PartialProductKey } | Select-Object LicenseStatus).LicenseStatus
                $WinVersion = Get-ComputerInfo
            } catch {
                Write-Error "Error retrieving system info: $($_.Exception.Message)"
            }

            # Generate report if -Report:$true
            if ($Report) {
                If(!(Test-Path -Path $ReportPath)){
                    New-Item -ItemType Directory -Force -Path $ReportPath | Out-Null
                }
                Invoke-SYSIMode *> (Join-Path -Path $ReportPath -ChildPath "PoshSYSI_Local_$($PoshSYSIRunTime).log")
            } else {
                Invoke-SYSIMode
            }
        }
        'Remote' {
            Write-Verbose "RunMode: Remote"
            if ($Report) { # Create directory once if reporting for remote hosts
                If(!(Test-Path -Path $ReportPath)){
                    New-Item -ItemType Directory -Force -Path $ReportPath | Out-Null
                }
            }
            foreach ($ComputerItem in $ComputerName) {
                if (Test-Connection -ComputerName $ComputerItem -Quiet -Count 1) {
                    Write-Host "`n$($ComputerItem)" -BackgroundColor DarkGreen -ForegroundColor White
                    try {
                        $Bios = Get-CimInstance -ClassName Win32_Bios -ComputerName $ComputerItem
                        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerItem
                        $ComputerSystemInstall = (Invoke-Command -ComputerName $ComputerItem -ScriptBlock { (Get-ChildItem -Path "C:\Windows\debug\NetSetup.LOG" | Select-Object CreationTime).CreationTime })
                        $DiskC = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ComputerName $ComputerItem
                        $Monitors = Get-CimInstance -ClassName WmiMonitorID -Namespace root\wmi -ComputerName $ComputerItem
                        $PhysicalMemory = Get-CimInstance -ClassName Win32_PhysicalMemory -ComputerName $ComputerItem
                        $PhysicalMemoryCap = ($PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum/1GB
                        $Processor = Get-CimInstance -ClassName Win32_Processor -ComputerName $ComputerItem
                        $WinLicenseStatus = (Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "Name like 'Windows%'" -ComputerName $ComputerItem | Where-Object { $_.PartialProductKey } | Select-Object LicenseStatus).LicenseStatus
                        $WinVersion = (Invoke-Command -ComputerName $ComputerItem -ScriptBlock { Get-ComputerInfo })
                    } catch {
                        Write-Error "Error retrieving info from $($ComputerItem): $($_.Exception.Message)"
                    }

                    # Generate report if -Report:$true
                    if ($Report) {
                        # Directory is already ensured to exist if $Report is true (created before loop)
                        Invoke-SYSIMode *> (Join-Path -Path $ReportPath -ChildPath "$($ComputerItem)_PoshSYSI_Remote_$($PoshSYSIRunTime).log")
                    } else {
                        Invoke-SYSIMode
                    }
                } else {
                    Write-Host "`n$($ComputerItem) not reachable!" -BackgroundColor DarkRed -ForegroundColor White
                }
            }
        }
    }

    Write-Output $Script:PoshSYSIData
}
