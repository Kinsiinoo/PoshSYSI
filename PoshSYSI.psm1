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
        The current user is derived based on the context of execution (local or remote).
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
        Decoded values are added to the $Script:PoshSYSIData.Monitors list (a System.Collections.Generic.List[PSObject]).
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
        The list is sorted by display name and items are added to the $Script:PoshSYSIData.InstalledPrograms list (a System.Collections.Generic.List[PSObject]).
        Uses an internal error handling helper ($PoshSYSI_ErrorHelper) for more detailed error reporting if issues occur during registry queries.
    .EXAMPLE
        Get-SYSIInstalledProgs
        Displays and stores a list of installed programs.
    #>
    try {
        $InstalledPrograms = @()
        $InstalledPrograms += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction Stop | Select-Object DisplayName, DisplayVersion
        $InstalledPrograms += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction Stop | Select-Object DisplayName, DisplayVersion
        
        $FilteredPrograms = $InstalledPrograms | Where-Object { $_.DisplayName } | Sort-Object -Property DisplayName
        
        $FilteredPrograms | Format-Table -HideTableHeaders -Wrap
        
        foreach ($prog in $FilteredPrograms) {
            $Script:PoshSYSIData.InstalledPrograms.Add($prog)
        }
    } catch {
        Write-Error ($PoshSYSI_ErrorHelper.Invoke($_, "Error retrieving installed programs", $env:COMPUTERNAME))
        Write-Verbose "Detailed error in Get-SYSIInstalledProgs: $($($_) | Format-List * | Out-String)"
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
        If a CimSession is provided (typically in remote scenarios), it attempts to retrieve installed programs from the remote machine.
        Otherwise, it retrieves installed programs from the local machine.
        This is typically called after Invoke-SYSINormal for the 'Full' PoshSYSIMode.
    .PARAMETER CimSession
        An optional CIM session object. If provided, installed programs will be retrieved from the remote machine associated with this session.
    .EXAMPLE
        Invoke-SYSIFull
        Gathers and displays installed programs information locally.
    .EXAMPLE
        Invoke-SYSIFull -CimSession $remoteSession
        Gathers and displays installed programs information from the remote machine associated with $remoteSession.
    #>
    param(
        [Parameter(Mandatory=$false)]
        $CimSession # Added for remote execution
    )
    Write-Host -ForegroundColor Cyan "`n>> Installed programs"
    if ($CimSession) {
        try {
            Write-Verbose "Attempting to retrieve installed programs remotely from $($CimSession.ComputerName)"
            $remotePrograms = Invoke-Command -CimSession $CimSession -ScriptBlock {
                $InstalledProgramsData = [System.Collections.Generic.List[PSObject]]::new()
                $regPaths = @(
                    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                )
                foreach ($path in $regPaths) {
                    try {
                        Get-ItemProperty -Path $path -ErrorAction Stop | ForEach-Object { $InstalledProgramsData.Add($_) }
                    } catch {
                        Write-Warning "Error querying $path on $($env:COMPUTERNAME): $($_.Exception.Message)"
                    }
                }
                $FilteredPrograms = $InstalledProgramsData | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName } | Select-Object DisplayName, DisplayVersion | Sort-Object -Property DisplayName
                $FilteredPrograms | ForEach-Object { [PSCustomObject]$_ }
            } -ErrorAction Stop

            if ($remotePrograms -and $remotePrograms.Count -gt 0) {
                $Script:PoshSYSIData.InstalledPrograms.Clear()
                foreach ($prog in $remotePrograms) {
                    $Script:PoshSYSIData.InstalledPrograms.Add($prog)
                }
                $remotePrograms | Format-Table -HideTableHeaders -Wrap
            } else {
                Write-Host "No installed programs found or retrieved from remote machine $($CimSession.ComputerName)."
            }
        } catch {
            $ErrorMessage = "Failed to retrieve installed programs from remote machine $($CimSession.ComputerName)."
            if ($_.Exception.InnerException) { $ErrorMessage += " Inner Exception: $($_.Exception.InnerException.Message)"}
            Write-Error ($PoshSYSI_ErrorHelper.Invoke($_, $ErrorMessage, $CimSession.ComputerName))
            Write-Verbose "Detailed error for remote Get-SYSIInstalledProgs on $($CimSession.ComputerName): $($($_) | Format-List * | Out-String)"
        }
    } else {
        Get-SYSIInstalledProgs
    }
}

function Get-PoshSYSI {
    <#
    .SYNOPSIS
        Retrieves system information from local or remote computers.

    .DESCRIPTION
        Get-PoshSYSI retrieves detailed system information including hardware, 
        operating system, and installed software from local or remote computers.
        The level of detail is controlled by the PoshSYSIMode parameter.
        Data is fetched conditionally based on the selected mode to improve efficiency.
        For remote operations, it utilizes CIM sessions for efficient data retrieval and robust error handling.
        Specific data points like OS installation date, full OS version details (via Get-ComputerInfo), 
        BitLocker status, and installed programs (in 'Full' mode) on remote machines are gathered using Invoke-Command 
        against the established CIM session.

    .PARAMETER ComputerName
        Specifies the remote computers to retrieve information from. Used with -PoshSYSIRunMode Remote.

    .PARAMETER PoshSYSIMode
        Specifies the level of detail for system information.
        Minimal: Basic system info (System, BIOS, Processor, Memory). Data is fetched only for these components.
        Normal: Minimal info plus BitLocker (C:\), Storage (C:\), Monitor(s), Windows OS details. Data for these is fetched in addition to Minimal. (Default)
        Full: Normal info plus a list of installed programs. Installed programs are fetched in addition to Normal data.

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
        The 'Monitors' and 'InstalledPrograms' properties are of type System.Collections.Generic.List[PSObject].
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

    # Helper function for creating detailed Error Records
    function New-PoshSYSIErrorRecord {
        <#
        .SYNOPSIS
            Internal helper function to create standardized, detailed ErrorRecord objects.
        .DESCRIPTION
            This function takes an original PowerShell error record, a custom message, and a target object string
            to construct a new, more informative ErrorRecord. It's used to provide consistent error feedback
            within PoshSYSI.
        .PARAMETER OriginalErrorRecord
            The original System.Management.Automation.ErrorRecord (typically from a catch block as $_).
        .PARAMETER CustomMessage
            A custom string message to prepend or use as the main message for the new error record.
        .PARAMETER TargetObject
            A string identifying the target of the operation that failed (e.g., computer name, component).
        .OUTPUTS
            System.Management.Automation.ErrorRecord
            A new, detailed ErrorRecord object.
        #>
        param(
            [Parameter(Mandatory=$true)]
            [System.Management.Automation.ErrorRecord]$OriginalErrorRecord,
            [Parameter(Mandatory=$true)]
            [string]$CustomMessage,
            [Parameter(Mandatory=$true)]
            [string]$TargetObject
        )
        $errorDetails = @{
            Message         = $CustomMessage
            Category        = $OriginalErrorRecord.CategoryInfo.Category
            ErrorID         = $OriginalErrorRecord.FullyQualifiedErrorId
            Exception       = $OriginalErrorRecord.Exception.Message
            Target          = $TargetObject
            ScriptStackTrace = $OriginalErrorRecord.ScriptStackTrace
            InvocationInfo  = $OriginalErrorRecord.InvocationInfo
        }
        $newException = New-Object System.Exception($errorDetails.Message, $OriginalErrorRecord.Exception)
        $newErrorRecord = New-Object System.Management.Automation.ErrorRecord(
            $newException,
            $errorDetails.ErrorID,
            $errorDetails.Category,
            $errorDetails.Target
        )
        if ($errorDetails.InvocationInfo) {
            $newErrorRecord.SetInvocationInfo($errorDetails.InvocationInfo)
        }
        return $newErrorRecord
    }
    $Script:PoshSYSI_ErrorHelper = ${function:New-PoshSYSIErrorRecord}

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
            This function is not intended for direct external use. It calls Invoke-SYSIMinimal by default.
            The variables it uses (e.g., $ComputerSystem, $Bios) must be populated in the calling scope (Get-PoshSYSI) 
            according to the PoshSYSIMode before this function is invoked.
            If PoshSYSIMode is 'Normal' or 'Full', it subsequently calls Invoke-SYSINormal (assuming relevant data has been fetched).
            If PoshSYSIMode is 'Full', it then calls Invoke-SYSIFull (assuming relevant data has been fetched).
        .PARAMETER CimSession
            An optional CIM session object. If provided and PoshSYSIMode is 'Full', this session is passed to Invoke-SYSIFull 
            to enable retrieval of installed programs from the remote machine.
        #>
        param(
            [Parameter(Mandatory=$false)] 
            $CimSession 
        )
        
        Write-Verbose "Mode: $PoshSYSIMode - Running Minimal information set"
        Invoke-SYSIMinimal -ComputerSystem $ComputerSystem -ComputerSystemInstall $ComputerSystemInstall -Bios $Bios -WinVersion $WinVersion -Processor $Processor -PhysicalMemory $PhysicalMemory -PhysicalMemoryCap $PhysicalMemoryCap

        if ($PoshSYSIMode -in @("Normal", "Full")) {
            Write-Verbose "Mode: $PoshSYSIMode - Running Normal information set"
            Invoke-SYSINormal -BitLockerStatus $BitLockerStatus -DiskC $DiskC -Monitors $Monitors -WinVersion $WinVersion -WinLicenseStatus $WinLicenseStatus
        }
        
        if ($PoshSYSIMode -eq "Full") {
            Write-Verbose "Mode: $PoshSYSIMode - Running Full information set"
            if ($CimSession) {
                Invoke-SYSIFull -CimSession $CimSession
            } else {
                Invoke-SYSIFull # Local execution
            }
        }
    }

    # RunMode
    switch ($PoshSYSIRunMode)
    {
        'Local' {
            Write-Verbose "RunMode: Local"
            # Clear lists for the current run
            $Script:PoshSYSIData.Monitors.Clear()
            $Script:PoshSYSIData.InstalledPrograms.Clear()

            # Initialize variables
            $Bios = $null; $ComputerSystem = $null; $ComputerSystemInstallObj = $null; $ComputerSystemInstall = $null
            $Processor = $null; $PhysicalMemory = $null; $PhysicalMemoryCap = 0; $WinVersion = $null
            $BitLockerStatus = $null; $DiskC = $null; $Monitors = $null 
            $WinLicenseProduct = $null; $WinLicenseStatus = $null

            # Minimal Mode Data
            try {
                Write-Verbose "Fetching Minimal data for Local"
                $Bios = Get-CimInstance -ClassName Win32_Bios -ErrorAction Stop
                $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                try {
                    # Attempt to get install date, but don't let it stop minimal info if it fails
                    $ComputerSystemInstallObj = Get-ChildItem -Path "C:\Windows\debug\NetSetup.LOG" -ErrorAction SilentlyContinue | Select-Object CreationTime -First 1
                    $ComputerSystemInstall = if ($ComputerSystemInstallObj) { $ComputerSystemInstallObj.CreationTime } else { $null }
                } catch {
                    Write-Warning "Could not retrieve OS install date from NetSetup.LOG: $($_.Exception.Message)"
                    $ComputerSystemInstall = $null # Ensure it's null if there was an error
                }
                $Processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
                $PhysicalMemory = Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop
                if ($PhysicalMemory) {
                    $PhysicalMemoryCap = ($PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB
                } else { 
                    $PhysicalMemoryCap = 0 
                }
                # WinVersion is needed for BiosFirmwareType (Minimal) and OS details (Normal)
                $WinVersion = Get-ComputerInfo -ErrorAction Stop 
            } catch {
                Write-Error (New-PoshSYSIErrorRecord -OriginalErrorRecord $_ -CustomMessage "Failed to retrieve MINIMAL system information on local machine" -TargetObject $env:COMPUTERNAME)
                Write-Verbose "Detailed error for local MINIMAL system info retrieval: $($($_) | Format-List * | Out-String)"
                # Potentially exit or handle inability to get minimal info
            }
            
            # Normal Mode Data (if applicable)
            if ($PoshSYSIMode -in @("Normal", "Full")) {
                Write-Verbose "Fetching Normal data for Local"
                try {
                    $BitLockerStatus = (New-Object -ComObject Shell.Application -ErrorAction Stop).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')
                } catch {
                    Write-Warning "Failed to retrieve BitLocker status on local machine: $($_.Exception.Message)" # Changed to Warning as it might not be critical for all 'Normal' scenarios
                    $BitLockerStatus = $null # Ensure it's null if there was an error
                    Write-Verbose "Detailed error for local BitLocker status retrieval: $($($_) | Format-List * | Out-String)"
                }
                
                try {
                    $DiskC = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
                    $Monitors = Get-CimInstance -ClassName WmiMonitorID -Namespace root\wmi -ErrorAction Stop
                    $WinLicenseProduct = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "Name like 'Windows%'" -ErrorAction Stop | Where-Object { $_.PartialProductKey } | Select-Object LicenseStatus -First 1
                    $WinLicenseStatus = if ($WinLicenseProduct) { $WinLicenseProduct.LicenseStatus } else { $null }
                } catch {
                    Write-Error (New-PoshSYSIErrorRecord -OriginalErrorRecord $_ -CustomMessage "Failed to retrieve additional NORMAL system information on local machine" -TargetObject $env:COMPUTERNAME)
                    Write-Verbose "Detailed error for local NORMAL system info retrieval: $($($_) | Format-List * | Out-String)"
                }
            }
            
            # Generate report if -Report:$true
            if ($Report) {
                If(!(Test-Path -Path $ReportPath)){
                    New-Item -ItemType Directory -Force -Path $ReportPath | Out-Null
                }
                Invoke-SYSIMode *> (Join-Path -Path $ReportPath -ChildPath "PoshSYSI_Local_$($PoshSYSIRunTime).log")
            } else {
                Invoke-SYSIMode # Called without -CimSession for local
            }
        }
        'Remote' {
            Write-Verbose "RunMode: Remote"
            if ($Report) { 
                If(!(Test-Path -Path $ReportPath)){
                    New-Item -ItemType Directory -Force -Path $ReportPath | Out-Null
                }
            }
            foreach ($ComputerItem in $ComputerName) {
                # Clear and Initialize data for the current remote computer
                $Script:PoshSYSIData.System = $null; $Script:PoshSYSIData.Bios = $null; $Script:PoshSYSIData.Processor = $null
                $Script:PoshSYSIData.Memory = $null; $Script:PoshSYSIData.Disk = $null; $Script:PoshSYSIData.Windows = $null
                $Script:PoshSYSIData.BitLocker = $null; $Script:PoshSYSIData.Monitors.Clear(); $Script:PoshSYSIData.InstalledPrograms.Clear()

                $cimSession = $null
                # Initialize variables for each remote machine iteration
                $Bios = $null; $ComputerSystem = $null; $ComputerSystemInstall = $null; $Processor = $null
                $PhysicalMemory = $null; $PhysicalMemoryCap = 0; $WinVersion = $null; $BitLockerStatus = $null
                $DiskC = $null; $Monitors = $null; $WinLicenseProductRemote = $null; $WinLicenseStatus = $null

                try {
                    $cimSessionOptions = New-CimSessionOption -Protocol WSMAN
                    $cimSession = New-CimSession -ComputerName $ComputerItem -SessionOption $cimSessionOptions -ErrorAction Stop
                    
                    Write-Host "`n$($ComputerItem)" -BackgroundColor DarkGreen -ForegroundColor White
                    
                    # Minimal Mode Data - Remote
                    try {
                        Write-Verbose "Fetching Minimal data for $ComputerItem"
                        $Bios = Get-CimInstance -ClassName Win32_Bios -CimSession $cimSession -ErrorAction Stop
                        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $cimSession -ErrorAction Stop
                        $Processor = Get-CimInstance -ClassName Win32_Processor -CimSession $cimSession -ErrorAction Stop
                        $PhysicalMemory = Get-CimInstance -ClassName Win32_PhysicalMemory -CimSession $cimSession -ErrorAction Stop
                        if ($PhysicalMemory) {
                            $PhysicalMemoryCap = ($PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB
                        } else { $PhysicalMemoryCap = 0 }
                        
                        # WinVersion for BiosFirmwareType (Minimal) and OS details (Normal)
                        $WinVersion = (Invoke-Command -CimSession $cimSession -ScriptBlock { Get-ComputerInfo -ErrorAction Stop })
                        $ComputerSystemInstall = (Invoke-Command -CimSession $cimSession -ScriptBlock { 
                            try { (Get-ChildItem -Path "C:\Windows\debug\NetSetup.LOG" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CreationTime -First 1) } catch { $null }
                        })
                    } catch {
                        Write-Error (New-PoshSYSIErrorRecord -OriginalErrorRecord $_ -CustomMessage "Error retrieving MINIMAL information from $($ComputerItem) via CIM/Invoke-Command." -TargetObject $ComputerItem)
                        Write-Verbose "Detailed error during MINIMAL data retrieval from $($ComputerItem): $($($_) | Format-List * | Out-String)"
                        if ($cimSession) { Remove-CimSession -CimSession $cimSession; $cimSession = $null } # Clean up session
                        continue # Skip to the next computer if minimal info fails
                    }

                    # Normal Mode Data - Remote (if applicable)
                    if ($PoshSYSIMode -in @("Normal", "Full")) {
                        Write-Verbose "Fetching Normal data for $ComputerItem"
                        try {
                            $DiskC = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -CimSession $cimSession -ErrorAction Stop
                            $Monitors = Get-CimInstance -ClassName WmiMonitorID -Namespace root\wmi -CimSession $cimSession -ErrorAction Stop
                            
                            # License status retrieval
                            $WinLicenseProductRemote = Invoke-Command -CimSession $cimSession -ScriptBlock {
                                Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "Name like 'Windows%'" -ErrorAction SilentlyContinue | 
                                Where-Object { $_.PartialProductKey } | 
                                Select-Object -ExpandProperty LicenseStatus -First 1
                            }
                            $WinLicenseStatus = if ($WinLicenseProductRemote) { $WinLicenseProductRemote } else { $null }
                            
                            $BitLockerStatus = (Invoke-Command -CimSession $cimSession -ScriptBlock { 
                                try { (New-Object -ComObject Shell.Application -ErrorAction Stop).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection') } catch { $null }
                            })
                        } catch {
                            Write-Warning "Error retrieving some NORMAL information from $($ComputerItem) via CIM/Invoke-Command: $($_.Exception.Message)" # Changed to Warning
                            Write-Verbose "Detailed error during NORMAL data retrieval from $($ComputerItem): $($($_) | Format-List * | Out-String)"
                            # Continue with data collected so far for this computer
                        }
                    }
                    
                    # Invoke data processing and display functions
                    if ($Report) {
                        Invoke-SYSIMode -CimSession $cimSession *> (Join-Path -Path $ReportPath -ChildPath "$($ComputerItem)_PoshSYSI_Remote_$($PoshSYSIRunTime).log")
                    } else {
                        Invoke-SYSIMode -CimSession $cimSession
                    }
                } catch { # Catches New-CimSession failure or other critical errors before data fetching stages
                    Write-Error (New-PoshSYSIErrorRecord -OriginalErrorRecord $_ -CustomMessage "Failed to establish CIM session with $($ComputerItem) or a critical remote operation failed." -TargetObject $ComputerItem)
                    Write-Host "`n$($ComputerItem) not reachable or CIM session creation failed!" -BackgroundColor DarkRed -ForegroundColor White
                    Write-Verbose "CIM Connection or critical remote operation error for $($ComputerItem): $($($_) | Format-List * | Out-String)"
                } finally {
                    if ($cimSession) {
                        Remove-CimSession -CimSession $cimSession
                    }
                }
            }
        }
    }

    Write-Output $Script:PoshSYSIData
    Remove-Variable PoshSYSI_ErrorHelper -Scope Script -ErrorAction SilentlyContinue
}
