function Get-PoshSYSI {
    [CmdletBinding()]
    param (
        [Parameter(Position=0,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("CN","MachineName")]
        [String[]]$ComputerName
    )

    # Variables
    $Bios = Get-WmiObject Win32_Bios
    $ComputerSystem = Get-WmiObject Win32_ComputerSystem
    $DiskC = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object -Property DeviceID, @{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}}, @{L="Capacity";E={"{0:N2}" -f ($_.Size/1GB)}}
    $Monitors = Get-WmiObject WmiMonitorID -Namespace root\wmi
    $PhysicalMemory = Get-WmiObject Win32_PhysicalMemory
    $PhysicalMemoryCap = (Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum/1GB
    $Processor = Get-WmiObject Win32_Processor
    $WinLicenseStatus = (Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" | Where-Object { $_.PartialProductKey } | Select-Object LicenseStatus).LicenseStatus
    $WinVersion = Get-ComputerInfo

    # Functions
    function Get-SYSISystemInfo($SystemInfo) {
        Write-Host "Name:" $SystemInfo.Name
        Write-Host "User:" $env:USERNAME
        Write-Host "Model:" $SystemInfo.Model
    }

    function Get-SYSIBiosInfo($BiosInfo, $BiosType) {
        Write-Host "Type:" $BiosType.BiosFirmwareType
        Write-Host "Version:" $BiosInfo.SMBIOSBIOSVersion
        Write-Host "S/N:" $BiosInfo.SerialNumber
    }

    function Get-SYSIProcessorInfo($ProcessorInfo) {
        Write-Host "Manufacturer:" $ProcessorInfo.Manufacturer
        Write-Host "Socket:" $ProcessorInfo.SocketDesignation
        Write-Host "Model:" $ProcessorInfo.Name
        Write-Host "C/LC:" $ProcessorInfo.NumberOfCores "/" $ProcessorInfo.NumberOfLogicalProcessors
    }

    function Get-SYSIMemoryInfo($MemoryInfo, $MemoryInfoCap) {
        Write-Host "Available:" $MemoryInfoCap "GB"
        Write-Host "Manufacturer:" $MemoryInfo.Manufacturer
        Write-Host "P/N:" $MemoryInfo.PartNumber
        Write-Host "S/N:" $MemoryInfo.SerialNumber
    }

    function Get-SYSIMonitors($Monitors) {
        ForEach ($Monitor in $Monitors) {  
            $MonitorManufacturer = Invoke-Decode $Monitor.ManufacturerName -notmatch 0
            $MonitorModel = Invoke-Decode $Monitor.UserFriendlyName -notmatch 0
            $MonitorPCID = Invoke-Decode $Monitor.ProductCodeID -notmatch 0
            $MonitorSerial = Invoke-Decode $Monitor.SerialNumberID -notmatch 0
            $MonitorYoM = Invoke-Decode $Monitor.YearOfManufacture -notmatch 0
            Write-Host "Manufacturer:" $MonitorManufacturer "`nName:" $MonitorModel "`nPCID:" $MonitorPCID "`nS/N:" $MonitorSerial "`nYoM:" $MonitorYoM "`n"
        }
    }

    function Get-SYSIDiskCInfo($DiskCInfo) {
        Write-Host "Capacity:" $DiskCInfo.Capacity "GB"
        Write-Host "Free:" $DiskCInfo.FreeSpaceGB "GB"
    }

    function Get-LicenseStatus($WLStatus) {
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

    function Get-SYSIWindowsInfo($WindowsInfo, $WindowsLicInfo) {
        Write-Host "Architecture:" $WindowsInfo.OsArchitecture
        Write-Host "Product name:" $WindowsInfo.OsName
        Write-Host "Version:" $WindowsInfo.WindowsVersion
        Write-Host "Build:" $WindowsInfo.OsBuildNumber
        Get-LicenseStatus $WindowsLicInfo
    }

    function Invoke-Decode {
        If ($args[0] -is [System.Array]) {
            [System.Text.Encoding]::ASCII.GetString($args[0])
        }
        Else {
            "No results!"
        }
    }

    function Get-SYSIInstalledProgs {
        $InstalledPrograms = $null
        $InstalledPrograms += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion
        $InstalledPrograms += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion
        $InstalledPrograms | Sort-Object -Property DisplayName | Format-Table -HideTableHeaders -Wrap
    }

    # System
    Write-Host -ForegroundColor Cyan ">> System"
    Get-SYSISystemInfo $ComputerSystem

    # Bios
    Write-Host -ForegroundColor Cyan "`n>> Bios"
    Get-SYSIBiosInfo $Bios $WinVersion

    # Processor
    Write-Host -ForegroundColor Cyan "`n>> Processor"
    Get-SYSIProcessorInfo $Processor

    # Memory
    Write-Host -ForegroundColor Cyan "`n>> Memory"
    Get-SYSIMemoryInfo $PhysicalMemory $PhysicalMemoryCap

    # Storage
    Write-Host -ForegroundColor Cyan "`n>> Storage (C:\)"
    Get-SYSIDiskCInfo $DiskC

    # Windows
    Write-Host -ForegroundColor Cyan "`n>> Windows"
    Get-SYSIWindowsInfo $WinVersion $WinLicenseStatus

    # Programs
    Write-Host -ForegroundColor Cyan "`n>> Installed programs"
    Get-SYSIInstalledProgs

    # Monitor
    Write-Host -ForegroundColor Cyan "`n>> Monitor(s)"
    Get-SYSIMonitors $Monitors

}
