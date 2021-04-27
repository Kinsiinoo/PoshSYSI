function Get-PoshSYSI {
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
        [String]$PoshSYSIRunMode
    )

    # Functions
    function Invoke-Decode {
        If ($args[0] -is [System.Array]) {
            [System.Text.Encoding]::ASCII.GetString($args[0])
        }
        Else {
            "No results!"
        }
    }

    # "Basic" system info
    function Get-SYSISystemInfo($SystemInfo) {
        Write-Host "Name:" $SystemInfo.Name
        Write-Host "User:" $env:USERNAME
        Write-Host "Model:" $SystemInfo.Model
    }

    # Bios info
    function Get-SYSIBiosInfo($BiosInfo, $BiosType) {
        Write-Host "Type:" $BiosType.BiosFirmwareType
        Write-Host "Version:" $BiosInfo.SMBIOSBIOSVersion
        Write-Host "S/N:" $BiosInfo.SerialNumber
    }

    # Processor info
    function Get-SYSIProcessorInfo($ProcessorInfo) {
        Write-Host "Manufacturer:" $ProcessorInfo.Manufacturer
        Write-Host "Socket:" $ProcessorInfo.SocketDesignation
        Write-Host "Model:" $ProcessorInfo.Name
        Write-Host "C/LC:" $ProcessorInfo.NumberOfCores "/" $ProcessorInfo.NumberOfLogicalProcessors
    }

    # Memory info
    function Get-SYSIMemoryInfo($MemoryInfo, $MemoryInfoCap) {
        Write-Host "Available:" $MemoryInfoCap "GB"
        Write-Host "Manufacturer:" $MemoryInfo.Manufacturer
        Write-Host "P/N:" $MemoryInfo.PartNumber
        Write-Host "S/N:" $MemoryInfo.SerialNumber
    }

    # Attached monitors
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

    # Disk Info (C:\)
    function Get-SYSIDiskCInfo($DiskCInfo) {
        Write-Host "Capacity:" $DiskCInfo.Capacity "GB"
        Write-Host "Free:" $DiskCInfo.FreeSpaceGB "GB"
    }

    # Windows license status
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

    # Windows info
    function Get-SYSIWindowsInfo($WindowsInfo, $WindowsLicInfo) {
        Write-Host "Architecture:" $WindowsInfo.OsArchitecture
        Write-Host "Product name:" $WindowsInfo.OsName
        Write-Host "Version:" $WindowsInfo.WindowsVersion
        Write-Host "Build:" $WindowsInfo.OsBuildNumber
        Get-LicenseStatus $WindowsLicInfo
    }

    # Installed programs (x64 + x86)
    function Get-SYSIInstalledProgs {
        $InstalledPrograms = $null
        $InstalledPrograms += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion
        $InstalledPrograms += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion
        $InstalledPrograms | Sort-Object -Property DisplayName | Format-Table -HideTableHeaders -Wrap
    }

    # Modes and Invoke mode function
    function Invoke-SYSIMinimal {
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
    }

    function Invoke-SYSINormal {
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
        # Programs
        Write-Host -ForegroundColor Cyan "`n>> Installed programs"
        Get-SYSIInstalledProgs
    }

    function Invoke-SYSIMode {
        switch ($PoshSYSIMode)
            {
                'Minimal' {
                    Write-Verbose "Mode: Minimal"
                    Invoke-SYSIMinimal
                }
                'Normal' {
                    Write-Verbose "Mode: Normal"
                    Invoke-SYSIMinimal
                    Invoke-SYSINormal
                }
                'Full' {
                    Write-Verbose "Mode: Full"
                    Invoke-SYSIMinimal
                    Invoke-SYSINormal
                    Invoke-SYSIFull
                }
            }
    }

    # RunMode
    switch ($PoshSYSIRunMode)
    {
        'Local' {
            Write-Verbose "RunMode: Local"
            $Bios = Get-WmiObject Win32_Bios
            $ComputerSystem = Get-WmiObject Win32_ComputerSystem
            $DiskC = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object -Property DeviceID, @{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}}, @{L="Capacity";E={"{0:N2}" -f ($_.Size/1GB)}}
            $Monitors = Get-WmiObject WmiMonitorID -Namespace root\wmi
            $PhysicalMemory = Get-WmiObject Win32_PhysicalMemory
            $PhysicalMemoryCap = (Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum/1GB
            $Processor = Get-WmiObject Win32_Processor
            $WinLicenseStatus = (Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" | Where-Object { $_.PartialProductKey } | Select-Object LicenseStatus).LicenseStatus
            $WinVersion = Get-ComputerInfo

            Invoke-SYSIMode
        }
        'Remote' {
            Write-Verbose "RunMode: Remote"
            foreach ($ComputerItem in $ComputerName) {
                if (Test-Connection -ComputerName $ComputerItem -Quiet -Count 1) {
                    Write-Host "$($ComputerItem)" -BackgroundColor DarkGreen -ForegroundColor White
                    
                    $Bios = Get-WmiObject Win32_Bios -ComputerName $ComputerItem
                    $ComputerSystem = Get-WmiObject Win32_ComputerSystem -ComputerName $ComputerItem
                    $DiskC = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'" -ComputerName $ComputerItem | Select-Object -Property DeviceID, @{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}}, @{L="Capacity";E={"{0:N2}" -f ($_.Size/1GB)}}
                    $Monitors = Get-WmiObject WmiMonitorID -Namespace root\wmi -ComputerName $ComputerItem
                    $PhysicalMemory = Get-WmiObject Win32_PhysicalMemory -ComputerName $ComputerItem
                    $PhysicalMemoryCap = (Get-WmiObject Win32_PhysicalMemory -ComputerName $ComputerItem | Measure-Object -Property Capacity -Sum).Sum/1GB
                    $Processor = Get-WmiObject Win32_Processor -ComputerName $ComputerItem
                    $WinLicenseStatus = (Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" -ComputerName $ComputerItem | Where-Object { $_.PartialProductKey } | Select-Object LicenseStatus).LicenseStatus
                    $WinVersion = (Invoke-Command -ComputerName $ComputerItem -ScriptBlock { Get-ComputerInfo })

                    Invoke-SYSIMode
                } else {
                    Write-Host "$($ComputerItem) not reachable!" -BackgroundColor DarkRed -ForegroundColor White
                }
            }
        }
    }

}
