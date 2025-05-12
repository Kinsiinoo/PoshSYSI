# Helper functions at module level
function Invoke-Decode {
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
    param (
        [Parameter(Mandatory=$true)]$BitLockerStatus
    )
    $Script:PoshSYSIData.BitLocker = $BitLockerStatus
    Get-SYSIBLStatus $BitLockerStatus
}

# Processor info
function Get-SYSIProcessorInfo {
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
    param (
        [Parameter(Mandatory=$true)]$Monitors
    )
    $monitorList = @()
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
        $monitorList += $temp
        Write-Host "Manufacturer:" $MonitorManufacturer "`nName:" $MonitorModel "`nPCID:" $MonitorPCID "`nS/N:" $MonitorSerial "`nYoM:" $MonitorYoM "`n"
    }
    $Script:PoshSYSIData.Monitors = $monitorList
}

# Disk Info (C:\)
function Get-SYSIDiskCInfo {
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
    try {
        $InstalledPrograms = $null
        $InstalledPrograms += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion
        $InstalledPrograms += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion
        $InstalledPrograms | Sort-Object -Property DisplayName | Format-Table -HideTableHeaders -Wrap
        $InstalledPrograms | ForEach-Object {
            $Script:PoshSYSIData.InstalledPrograms += $_
        }
    } catch {
        Write-Error "Error retrieving installed programs: $($_.Exception.Message)"
    }
}

# Modes functions (now at module level)
function Invoke-SYSIMinimal {
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
    Write-Host -ForegroundColor Cyan "`n>> Installed programs"
    Get-SYSIInstalledProgs
}

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
        [String]$PoshSYSIRunMode,
        [Parameter(Mandatory=$false,Position=2,ParameterSetName="LOCAL")]
        [Parameter(Mandatory=$false,Position=3,ParameterSetName="REMOTE")]
        [bool]$Report = $false
    )

    # Report variables
    $PoshSYSIOutPath = "C:\Temp\PoshSYSI\"
    $PoshSYSIRunTime = (Get-Date).ToString('yyyy-MM-dd-HH-mm-ss')

    # Script-level PSCustomObject for report details
    $Script:PoshSYSIData = [PSCustomObject]@{
        System           = $null
        Bios             = $null
        Processor        = $null
        Memory           = $null
        Disk             = $null
        Windows          = $null
        BitLocker        = $null
        Monitors         = @()
        InstalledPrograms= @()
    }

    # Invoke mode function
    function Invoke-SYSIMode {
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
                If(!(Test-Path -Path $PoshSYSIOutPath)){
                    New-Item -ItemType Directory -Force -Path $PoshSYSIOutPath | Out-Null
                }
                Invoke-SYSIMode *> "$($PoshSYSIOutPath)\PoshSYSI_Local_$($PoshSYSIRunTime).log"
            } else {
                Invoke-SYSIMode
            }
        }
        'Remote' {
            Write-Verbose "RunMode: Remote"
            if ($Report) { # Create directory once if reporting for remote hosts
                If(!(Test-Path -Path $PoshSYSIOutPath)){
                    New-Item -ItemType Directory -Force -Path $PoshSYSIOutPath | Out-Null
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
                        Invoke-SYSIMode *> "$($PoshSYSIOutPath)\$($ComputerItem)_PoshSYSI_Remote_$($PoshSYSIRunTime).log"
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
