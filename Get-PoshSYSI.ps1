# Variables
$Bios = Get-WmiObject Win32_Bios
$ComputerSystem = Get-WmiObject Win32_ComputerSystem
$DiskC = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object -Property DeviceID, @{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}}, @{L="Capacity";E={"{0:N2}" -f ($_.Size/1GB)}}
$PhysicalMemory = (Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum/1GB
$Processor = Get-WmiObject Win32_Processor
$WinLicenseStatus = Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" | Where-Object { $_.PartialProductKey } | Select-Object LicenseStatus
$WinVersion = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion

# System
Write-Host -ForegroundColor Cyan ">> System"
Write-Host "Name:" $ComputerSystem.Name
Write-Host "User:" $env:USERNAME
Write-Host "Model:" $ComputerSystem.Model

# Bios
Write-Host -ForegroundColor Cyan "`n>> Bios"
Write-Host "Version:" $Bios.SMBIOSBIOSVersion
Write-Host "S/N:" $Bios.SerialNumber

# Processor
Write-Host -ForegroundColor Cyan "`n>> Processor"
Write-Host "Model:" $Processor.Name
Write-Host "C/LC:" $Processor.NumberOfCores "/" $Processor.NumberOfLogicalProcessors
Write-Host "Status:" $Processor.Status

# Memory
Write-Host -ForegroundColor Cyan "`n>> Memory"
Write-Host "Available:" $PhysicalMemory "GB"

# Storage
Write-Host -ForegroundColor Cyan "`n>> Storage (C:\)"
Write-Host "Capacity:" $DiskC.Capacity "GB"
Write-Host "Free:" $DiskC.FreeSpaceGB "GB"

# Windows
Write-Host -ForegroundColor Cyan "`n>> Windows"
Write-Host "Version:" $WinVersion.WindowsVersion
Write-Host "License status:" $WinLicenseStatus.LicenseStatus
