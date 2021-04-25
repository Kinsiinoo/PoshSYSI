# PoshSYSI

PowerShell System Information 0.2.0

This PowerShell script gives information about the following things on the specified machine:

Category | Subcategory | Useful for NB | Useful for PC
---------|-------------|---------------|--------------
**Bios** |S/N|Yes|No
||Type|Yes|Yes
||Version|Yes|Yes
**CPU** |C/LC|Yes|Yes
||Manufacturer|Yes|Yes
||Model|Yes|Yes
||Socket|No|Yes
**Installed**|Name|Yes|Yes
||Version|Yes|Yes
**Monitor(s)**|Manufacturer|Yes|Yes
||Name|Yes|Yes
||PCID|Yes|Yes
||S/N|Yes|Yes
||YoM|Yes|Yes
**RAM**|Available|Yes|Yes
||Manufacturer|Yes|No
||P/N|Yes|Yes
||S/N|Yes|No
**Storage(C:)**|Capacity|Yes|Yes
||Free|Yes|Yes
**System**|Model|Yes|No
||Name|Yes|Yes
||User|Yes|Yes
**Windows**|Architecture|Yes|Yes
||Build|Yes|Yes
||License status|Yes|Yes
||Product name|Yes|Yes
||Version|Yes|Yes

## Screenshots

WIP

## Syntax

Local:

```PowerShell
Get-PoshSYSI [[-PoshSYSIMode] {Minimal | Normal | Full}] [-PoshSYSIRunMode] {Local | Remote}  [<CommonParameters>]
```

Remote:

```PowerShell
Get-PoshSYSI [-ComputerName] <string[]> [[-PoshSYSIMode] {Minimal | Normal | Full}] [-PoshSYSIRunMode] {Local | Remote}  [<CommonParameters>]
```

## Usage

Local without mode:

```PowerShell
Get-PoshSYSI -PoshSYSIRunMode Local
```

Local with mode:

```PowerShell
Get-PoshSYSI -PoshSYSIMode {Minimal | Normal | Full} -PoshSYSIRunMode Local
```

Remote without mode:

```PowerShell
Get-PoshSYSI -ComputerName EXAMPLE -PoshSYSIRunMode Remote
Get-PoshSYSI -ComputerName EXAMPLE1,EXAMPLE2 -PoshSYSIRunMode Remote
```

Remote with mode:

```PowerShell
Get-PoshSYSI -ComputerName EXAMPLE -PoshSYSIMode {Minimal | Normal | Full} -PoshSYSIRunMode Remote
Get-PoshSYSI -ComputerName EXAMPLE1,EXAMPLE2 -PoshSYSIMode {Minimal | Normal | Full} -PoshSYSIRunMode Remote
```

## Todo

- [X] More info :thinking:
- [X] Refactor code into a nice PS module :eyes:
  - [X] Run on multiple computer (not tested YET)
  - [X] Modes (`Full`, `Normal`, `Minimal`)
  - [ ] Report (maybe `.csv` and/or `.xlsx` and/or `.html`)
- [ ] GUI version
  - [ ] Multilingual interface

## License

PoshSYSI is licensed under the MIT License.
