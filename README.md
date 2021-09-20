# PoshSYSI (PowerShell System Information) - 0.2.3.2

<p align="center">
  <a href="https://github.com/Kinsiinoo/PoshSYSI"><img src="https://img.shields.io/github/languages/top/kinsiinoo/poshsysi?style=for-the-badge"></a>
  <a href="https://github.com/Kinsiinoo/PoshSYSI"><img src="https://img.shields.io/github/languages/code-size/kinsiinoo/poshsysi?style=for-the-badge"></a>
  <a href="https://github.com/Kinsiinoo/PoshSYSI"><img src="https://img.shields.io/github/license/kinsiinoo/poshsysi?style=for-the-badge"></a>
</p>

<p align="center">
  <a href="https://github.com/Kinsiinoo/PoshSYSI/releases/"><img src="https://img.shields.io/github/v/release/kinsiinoo/poshsysi?style=for-the-badge"></a>
  <a href="https://github.com/Kinsiinoo/PoshSYSI"><img src="https://img.shields.io/github/last-commit/kinsiinoo/poshsysi?style=for-the-badge"></a>
</p>

This PowerShell module gives information about the following things on the specified machine:

Category | Subcategory | Useful for NB | Useful for PC
---------|-------------|---------------|--------------
**Bios** |S/N|Yes|No
||Type|Yes|Yes
||Version|Yes|Yes
**BitLocker**|Status|Yes|Yes
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
||Install(approx)|Yes|Yes
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
Get-PoshSYSI [[-PoshSYSIMode] {Minimal | Normal | Full}] [-PoshSYSIRunMode] {Local | Remote} [[-Report]]  [<CommonParameters>]
```

Remote:

```PowerShell
Get-PoshSYSI [-ComputerName] <string[]> [[-PoshSYSIMode] {Minimal | Normal | Full}] [-PoshSYSIRunMode] {Local | Remote} [[-Report]]  [<CommonParameters>]
```

## Mode

**Minimal:** System, Bios, Processor, Memory

**Normal:** + BitLocker (C:), Storage (C:), Monitor(s), Windows

**Full:** + Programs (x64 + x86)

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

### Report

A report can be generated using the `-Report` switch.

 Default output folder path: `C:\Temp\PoshSYSI\`

## Known issues

- ~~[#1](https://github.com/Kinsiinoo/PoshSYSI/issues/1) System info: wrong user~~
- [#2](https://github.com/Kinsiinoo/PoshSYSI/issues/2) Wait for variables
- [#3](https://github.com/Kinsiinoo/PoshSYSI/issues/3) Remote: Installed programs

## Todo

- [ ] CLI version
  - [X] More info
  - [X] Refactor code into a nice PS module :eyes:
  - [X] Run on multiple computer (Tested on a huge AD)
  - [X] Modes (`Full`, `Normal`, `Minimal`)
  - [X] Report ~~(maybe `.csv` and/or `.xlsx` and/or `.html`)~~
  - [ ] Extend storage info
  - [X] BitLocker info
  - [ ] Fine-tune some output to make them easier to read
- [ ] GUI version
  - [ ] Multilingual interface

## Changelog

WIP

## License

PoshSYSI is licensed under the MIT License.
