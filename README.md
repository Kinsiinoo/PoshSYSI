# PoshSYSI (PowerShell System Information) - 0.3.1.0

<p align="center">
  <a href="https://github.com/Kinsiinoo/PoshSYSI"><img src="https://img.shields.io/github/languages/top/kinsiinoo/poshsysi?style=for-the-badge"></a>
  <a href="https://github.com/Kinsiinoo/PoshSYSI"><img src="https://img.shields.io/github/languages/code-size/kinsiinoo/poshsysi?style=for-the-badge"></a>
  <a href="https://github.com/Kinsiinoo/PoshSYSI"><img src="https://img.shields.io/github/license/kinsiinoo/poshsysi?style=for-the-badge"></a>
</p>

<p align="center">
  <a href="https://github.com/Kinsiinoo/PoshSYSI/releases/"><img src="https://img.shields.io/github/v/release/kinsiinoo/poshsysi?style=for-the-badge&label=Release"></a>
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
Get-PoshSYSI [-PoshSYSIRunMode Local] [[-PoshSYSIMode] <string>] [[-Report] <bool>] [[-ReportPath] <string>] [<CommonParameters>]
```

Remote:

```PowerShell
Get-PoshSYSI -ComputerName <string[]> [-PoshSYSIRunMode Remote] [[-PoshSYSIMode] <string>] [[-Report] <bool>] [[-ReportPath] <string>] [<CommonParameters>]
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
You can specify a custom path using the `-ReportPath` parameter.

## Known issues

- ~~[#1](https://github.com/Kinsiinoo/PoshSYSI/issues/1) System info: wrong user~~
- ~~[#2](https://github.com/Kinsiinoo/PoshSYSI/issues/2) Wait for variables~~ (Fixed in 0.3.1.0 with improved error handling, proper variable initialization, and more robust CIM session management)
- ~~[#3](https://github.com/Kinsiinoo/PoshSYSI/issues/3) Remote: Installed programs~~ (Addressed in 0.3.1.0 by implementing remote retrieval)
- ~~[#4](https://github.com/Kinsiinoo/PoshSYSI/issues/4) Change WMI to CIM~~

## Todo

- [ ] CLI version
  - [X] More info
  - [X] Refactor code into a nice PS module :eyes:
  - [X] Run on multiple computer (Tested on a huge AD)
  - [X] Modes (`Full`, `Normal`, `Minimal`)
  - [X] Report ~~(maybe `.csv` and/or `.xlsx` and/or `.html`)~~
  - [ ] Extend storage info
  - [X] BitLocker info
  - [X] Fine-tune some output to make them easier to read
- [ ] GUI version
  - [ ] Multilingual interface

## Changelog

### Version 0.3.1.0
- Implemented retrieval of installed programs from remote computers in 'Full' mode using `Invoke-Command` with CIM sessions.
- Introduced a standardized error handling mechanism (`New-PoshSYSIErrorRecord`) for more consistent and detailed error reporting.
- Ensured proper re-initialization of data structures for each local run and for every remote computer processed, preventing data carry-over.
- Added automatic normalization for `ReportPath` to ensure it ends with a backslash if it's a directory.
- Refined remote data fetching for OS installation date, `Get-ComputerInfo`, BitLocker status, and Windows License status using targeted `Invoke-Command` calls.
- Improved robustness of data collection with more granular try-catch blocks for different data categories (Minimal, Normal).

### Version 0.3.0.0
- Added optional `ReportPath` parameter for custom report output directory.
- Improved data collection performance using generic lists for Monitors and InstalledPrograms.
- Refactored `Invoke-SYSIMode` logic for clarity and efficiency.
- Enhanced remote connection handling using CIM sessions for most operations, improving reliability and performance.
- Implemented more robust and detailed error handling with a dedicated helper function.
- Updated comment-based help and inline comments for clarity and accuracy.
- Known issue: In 'Full' mode for remote computers, installed programs are currently retrieved from the machine running `Get-PoshSYSI`, not the remote target.

For older versions, please refer to the commit history or release tags.

## License

PoshSYSI is licensed under the MIT License.
